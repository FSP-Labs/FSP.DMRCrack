// FSP.DMRCrack - GPU-accelerated ARC4 key recovery for DMR communications
// Copyright (C) 2026 FSP-Labs
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see https://www.gnu.org/licenses/.

/*
 * cli.c — headless entry point for FSP.DMRCrack (-DNO_GUI / Linux build)
 *
 * Usage:
 *   dmrcrack --bin <payload.bin> [options]
 *
 * Options:
 *   --bin   <file>       .bin payload file (required)
 *   --start <hex>        start key, 40-bit hex (default: 0000000000)
 *   --end   <hex>        end key,   40-bit hex (default: FFFFFFFFFF)
 *   --threads <n>        CPU worker threads (default: CPU count - 1)
 *   --gpu-pct <50-95>    GPU share of keyspace in percent (default: 80)
 *   --samples <n>        payload lines to sample per candidate (default: all)
 *   --key   <hex>        test a specific key and print its score, then exit
 *   --no-resume          ignore any .progress checkpoint file
 */

#include "../include/bruteforce.h"
#include "../include/payload_io.h"
#include "../include/platform.h"
#include "../include/version.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <inttypes.h>

#if defined(_WIN32)
#  include <windows.h>   /* Sleep() */
#else
#  include <unistd.h>    /* sleep() */
static void Sleep(unsigned ms) { usleep((useconds_t)ms * 1000u); }
#endif

/* ── Globals ──────────────────────────────────────────────────────────── */
static BruteforceEngine g_engine;
static PayloadSet       g_payloads;
static volatile int     g_interrupted = 0;

static void on_signal(int sig)
{
    (void)sig;
    g_interrupted = 1;
    bruteforce_stop(&g_engine);
}

/* ── Helpers ──────────────────────────────────────────────────────────── */

static int parse_hex40(const char *s, uint64_t *out)
{
    char *end;
    uint64_t v = strtoull(s, &end, 16);
    if (end == s || *end != '\0' || v > 0xFFFFFFFFFFULL) return 0;
    *out = v;
    return 1;
}

static void print_key(uint64_t key)
{
    printf("%02X %02X %02X %02X %02X",
           (unsigned)((key >> 32) & 0xFF),
           (unsigned)((key >> 24) & 0xFF),
           (unsigned)((key >> 16) & 0xFF),
           (unsigned)((key >>  8) & 0xFF),
           (unsigned)( key        & 0xFF));
}

static void print_usage(const char *argv0)
{
    fprintf(stderr,
        "FSP.DMRCrack v" DMRCRACK_VERSION " — RC4 40-bit DMR key recovery\n"
        "\n"
        "Usage: %s --bin <payload.bin> [options]\n"
        "\n"
        "  --bin   <file>      .bin payload file (required)\n"
        "  --start <hex>       start key (default: 0000000000)\n"
        "  --end   <hex>       end key   (default: FFFFFFFFFF)\n"
        "  --threads <n>       CPU worker threads (default: auto)\n"
        "  --gpu-pct <50-95>   GPU share of keyspace (default: 80)\n"
        "  --samples <n>       payload lines to sample per key (default: all)\n"
        "  --key   <hex>       score a single key and exit\n"
        "  --no-resume         ignore any saved checkpoint\n"
        "\n", argv0);
}

/* ── Progress bar ─────────────────────────────────────────────────────── */

static void print_progress(const BruteforceSnapshot *s)
{
    double pct = (s->total_keys > 0)
                 ? (double)s->keys_tested * 100.0 / (double)s->total_keys
                 : 0.0;

    printf("\r  %6.2f%%  %10.0f k/s  best: ", pct, s->keys_per_second / 1000.0);
    print_key(s->best_key);
    printf("  (score %.1f)  ETA: ", s->best_score);

    if (s->eta_seconds < 0.0 || s->eta_seconds > 999999.0) {
        printf("--:--:--");
    } else {
        int eta = (int)s->eta_seconds;
        printf("%02d:%02d:%02d", eta / 3600, (eta % 3600) / 60, eta % 60);
    }

    fflush(stdout);
}

/* ── Entry point ──────────────────────────────────────────────────────── */

#if defined(_WIN32) && !defined(NO_GUI)
/* When built with GUI, this file is not compiled — main.c has WinMain. */
#else

#if defined(_WIN32)
int wmain(int argc, wchar_t **wargv)
{
    /* Convert wide args to narrow for simplicity */
    char **argv = (char **)malloc((size_t)(argc + 1) * sizeof(char *));
    for (int i = 0; i < argc; ++i) {
        int n = WideCharToMultiByte(CP_UTF8, 0, wargv[i], -1, NULL, 0, NULL, NULL);
        argv[i] = (char *)malloc((size_t)n);
        WideCharToMultiByte(CP_UTF8, 0, wargv[i], -1, argv[i], n, NULL, NULL);
    }
    argv[argc] = NULL;
#else
int main(int argc, char **argv)
{
#endif
    const char *bin_path   = NULL;
    const char *key_str    = NULL;
    uint64_t    start_key  = 0x0000000000ULL;
    uint64_t    end_key    = 0xFFFFFFFFFFULL;
    int         threads    = 0;   /* 0 = auto */
    int         gpu_pct    = 80;
    int         samples    = 0;   /* 0 = all */
    int         no_resume  = 0;
    char        err[256];

    /* ── Argument parsing ─────────────────────────────────────────────── */
    for (int i = 1; i < argc; ++i) {
        if      (strcmp(argv[i], "--bin")       == 0 && i+1 < argc) { bin_path  = argv[++i]; }
        else if (strcmp(argv[i], "--start")     == 0 && i+1 < argc) {
            if (!parse_hex40(argv[++i], &start_key)) {
                fprintf(stderr, "error: invalid --start value\n"); return 1; }
        }
        else if (strcmp(argv[i], "--end")       == 0 && i+1 < argc) {
            if (!parse_hex40(argv[++i], &end_key))   {
                fprintf(stderr, "error: invalid --end value\n");   return 1; }
        }
        else if (strcmp(argv[i], "--threads")   == 0 && i+1 < argc) { threads  = atoi(argv[++i]); }
        else if (strcmp(argv[i], "--gpu-pct")   == 0 && i+1 < argc) { gpu_pct  = atoi(argv[++i]); }
        else if (strcmp(argv[i], "--samples")   == 0 && i+1 < argc) { samples  = atoi(argv[++i]); }
        else if (strcmp(argv[i], "--key")       == 0 && i+1 < argc) { key_str  = argv[++i]; }
        else if (strcmp(argv[i], "--no-resume") == 0)                { no_resume = 1; }
        else if (strcmp(argv[i], "--help")      == 0 ||
                 strcmp(argv[i], "-h")          == 0) { print_usage(argv[0]); return 0; }
        else { fprintf(stderr, "error: unknown argument '%s'\n", argv[i]); return 1; }
    }

    if (!bin_path) {
        fprintf(stderr, "error: --bin is required\n\n");
        print_usage(argv[0]);
        return 1;
    }
    if (start_key > end_key) {
        fprintf(stderr, "error: --start must be <= --end\n"); return 1;
    }
    if (gpu_pct < 50 || gpu_pct > 95) gpu_pct = 80;
    if (threads <= 0) threads = plat_cpu_count() - 1;
    if (threads < 1) threads = 1;
    if (threads > 64) threads = 64;

    /* ── Load payloads ──────────────────────────────────────────────────── */
    payload_set_init(&g_payloads);
    printf("Loading %s ...\n", bin_path);
    if (!load_payload_file(bin_path, 0, &g_payloads, err, sizeof(err))) {
        fprintf(stderr, "error: %s\n", err); return 1;
    }
    printf("  %zu payloads loaded\n", g_payloads.count);

    if (g_payloads.count == 0) {
        fprintf(stderr, "error: no payloads in file\n"); return 1;
    }

    /* ── Single-key score mode ─────────────────────────────────────────── */
    if (key_str) {
        uint64_t kv;
        if (!parse_hex40(key_str, &kv)) {
            fprintf(stderr, "error: invalid --key value\n"); return 1;
        }
        unsigned char kb[5] = {
            (unsigned char)((kv >> 32) & 0xFF),
            (unsigned char)((kv >> 24) & 0xFF),
            (unsigned char)((kv >> 16) & 0xFF),
            (unsigned char)((kv >>  8) & 0xFF),
            (unsigned char)( kv        & 0xFF),
        };
        double sc = bruteforce_test_score(&g_payloads, 0, 0, kb);
        printf("Key ");
        print_key(kv);
        printf("  score: %.4f\n", sc);
        payload_set_free(&g_payloads);
        return 0;
    }

    /* ── Engine init ───────────────────────────────────────────────────── */
    bruteforce_engine_init(&g_engine);

    BruteforceConfig cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.start_key    = start_key;
    cfg.end_key      = end_key;
    cfg.thread_count = threads;
    cfg.sample_lines = samples;
    cfg.gpu_split_pct = gpu_pct;

    /* Determine sample_bytes from payload size */
    {
        size_t ml = 0;
        for (size_t i = 0; i < g_payloads.count; ++i)
            if (g_payloads.items[i].len > ml) ml = g_payloads.items[i].len;
        cfg.sample_bytes = (ml >= 33) ? 33 : 27;
    }

    /* ── Checkpoint resume ─────────────────────────────────────────────── */
    char progress_path[4096];
    snprintf(progress_path, sizeof(progress_path), "%s.progress", bin_path);

    if (!no_resume) {
        FILE *fp = fopen(progress_path, "rt");
        if (fp) {
            unsigned long long saved_offset = 0, saved_end = 0;
            int ok = (fscanf(fp, "offset=%llu\nend=%llu\n",
                             &saved_offset, &saved_end) == 2);
            fclose(fp);
            if (ok
                && saved_end    == (unsigned long long)cfg.end_key
                && saved_offset >  (unsigned long long)cfg.start_key
                && saved_offset <  (unsigned long long)cfg.end_key) {
                printf("Resuming from checkpoint at key %010llX\n",
                       (unsigned long long)saved_offset);
                cfg.start_key = (uint64_t)saved_offset;
            }
        }
    }

    /* Pass the progress path to the engine for periodic writes */
    strncpy(g_engine.progress_path, progress_path, sizeof(g_engine.progress_path) - 1);

    /* ── Signal handling ───────────────────────────────────────────────── */
    signal(SIGINT,  on_signal);
    signal(SIGTERM, on_signal);

    /* ── Start ─────────────────────────────────────────────────────────── */
    printf("Searching %010llX – %010llX  (%d threads, GPU %d%%)\n",
           (unsigned long long)cfg.start_key,
           (unsigned long long)cfg.end_key,
           cfg.thread_count, cfg.gpu_split_pct);
    printf("Press Ctrl+C to stop and save checkpoint.\n\n");

    if (!bruteforce_start(&g_engine, &cfg, &g_payloads, err, sizeof(err))) {
        fprintf(stderr, "error: %s\n", err); return 1;
    }

    /* ── Poll loop ──────────────────────────────────────────────────────── */
    BruteforceSnapshot snap;
    do {
        Sleep(500);
        bruteforce_get_snapshot(&g_engine, &snap);
        print_progress(&snap);
    } while (snap.running && !g_interrupted);

    bruteforce_get_snapshot(&g_engine, &snap);
    printf("\n\n");

    /* ── Result ─────────────────────────────────────────────────────────── */
    if (snap.finished) {
        printf("Search complete.\n");
        printf("Best key:   ");
        print_key(snap.best_key);
        printf("\nBest score: %.4f\n", snap.best_score);
        if (snap.best_score > 7.0) {
            printf("  ✓ Score above threshold — likely the correct key.\n");
        } else {
            printf("  ✗ Score below threshold — key may be wrong or sample too small.\n");
        }
    } else {
        printf("Search interrupted. Progress saved to %s\n", progress_path);
        printf("Best so far: ");
        print_key(snap.best_key);
        printf("  (score %.4f)\n", snap.best_score);
    }

    bruteforce_stop(&g_engine);
    bruteforce_engine_destroy(&g_engine);
    payload_set_free(&g_payloads);
    return 0;

#if defined(_WIN32)
    /* Free narrow args */
    for (int i = 0; i < argc; ++i) free(argv[i]);
    free(argv);
#endif
}

#endif /* NO_GUI / Linux */
