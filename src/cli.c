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
 * cli.c - headless entry point for FSP.DMRCrack (-DNO_GUI / Linux build)
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

/* -- Banner ------------------------------------------------------------- */

static void print_banner(void)
{
    printf(
        "\n"
        "  ____  __  __ ____    ____                      _    \n"
        " |  _ \\|  \\/  |  _ \\  / ___|_ __ __ _  ___| | __\n"
        " | | | | |\\/| | |_) || |   | '__/ _` |/ __| |/ /\n"
        " | |_| | |  | |  _ < | |___| | | (_| | (__|   < \n"
        " |____/|_|  |_|_| \\_\\ \\____|_|  \\__,_|\\___|_|\\_\\\n"
        "\n"
        " v" DMRCRACK_VERSION "  |  RC4-40 key recovery for DMR Enhanced Privacy\n"
        " FSP-Labs  |  https://github.com/FSP-Labs/FSP.DMRCrack\n"
        "\n"
        " LEGAL: Security-auditing tool. Use ONLY on radio systems you own or are\n"
        "        explicitly authorized in writing to test. Unauthorized intercept\n"
        "        or decryption of communications is illegal in most jurisdictions\n"
        "        and is solely the user's responsibility. GPLv3, NO WARRANTY.\n"
        "\n"
    );
}

/* -- Globals ------------------------------------------------------------ */
static BruteforceEngine g_engine;
static PayloadSet       g_payloads;
static volatile int     g_interrupted = 0;

static void on_signal(int sig)
{
    (void)sig;
    g_interrupted = 1;
    bruteforce_stop(&g_engine);
}

/* -- Helpers ------------------------------------------------------------ */

static int parse_hex40(const char *s, uint64_t *out)
{
    char *end;
    uint64_t v = strtoull(s, &end, 16);
    if (end == s || *end != '\0' || v > 0xFFFFFFFFFFULL) return 0;
    *out = v;
    return 1;
}

/* Parse a 10-character nibble mask: a hex digit fixes that nibble, '?' is a
 * wildcard. e.g. "A1B2C3D4??" fixes the top 8 nibbles, frees the low 2.
 *   fixed_value  : fixed nibbles in place (wildcards left 0)
 *   free_nibbles : number of '?'
 *   free_idx[]   : nibble indices of wildcards, MS-first (0 = most significant)
 *   low_contig   : 1 if the wildcards are exactly the lowest free_nibbles
 *                  nibbles, i.e. the mask maps to a contiguous key range that
 *                  the GPU engine can sweep directly.
 * Returns 1 on success, 0 on a malformed mask. */
static int parse_mask(const char *s, uint64_t *fixed_value,
                      int *free_nibbles, int free_idx[10], int *low_contig)
{
    if (!s || strlen(s) != 10) return 0;
    uint64_t fixed = 0;
    int nfree = 0;
    for (int i = 0; i < 10; ++i) {
        char c = s[i];
        int shift = (9 - i) * 4;
        if (c == '?') { free_idx[nfree++] = i; continue; }
        int v;
        if      (c >= '0' && c <= '9') v = c - '0';
        else if (c >= 'a' && c <= 'f') v = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') v = c - 'A' + 10;
        else return 0;
        fixed |= (uint64_t)v << shift;
    }
    *fixed_value = fixed;
    *free_nibbles = nfree;
    int lc = 1;
    for (int k = 0; k < nfree; ++k)
        if (free_idx[k] != (10 - nfree + k)) { lc = 0; break; }
    *low_contig = (nfree > 0) ? lc : 1;
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

/* Last path component of a file path (for potfile/JSON labels). */
static const char *path_basename(const char *p)
{
    const char *b = p;
    for (const char *s = p; *s; ++s)
        if (*s == '/' || *s == '\\') b = s + 1;
    return b;
}

/* Potfile line: "<bin>:<KEY10HEX>:<score>". Appended, never overwritten, so
 * multiple recoveries accumulate. */
static void potfile_append(const char *potfile, const char *bin_path,
                           uint64_t key, double score)
{
    if (!potfile) return;
    FILE *fp = fopen(potfile, "at");
    if (!fp) {
        fprintf(stderr, "warning: cannot write potfile '%s'\n", potfile);
        return;
    }
    fprintf(fp, "%s:%010llX:%.4f\n",
            path_basename(bin_path), (unsigned long long)key, score);
    fclose(fp);
}

/* Final result as a one-line JSON object on stdout. */
static void print_json_result(const char *bin_path, uint64_t key, double score)
{
    printf("{\"bin\":\"%s\",\"key\":\"%010llX\",\"score\":%.4f}\n",
           path_basename(bin_path), (unsigned long long)key, score);
}

/* Look up a previously recovered key for this capture in the potfile, indexed
 * by capture file name (the hashcat model: results keyed by the unique thing
 * that was cracked, not by a reusable slot/KID). Returns 1 if found, so the
 * search can be skipped. Last matching line wins (most recent). */
static int potfile_lookup(const char *potfile, const char *bin_path,
                          uint64_t *key_out, double *score_out)
{
    if (!potfile) return 0;
    FILE *fp = fopen(potfile, "rt");
    if (!fp) return 0;
    const char *base = path_basename(bin_path);
    size_t blen = strlen(base);
    char line[4096];
    int found = 0;
    while (fgets(line, sizeof(line), fp)) {
        size_t ll = strlen(line);
        /* Skip any line that did not fit in the buffer (no terminating newline
         * and not EOF), so a truncated row never yields a partial wrong key. */
        if (ll == sizeof(line) - 1 && line[ll - 1] != '\n' && !feof(fp)) {
            int c; while ((c = fgetc(fp)) != '\n' && c != EOF) { }
            continue;
        }
        if (strncmp(line, base, blen) == 0 && line[blen] == ':') {
            unsigned long long key = 0; double sc = 0.0;
            if (sscanf(line + blen + 1, "%llx:%lf", &key, &sc) >= 1) {
                *key_out = key; if (score_out) *score_out = sc; found = 1;
            }
        }
    }
    fclose(fp);
    return found;
}

static void print_usage(void)
{
    printf(
        "Usage: dmrcrack --bin <payload.bin> [options]\n"
        "\n"
        "  --bin   <file>      .bin payload file (required)\n"
        "  --start <hex>       start key (default: 0000000000)\n"
        "  --end   <hex>       end key   (default: FFFFFFFFFF)\n"
        "  --threads <n>       CPU worker threads (default: auto)\n"
        "  --gpu-pct <50-95>   GPU share of keyspace (default: 80)\n"
        "  --samples <n>       payload lines to sample per key (default: all)\n"
        "  --key   <hex>       score a single key and exit\n"
        "  --mask  <10 chars>  nibble mask: hex digit fixes a nibble, '?' is a\n"
        "                      wildcard (e.g. A1B2C3D4??). Low wildcards map to a\n"
        "                      GPU range; scattered wildcards enumerate on CPU.\n"
        "  --wordlist <file>   try a list of candidate keys first (one hex key\n"
        "                      per line; '#' comments and blanks ignored)\n"
        "  --potfile <file>    append recovered keys to a potfile (bin:key:score);\n"
        "                      a capture already in the potfile is shown and skipped\n"
        "  --json              print the final result as a JSON object\n"
        "  --benchmark         measure throughput on this machine and exit\n"
        "  --no-resume         ignore any saved checkpoint\n"
        "\n");
}

/* -- Progress bar ------------------------------------------------------- */

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

/* -- Entry point -------------------------------------------------------- */

#if defined(_WIN32) && !defined(NO_GUI)
/* When built with GUI, this file is not compiled - main.c has WinMain. */
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
    print_banner();

    const char *bin_path   = NULL;
    const char *key_str    = NULL;
    const char *mask_str   = NULL;
    const char *wordlist   = NULL;
    const char *potfile    = NULL;
    uint64_t    start_key  = 0x0000000000ULL;
    uint64_t    end_key    = 0xFFFFFFFFFFULL;
    int         threads    = 0;   /* 0 = auto */
    int         gpu_pct    = 80;
    int         samples    = 0;   /* 0 = all */
    int         no_resume  = 0;
    int         json_out   = 0;
    int         benchmark  = 0;
    char        err[256];

    /* -- Argument parsing ----------------------------------------------- */
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
        else if (strcmp(argv[i], "--mask")      == 0 && i+1 < argc) { mask_str = argv[++i]; }
        else if (strcmp(argv[i], "--wordlist")  == 0 && i+1 < argc) { wordlist = argv[++i]; }
        else if (strcmp(argv[i], "--potfile")   == 0 && i+1 < argc) { potfile  = argv[++i]; }
        else if (strcmp(argv[i], "--json")      == 0)                { json_out  = 1; }
        else if (strcmp(argv[i], "--benchmark") == 0)                { benchmark = 1; }
        else if (strcmp(argv[i], "--no-resume") == 0)                { no_resume = 1; }
        else if (strcmp(argv[i], "--help")      == 0 ||
                 strcmp(argv[i], "-h")          == 0) { print_usage(); return 0; }
        else { fprintf(stderr, "error: unknown argument '%s'\n", argv[i]); return 1; }
    }

    if (!bin_path) {
        fprintf(stderr, "error: --bin is required\n\n");
        print_usage();
        return 1;
    }
    if (start_key > end_key) {
        fprintf(stderr, "error: --start must be <= --end\n"); return 1;
    }
    if (gpu_pct < 50 || gpu_pct > 95) gpu_pct = 80;
    if (threads <= 0) threads = plat_cpu_count() - 1;
    if (threads < 1) threads = 1;
    if (threads > 64) threads = 64;

    /* -- Load payloads ---------------------------------------------------- */
    payload_set_init(&g_payloads);
    printf("Loading %s ...\n", bin_path);
    if (!load_payload_file(bin_path, 0, &g_payloads, err, sizeof(err))) {
        fprintf(stderr, "error: %s\n", err); return 1;
    }
    printf("  %zu payloads loaded\n", g_payloads.count);

    if (g_payloads.count == 0) {
        fprintf(stderr, "error: no payloads in file\n"); return 1;
    }

    /* Up-front algorithm classification: tell the user whether this is even
     * crackable before committing to a long search. */
    {
        char cmsg[160]; int crackable = 0;
        payload_classify(&g_payloads, &crackable, cmsg, sizeof(cmsg));
        printf("  %s\n", cmsg);
        if (!crackable)
            fprintf(stderr, "warning: this capture is not recoverable by dmrcrack\n");
    }

    /* Potfile auto-skip (hashcat model): if this capture was already cracked,
     * show the stored key and skip the search. Only for an actual search run. */
    if (potfile && !key_str && !mask_str && !wordlist && !benchmark) {
        uint64_t pk; double ps;
        if (potfile_lookup(potfile, bin_path, &pk, &ps)) {
            printf("Already cracked (potfile): ");
            print_key(pk);
            printf("  (score %.2f)\n", ps);
            if (json_out) print_json_result(bin_path, pk, ps);
            payload_set_free(&g_payloads);
            return 0;
        }
    }

    /* -- Single-key score mode ------------------------------------------- */
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
        if (json_out) print_json_result(bin_path, kv, sc);
        payload_set_free(&g_payloads);
        return 0;
    }

    /* -- Dictionary / known-key mode ------------------------------------- */
    if (wordlist) {
        FILE *wf = fopen(wordlist, "rt");
        if (!wf) {
            fprintf(stderr, "error: cannot open wordlist '%s'\n", wordlist);
            payload_set_free(&g_payloads); return 1;
        }
        printf("Dictionary attack: %s\n\n", wordlist);

        char     line[256];
        uint64_t best_key = 0;
        double   best_score = -1e308;
        long     tried = 0, bad = 0;

        while (fgets(line, sizeof(line), wf)) {
            /* trim leading whitespace */
            char *s = line;
            while (*s == ' ' || *s == '\t') ++s;
            /* skip comments and blank lines */
            if (*s == '#' || *s == '\n' || *s == '\r' || *s == '\0') continue;
            /* trim trailing whitespace/newline */
            char *e = s + strlen(s);
            while (e > s && (e[-1] == '\n' || e[-1] == '\r' ||
                             e[-1] == ' '  || e[-1] == '\t')) --e;
            *e = '\0';

            uint64_t kv;
            if (!parse_hex40(s, &kv)) { ++bad; continue; }
            unsigned char kb[5] = {
                (unsigned char)((kv >> 32) & 0xFF),
                (unsigned char)((kv >> 24) & 0xFF),
                (unsigned char)((kv >> 16) & 0xFF),
                (unsigned char)((kv >>  8) & 0xFF),
                (unsigned char)( kv        & 0xFF),
            };
            double sc = bruteforce_test_score(&g_payloads, 0, 0, kb);
            ++tried;
            printf("  ");
            print_key(kv);
            printf("  score: %.4f\n", sc);
            if (sc > best_score) { best_score = sc; best_key = kv; }
        }
        fclose(wf);

        printf("\nTried %ld key(s)", tried);
        if (bad) printf(" (%ld malformed line(s) skipped)", bad);
        printf(".\n");

        if (tried == 0) {
            fprintf(stderr, "error: no valid keys in wordlist\n");
            payload_set_free(&g_payloads); return 1;
        }

        printf("Best candidate (highest score): ");
        print_key(best_key);
        printf("  (score %.4f)\n", best_score);

        potfile_append(potfile, bin_path, best_key, best_score);
        if (json_out) print_json_result(bin_path, best_key, best_score);

        payload_set_free(&g_payloads);
        return 0;
    }

    /* -- Mask mode ---------------------------------------------------------
     * Low (contiguous) wildcards collapse to a key range and run the normal
     * GPU search; scattered wildcards are enumerated on the CPU. */
    if (mask_str) {
        uint64_t fixed; int nfree, fidx[10], low_contig;
        if (!parse_mask(mask_str, &fixed, &nfree, fidx, &low_contig)) {
            fprintf(stderr, "error: --mask must be 10 chars of [0-9A-Fa-f?]\n");
            payload_set_free(&g_payloads); return 1;
        }

        if (nfree == 0) {
            /* Fully fixed mask: score the single key and exit. */
            unsigned char kb[5] = {
                (unsigned char)((fixed >> 32) & 0xFF), (unsigned char)((fixed >> 24) & 0xFF),
                (unsigned char)((fixed >> 16) & 0xFF), (unsigned char)((fixed >>  8) & 0xFF),
                (unsigned char)( fixed        & 0xFF) };
            double sc = bruteforce_test_score(&g_payloads, 0, 0, kb);
            printf("Mask %s (no wildcards) = single key ", mask_str);
            print_key(fixed); printf("  score: %.4f\n", sc);
            potfile_append(potfile, bin_path, fixed, sc);
            if (json_out) print_json_result(bin_path, fixed, sc);
            payload_set_free(&g_payloads); return 0;
        }

        if (low_contig) {
            /* Contiguous low wildcards -> a key range; let the GPU sweep it. */
            start_key = fixed;
            end_key   = fixed | ((((uint64_t)1) << (4 * nfree)) - 1);
            printf("Mask %s : %d free nibble(s) -> GPU range %010llX..%010llX\n\n",
                   mask_str, nfree,
                   (unsigned long long)start_key, (unsigned long long)end_key);
            /* fall through to the full search below */
        } else {
            /* Scattered wildcards: enumerate the masked subset on the CPU. */
            uint64_t total = 1;
            for (int k = 0; k < nfree; ++k) total *= 16ULL;
            if (total > (1ULL << 20)) {
                fprintf(stderr,
                    "error: scattered mask spans %llu keys, too many for CPU "
                    "enumeration.\n       Use a prefix mask with low wildcards "
                    "(e.g. ABCDE?????) for a GPU range search.\n",
                    (unsigned long long)total);
                payload_set_free(&g_payloads); return 1;
            }
            printf("Mask %s : %d scattered free nibble(s), %llu combination(s) "
                   "(CPU)\n\n", mask_str, nfree, (unsigned long long)total);

            uint64_t best_key = 0; double best_score = -1e308;
            for (uint64_t combo = 0; combo < total; ++combo) {
                uint64_t kv = fixed;
                for (int k = 0; k < nfree; ++k) {
                    unsigned digit = (unsigned)((combo >> (4 * (nfree - 1 - k))) & 0xF);
                    kv |= (uint64_t)digit << ((9 - fidx[k]) * 4);
                }
                unsigned char kb[5] = {
                    (unsigned char)((kv >> 32) & 0xFF), (unsigned char)((kv >> 24) & 0xFF),
                    (unsigned char)((kv >> 16) & 0xFF), (unsigned char)((kv >>  8) & 0xFF),
                    (unsigned char)( kv        & 0xFF) };
                double sc = bruteforce_test_score(&g_payloads, 0, 0, kb);
                if (sc > best_score) { best_score = sc; best_key = kv; }
            }
            printf("Best candidate (highest score): ");
            print_key(best_key); printf("  (score %.4f)\n", best_score);
            potfile_append(potfile, bin_path, best_key, best_score);
            if (json_out) print_json_result(bin_path, best_key, best_score);
            payload_set_free(&g_payloads); return 0;
        }
    }

    /* Determine sample_bytes from payload size (shared by benchmark + search) */
    int sample_bytes;
    {
        size_t ml = 0;
        for (size_t i = 0; i < g_payloads.count; ++i)
            if (g_payloads.items[i].len > ml) ml = g_payloads.items[i].len;
        sample_bytes = (ml >= 33) ? 33 : 27;
    }

    /* -- Benchmark mode -------------------------------------------------- */
    if (benchmark) {
        const double bench_seconds = 5.0;
        printf("Benchmark: running ~%.0f s over the keyspace...\n\n",
               bench_seconds);

        bruteforce_engine_init(&g_engine);

        BruteforceConfig bcfg;
        memset(&bcfg, 0, sizeof(bcfg));
        bcfg.start_key     = 0;
        bcfg.end_key       = 0xFFFFFFFFFFULL; /* full 40-bit space */
        bcfg.thread_count  = threads;
        bcfg.sample_lines  = samples;
        bcfg.gpu_split_pct = gpu_pct;
        bcfg.sample_bytes  = sample_bytes;

        if (!bruteforce_start(&g_engine, &bcfg, &g_payloads, err, sizeof(err))) {
            fprintf(stderr, "error: %s\n", err);
            bruteforce_engine_destroy(&g_engine);
            payload_set_free(&g_payloads);
            return 1;
        }

        BruteforceSnapshot bsnap;
        double waited = 0.0;
        do {
            plat_sleep_ms(500);
            waited += 0.5;
            bruteforce_get_snapshot(&g_engine, &bsnap);
            print_progress(&bsnap);
        } while (bsnap.running && !g_interrupted && waited < bench_seconds);

        bruteforce_stop(&g_engine);
        bruteforce_get_snapshot(&g_engine, &bsnap);
        printf("\n\n");

        printf("Benchmark result:\n");
        printf("  keys tested:  %llu\n",
               (unsigned long long)bsnap.keys_tested);
        printf("  elapsed:      %.2f s\n", bsnap.elapsed_seconds);
        printf("  throughput:   %.2f M keys/s\n",
               bsnap.keys_per_second / 1e6);
        if (json_out)
            printf("{\"keys_tested\":%llu,\"elapsed_s\":%.3f,"
                   "\"keys_per_second\":%.0f}\n",
                   (unsigned long long)bsnap.keys_tested,
                   bsnap.elapsed_seconds, bsnap.keys_per_second);

        bruteforce_engine_destroy(&g_engine);
        payload_set_free(&g_payloads);
        return 0;
    }

    /* -- Engine init ----------------------------------------------------- */
    bruteforce_engine_init(&g_engine);

    BruteforceConfig cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.start_key    = start_key;
    cfg.end_key      = end_key;
    cfg.thread_count = threads;
    cfg.sample_lines = samples;
    cfg.gpu_split_pct = gpu_pct;
    cfg.sample_bytes  = sample_bytes;

    /* -- Checkpoint resume ----------------------------------------------- */
    char progress_path[4096];
    snprintf(progress_path, sizeof(progress_path), "%s.progress", bin_path);

    if (!no_resume) {
        FILE *fp = fopen(progress_path, "rt");
        if (fp) {
            unsigned long long saved_offset = 0, saved_end = 0;
            unsigned long long saved_best_key = 0;
            double saved_best_score = -1e308;
            unsigned long long saved_original_start = 0;
            int ok = (fscanf(fp, "offset=%llu\nend=%llu\n",
                             &saved_offset, &saved_end) == 2);
            if (ok) {
                /* These fields are optional; if the format differs the
                 * defaults above (no seeded best, no resume context) stand. */
                if (fscanf(fp, "best_key=%llX\nbest_score=%lf\n",
                           &saved_best_key, &saved_best_score) != 2) {
                    saved_best_key = 0;
                    saved_best_score = -1e308;
                }
                if (fscanf(fp, "original_start=%llu\n", &saved_original_start) != 1)
                    saved_original_start = 0;
            }
            fclose(fp);
            if (ok
                && saved_end    == (unsigned long long)cfg.end_key
                && saved_offset >  (unsigned long long)cfg.start_key
                && saved_offset <  (unsigned long long)cfg.end_key) {
                printf("Resuming from checkpoint at key %010llX\n",
                       (unsigned long long)saved_offset);
                if (saved_best_score > -1e307 && saved_best_key != 0)
                    printf("Restoring best candidate: %010llX (score %.2f)\n",
                           (unsigned long long)saved_best_key, saved_best_score);
                cfg.start_key          = (uint64_t)saved_offset;
                cfg.has_seed_best      = (saved_best_score > -1e307 && saved_best_key != 0) ? 1 : 0;
                cfg.seed_best_key      = (uint64_t)saved_best_key;
                cfg.seed_best_score    = saved_best_score;
                cfg.has_resume_context = (saved_original_start > 0 || saved_offset == 0) ? 1 : 0;
                cfg.original_start_key = cfg.has_resume_context ? (uint64_t)saved_original_start : (uint64_t)saved_offset;
            }
        }
    }

    /* Pass the progress path to the engine for periodic writes */
    strncpy(g_engine.progress_path, progress_path, sizeof(g_engine.progress_path) - 1);

    /* -- Signal handling ------------------------------------------------- */
    signal(SIGINT,  on_signal);
    signal(SIGTERM, on_signal);

    /* -- Start ----------------------------------------------------------- */
    printf("Searching %010llX - %010llX  (%d threads, GPU %d%%)\n",
           (unsigned long long)cfg.start_key,
           (unsigned long long)cfg.end_key,
           cfg.thread_count, cfg.gpu_split_pct);
    printf("Press Ctrl+C to stop and save checkpoint.\n\n");

    if (!bruteforce_start(&g_engine, &cfg, &g_payloads, err, sizeof(err))) {
        fprintf(stderr, "error: %s\n", err);
        bruteforce_engine_destroy(&g_engine);
        payload_set_free(&g_payloads);
        return 1;
    }

    /* -- Poll loop -------------------------------------------------------- */
    BruteforceSnapshot snap;
    do {
        plat_sleep_ms(500);
        bruteforce_get_snapshot(&g_engine, &snap);
        print_progress(&snap);
    } while (snap.running && !g_interrupted);

    bruteforce_get_snapshot(&g_engine, &snap);
    printf("\n\n");

    /* -- Result ----------------------------------------------------------- */
    if (snap.finished) {
        printf("Search complete.\n");
        printf("Best key:   ");
        print_key(snap.best_key);
        printf("\nBest score: %.4f\n", snap.best_score);
        printf("  (highest-scoring key over the searched range - the recovered key)\n");
        potfile_append(potfile, bin_path, snap.best_key, snap.best_score);
        if (json_out) print_json_result(bin_path, snap.best_key, snap.best_score);
    } else {
        printf("Search interrupted. Progress saved to %s\n", progress_path);
        printf("Best so far: ");
        print_key(snap.best_key);
        printf("  (score %.4f)\n", snap.best_score);
    }

    bruteforce_stop(&g_engine);
    bruteforce_engine_destroy(&g_engine);
    payload_set_free(&g_payloads);

#if defined(_WIN32)
    for (int i = 0; i < argc; ++i) free(argv[i]);
    free(argv);
#endif
    return 0;
}

#endif /* NO_GUI / Linux */
