// FSP.DMRCrack - GPU-accelerated ARC4 key recovery for DMR communications
// Copyright (C) 2026 FSP-Labs
//
// Benchmark & correctness test for bruteforce kernels.
// Compile via build_bench.bat

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include <windows.h>
#include <cuda_runtime.h>

#include "payload_io.h"
#include "bruteforce.h"

/* -------------------------------------------------------------------------
 * Forward declarations for the kernel and its constant memory symbols.
 * These are *defined* in bruteforce.cu and resolved at device link time
 * (requires -rdc=true in the build).
 * ------------------------------------------------------------------------- */

/* Kernel - C++ (mangled) linkage, matches bruteforce.cu definition */
__global__ void bruteforce_kernel_strict(
    uint64_t start_key,
    uint64_t total_keys,
    int payload_count,
    uint32_t global_mi,
    unsigned long long* __restrict__ dev_keys_tested,
    float* __restrict__             dev_best_score,
    unsigned long long* __restrict__ dev_best_key,
    int* __restrict__               dev_stop_requested);

/* Constant memory symbols defined in bruteforce.cu */
#define MAX_CONST_LINES 256
extern __constant__ unsigned char  d_const_cipher_packs[MAX_CONST_LINES * 21];
extern __constant__ unsigned int   d_const_mi[MAX_CONST_LINES];
extern __constant__ unsigned char  d_const_algid[MAX_CONST_LINES];
extern __constant__ unsigned char  d_const_meta_flags[MAX_CONST_LINES];
extern __constant__ float          d_abs_floor[MAX_CONST_LINES + 1];

/* -------------------------------------------------------------------------
 * Helpers
 * ------------------------------------------------------------------------- */

static void print_sep(void)
{
    printf("------------------------------------------------------------\n");
}

static int get_clock_khz(int dev)
{
    int v = 0;
    cudaDeviceGetAttribute(&v, cudaDevAttrClockRate, dev);
    return v;  /* kHz */
}

static void print_device_info(void)
{
    int dev;
    cudaGetDevice(&dev);
    cudaDeviceProp p;
    cudaGetDeviceProperties(&p, dev);
    int clock_khz = get_clock_khz(dev);
    printf("GPU : %s\n", p.name);
    printf("  SM count       : %d\n",   p.multiProcessorCount);
    printf("  Clock (MHz)    : %d\n",   clock_khz / 1000);
    printf("  Regs/SM        : %d\n",   p.regsPerMultiprocessor);
    printf("  Shared mem/SM  : %zu KB\n", p.sharedMemPerMultiprocessor / 1024);
    printf("  Warp size      : %d\n",   p.warpSize);
}

/* Upload cipher_packs and metadata to constant memory.
 * Returns the number of payloads actually uploaded (min of n, limit, MAX_CONST_LINES). */
static int upload_payloads(const PayloadSet *ps, int limit,
                           float *abs_floor_host)
{
    int n = (int)ps->count;
    if (n > limit)           n = limit;
    if (n > MAX_CONST_LINES) n = MAX_CONST_LINES;

    static unsigned char h_cipher[MAX_CONST_LINES * 21];
    static unsigned int  h_mi[MAX_CONST_LINES];
    static unsigned char h_algid[MAX_CONST_LINES];
    static unsigned char h_flags[MAX_CONST_LINES];

    /* Pre-compute de-interleaved+packed cipher packs (3 sub-frames x 7 bytes each).
     * This is the format the strict kernel expects in d_const_cipher_packs. */
    precompute_cipher_packs(ps, h_cipher, n);

    for (int i = 0; i < n; i++) {
        const PayloadLine *pl = &ps->items[i];
        h_mi[i]    = pl->mi;
        h_algid[i] = pl->algid;
        h_flags[i] = pl->has_mi ? 0x1u : 0u;
    }

    cudaMemcpyToSymbol(d_const_cipher_packs, h_cipher, n * 21);
    cudaMemcpyToSymbol(d_const_mi,    h_mi,    n * sizeof(unsigned int));
    cudaMemcpyToSymbol(d_const_algid, h_algid, n * sizeof(unsigned char));
    cudaMemcpyToSymbol(d_const_meta_flags, h_flags, n * sizeof(unsigned char));

    /* Absolute per-burst Hamming floor: same formula as bruteforce.cu cuda_launcher_thread.
     * Wrong key:   mean = 24*k, sigma ~ 3.46*sqrt(k)
     * Correct key: mean ~ 44*k  (h01~2, h12~2 -> score ~ 44/burst)
     * Floor = 33*k - 2*sigma rejects ~99.9997% of wrong keys. */
    abs_floor_host[0] = -3.402823e38f;
    for (int k = 1; k <= n; k++) {
        float sigma_k = 3.46f * sqrtf((float)k);
        abs_floor_host[k] = 33.0f * (float)k - 2.0f * sigma_k;
    }
    for (int k = n + 1; k <= MAX_CONST_LINES; k++)
        abs_floor_host[k] = -3.402823e38f;
    cudaMemcpyToSymbol(d_abs_floor, abs_floor_host,
                       (MAX_CONST_LINES + 1) * sizeof(float));
    return n;
}

/* -------------------------------------------------------------------------
 * Benchmark: run kernel for ~duration_ms ms, return keys/s
 * ------------------------------------------------------------------------- */
static double run_benchmark(int payload_count, uint32_t global_mi,
                            int tpb, int blocks,
                            double duration_ms)
{
    unsigned long long *d_keys_tested, *d_best_key;
    float              *d_best_score;
    int                *d_stop;

    cudaMalloc(&d_keys_tested, sizeof(unsigned long long));
    cudaMalloc(&d_best_key,    sizeof(unsigned long long));
    cudaMalloc(&d_best_score,  sizeof(float));
    cudaMalloc(&d_stop,        sizeof(int));

    float neg_inf = -3.402823e38f;
    cudaMemset(d_keys_tested, 0, sizeof(unsigned long long));
    cudaMemset(d_best_key,    0, sizeof(unsigned long long));
    cudaMemcpy(d_best_score, &neg_inf, sizeof(float), cudaMemcpyHostToDevice);
    cudaMemset(d_stop, 0, sizeof(int));

    /* Warm-up (1 chunk) */
    uint64_t chunk = (uint64_t)blocks * tpb * 64;
    bruteforce_kernel_strict<<<blocks, tpb>>>(
        0ULL, chunk, payload_count, global_mi,
        d_keys_tested, d_best_score, d_best_key, d_stop);
    cudaDeviceSynchronize();

    /* Reset counters */
    cudaMemset(d_keys_tested, 0, sizeof(unsigned long long));
    float neg_inf2 = -3.402823e38f;
    cudaMemcpy(d_best_score, &neg_inf2, sizeof(float), cudaMemcpyHostToDevice);

    /* Timed run */
    cudaEvent_t t0, t1;
    cudaEventCreate(&t0);
    cudaEventCreate(&t1);

    uint64_t total_keys = 0;
    cudaEventRecord(t0);

    double elapsed = 0.0;
    while (elapsed < duration_ms) {
        bruteforce_kernel_strict<<<blocks, tpb>>>(
            total_keys, chunk, payload_count, global_mi,
            d_keys_tested, d_best_score, d_best_key, d_stop);
        total_keys += chunk;
        cudaEventRecord(t1);
        cudaEventSynchronize(t1);
        float ms;
        cudaEventElapsedTime(&ms, t0, t1);
        elapsed = (double)ms;
    }

    unsigned long long keys_done;
    cudaMemcpy(&keys_done, d_keys_tested, sizeof(unsigned long long),
               cudaMemcpyDeviceToHost);

    double kps = (double)keys_done / (elapsed / 1000.0);

    cudaFree(d_keys_tested);
    cudaFree(d_best_key);
    cudaFree(d_best_score);
    cudaFree(d_stop);
    cudaEventDestroy(t0);
    cudaEventDestroy(t1);

    return kps;
}

/* -------------------------------------------------------------------------
 * Correctness test: verify known key is found with score > 0
 * ------------------------------------------------------------------------- */
static int correctness_test(const PayloadSet *ps, uint64_t known_key,
                            int payload_count, uint32_t global_mi,
                            int tpb, int blocks)
{
    unsigned long long *d_keys_tested, *d_best_key;
    float              *d_best_score;
    int                *d_stop;

    cudaMalloc(&d_keys_tested, sizeof(unsigned long long));
    cudaMalloc(&d_best_key,    sizeof(unsigned long long));
    cudaMalloc(&d_best_score,  sizeof(float));
    cudaMalloc(&d_stop,        sizeof(int));

    float neg_inf = -3.402823e38f;
    cudaMemset(d_keys_tested, 0, sizeof(unsigned long long));
    cudaMemset(d_best_key,    0, sizeof(unsigned long long));
    cudaMemcpy(d_best_score, &neg_inf, sizeof(float), cudaMemcpyHostToDevice);
    cudaMemset(d_stop, 0, sizeof(int));

    /* Test a window centred on the known key.
     * Must be > 1<<20 (1M) so enable_prune=1 fires in the kernel. */
    uint64_t window = 2ULL << 20;  /* 2M keys */
    uint64_t start  = (known_key >= window / 2) ? known_key - window / 2 : 0;

    bruteforce_kernel_strict<<<blocks, tpb>>>(
        start, window, payload_count, global_mi,
        d_keys_tested, d_best_score, d_best_key, d_stop);
    cudaDeviceSynchronize();

    float              h_score = 0.0f;
    unsigned long long h_key   = 0ULL;
    cudaMemcpy(&h_score, d_best_score, sizeof(float),              cudaMemcpyDeviceToHost);
    cudaMemcpy(&h_key,   d_best_key,   sizeof(unsigned long long), cudaMemcpyDeviceToHost);

    cudaFree(d_keys_tested);
    cudaFree(d_best_key);
    cudaFree(d_best_score);
    cudaFree(d_stop);

    printf("  Best key found : %010llX  (expected %010llX)  %s\n",
           h_key, (unsigned long long)known_key,
           h_key == known_key ? "PASS" : "FAIL");
    printf("  Best score     : %.2f  (> 0 to pass)\n", h_score);

    return (h_score > 0.0f) ? 0 : 1;
}

/* -------------------------------------------------------------------------
 * Occupancy analysis
 * ------------------------------------------------------------------------- */
static void occupancy_analysis(int tpb)
{
    int dev;
    cudaGetDevice(&dev);
    cudaDeviceProp p;
    cudaGetDeviceProperties(&p, dev);

    int min_grid, block_size;
    cudaOccupancyMaxPotentialBlockSize(&min_grid, &block_size,
        bruteforce_kernel_strict, 0, 0);

    int active_blocks = 0;
    cudaOccupancyMaxActiveBlocksPerMultiprocessor(
        &active_blocks, bruteforce_kernel_strict, tpb, 0);

    int warps_per_sm = active_blocks * (tpb / p.warpSize);
    int max_warps    = p.maxThreadsPerMultiProcessor / p.warpSize;
    float occupancy  = (float)warps_per_sm / (float)max_warps * 100.0f;

    printf("  Threads/block (requested) : %d\n", tpb);
    printf("  Active blocks/SM          : %d\n", active_blocks);
    printf("  Warps/SM                  : %d / %d\n", warps_per_sm, max_warps);
    printf("  Theoretical occupancy     : %.1f%%\n", occupancy);
    printf("  Optimal block size (CUDA) : %d\n", block_size);
}

/* -------------------------------------------------------------------------
 * Main
 * ------------------------------------------------------------------------- */
int main(int argc, char **argv)
{
    const char *bin_path   = "test/aaaaa/RC4-40.fromdsdfme.bin";
    uint64_t    known_key  = 0x0000000000ULL;
    int         tpb        = 256;
    double      bench_secs = 3.0;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--bin")  && i+1 < argc) bin_path   = argv[++i];
        if (!strcmp(argv[i], "--key")  && i+1 < argc) known_key  = strtoull(argv[++i], NULL, 16);
        if (!strcmp(argv[i], "--tpb")  && i+1 < argc) tpb        = atoi(argv[++i]);
        if (!strcmp(argv[i], "--secs") && i+1 < argc) bench_secs = atof(argv[++i]);
    }

    printf("\n=== FSP.DMRCrack kernel benchmark ===\n\n");
    print_sep();
    print_device_info();
    print_sep();

    /* Load payloads */
    PayloadSet ps;
    payload_set_init(&ps);
    char err[256] = {0};
    if (!load_payload_file(bin_path, MAX_CONST_LINES, &ps, err, sizeof(err))) {
        fprintf(stderr, "ERROR: cannot load %s: %s\n", bin_path, err);
        return 1;
    }
    printf("Payload file   : %s  (%zu lines)\n", bin_path, ps.count);

    /* Global MI from first payload that has one */
    uint32_t global_mi = 0u;
    for (size_t i = 0; i < ps.count; i++) {
        if (ps.items[i].has_mi) { global_mi = ps.items[i].mi; break; }
    }

    int dev;
    cudaGetDevice(&dev);
    cudaDeviceProp prop;
    cudaGetDeviceProperties(&prop, dev);
    int clock_khz = get_clock_khz(dev);

    float abs_floor_host[MAX_CONST_LINES + 1];

    /* --- Occupancy analysis --------------------------------------------- */
    print_sep();
    printf("OCCUPANCY ANALYSIS (bruteforce_kernel_strict, tpb=%d)\n", tpb);
    print_sep();
    occupancy_analysis(tpb);

    /* --- Throughput benchmark -------------------------------------------- */
    printf("\n");
    print_sep();
    printf("THROUGHPUT BENCHMARK (strict kernel)\n");
    print_sep();

    int payload_counts[] = {6, 12, 30, 60, 126};
    int n_tests = (int)(sizeof(payload_counts) / sizeof(payload_counts[0]));

    int active_blocks_main = 0;
    cudaOccupancyMaxActiveBlocksPerMultiprocessor(
        &active_blocks_main, bruteforce_kernel_strict, tpb, 0);
    int blocks = prop.multiProcessorCount * active_blocks_main;

    for (int t = 0; t < n_tests; t++) {
        int pc = payload_counts[t];
        if ((size_t)pc > ps.count) pc = (int)ps.count;

        int uploaded = upload_payloads(&ps, pc, abs_floor_host);

        double kps = run_benchmark(uploaded, global_mi, tpb, blocks,
                                   bench_secs * 1000.0);

        /* RC4 steps: KSA256 + discard + 3 sub-frames/burst * 7 bytes = 21 PRGA steps
           For reject path (chi2 prunes early), use conservative 256+256+63 */
        double rc4_steps = 256.0 + 256.0 + (double)uploaded * 21.0 / 6.0;
        double cycles_per_key  = (double)clock_khz * 1000.0 / kps;
        double cycles_per_step = cycles_per_key / rc4_steps;

        printf("  payloads=%3d  blocks=%4d  -> %7.2f M keys/s"
               "  (%.0f cyc/key, %.1f cyc/RC4-step)\n",
               uploaded, blocks, kps / 1e6, cycles_per_key, cycles_per_step);
    }

    /* --- Correctness test ------------------------------------------------ */
    if (known_key != 0) {
        printf("\n");
        print_sep();
        printf("CORRECTNESS TEST (key=%010llX)\n", (unsigned long long)known_key);
        print_sep();

        int pc = (int)(ps.count < (size_t)MAX_CONST_LINES
                       ? ps.count : MAX_CONST_LINES);
        upload_payloads(&ps, pc, abs_floor_host);

        int rc = correctness_test(&ps, known_key, pc, global_mi, tpb, blocks);
        printf("  Result: %s\n", rc == 0 ? "PASS" : "FAIL");
    }

    /* --- Bottleneck analysis --------------------------------------------- */
    printf("\n");
    print_sep();
    printf("BOTTLENECK ANALYSIS\n");
    print_sep();
    {
        int uploaded = upload_payloads(&ps, 6, abs_floor_host);
        double kps   = run_benchmark(uploaded, global_mi, tpb, blocks,
                                     bench_secs * 1000.0);

        double cycles_per_key  = (double)clock_khz * 1000.0 / kps;
        /* 6 payloads = 1 superframe; reject path: KSA256 + discard256 + 63 PRGA */
        double rc4_steps       = 256.0 + 256.0 + 63.0;
        double cycles_per_step = cycles_per_key / rc4_steps;
        int    warps_per_sm    = active_blocks_main * (tpb / prop.warpSize);

        /* Ampere (sm_86): 128 CUDA cores/SM */
        int    cuda_cores_per_sm = (prop.major == 8) ? 128 : 64;
        double peak_int_ops      = (double)prop.multiProcessorCount
                                   * (double)cuda_cores_per_sm
                                   * (double)clock_khz * 1000.0;
        double actual_ops        = kps * rc4_steps * 5.0; /* ~5 ops/RC4 step */
        double efficiency        = actual_ops / peak_int_ops * 100.0;

        printf("  Keys/s (6-payload)        : %.2f M\n",  kps / 1e6);
        printf("  Cycles/key (empirical)    : %.0f\n",    cycles_per_key);
        printf("  RC4 steps/key (reject)    : %.0f\n",    rc4_steps);
        printf("  Cycles/RC4-step           : %.1f"
               "  (register-file latency ~4-8 cycles)\n", cycles_per_step);
        printf("  Warps/SM                  : %d\n",      warps_per_sm);
        printf("  Integer efficiency        : %.2f%%\n",  efficiency);
        printf("\n");
        printf("  Bottleneck: j-dependency RAW chain in RC4 KSA/PRGA\n");
        printf("    j[i] = (j[i-1] + S[i] + key[i%%9]) & 0xFF\n");
        printf("    => 256-level serial dependency, all warps stall together\n");
        printf("    => warp latency hiding ineffective for the KSA loop\n");
        printf("    => %.1f cyc/step ~ hardware register-file read latency\n",
               cycles_per_step);
    }

    print_sep();
    payload_set_free(&ps);
    return 0;
}
