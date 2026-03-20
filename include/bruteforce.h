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

#ifndef BRUTEFORCE_H
#define BRUTEFORCE_H

#include <stddef.h>
#include <stdint.h>
#include <windows.h>

#include "payload_io.h"

typedef struct {
    uint64_t start_key;
    uint64_t end_key;
    int thread_count;
    int sample_lines;
    int sample_bytes;
} BruteforceConfig;

typedef struct {
    uint64_t keys_tested;
    uint64_t total_keys;
    uint64_t best_key;
    double best_score;
    double keys_per_second;
    double elapsed_seconds;
    double eta_seconds;
    int running;
    int paused;
    int finished;
} BruteforceSnapshot;

typedef struct BruteforceEngine {
    BruteforceConfig cfg;
    const PayloadSet *payloads;

    HANDLE *thread_handles;
    void *workers;
    HANDLE pause_event;

    CRITICAL_SECTION lock;
    volatile LONG running;
    volatile LONG paused;
    volatile LONG stop_requested;
    volatile LONG finished_threads;
    volatile LONG search_completed;
    volatile LONG64 keys_tested;

    uint64_t best_key;
    double best_score;

    LARGE_INTEGER qpc_start;
    LARGE_INTEGER qpc_freq;

    char cuda_error[256];  /* Last CUDA error message, empty if OK */
    char cuda_device_name[128]; /* Active CUDA device name if running on GPU */
    volatile LONG cuda_active;  /* 1 when CUDA backend is active */
    volatile LONG cuda_stage;   /* 0=init, 1=autotune, 2=scanning, 3=done */
    volatile LONG cuda_profile_cached; /* 1 if profile loaded from disk */
    volatile LONG cuda_tpb;
    volatile LONG cuda_bpsm;
    volatile LONG cuda_chunk_mult;
    volatile LONG cuda_sm_count;
    volatile LONG cuda_compute_major;
    volatile LONG cuda_compute_minor;
    volatile LONG64 cuda_last_update_ms;
} BruteforceEngine;

#ifdef __cplusplus
extern "C" {
#endif

// Host-side: Precompute cipher packs for all payloads (3x7 bytes per burst)
void precompute_cipher_packs(const PayloadSet *payloads, unsigned char *out_cipher_packs, int payload_limit);

// Note: The CUDA kernel assumes the first payload in the .bin corresponds to burst_pos=0 of a superframe.
// If the file is not aligned, the drop value will be incorrect and the scoring will not be valid.
// For maximum robustness, validate alignment on the host and/or add a burst_pos_start field to PayloadItem.

void bruteforce_engine_init(BruteforceEngine *engine);
void bruteforce_engine_destroy(BruteforceEngine *engine);

int bruteforce_start(
    BruteforceEngine *engine,
    const BruteforceConfig *cfg,
    const PayloadSet *payloads,
    char *err,
    size_t err_len);

void bruteforce_pause(BruteforceEngine *engine);
void bruteforce_resume(BruteforceEngine *engine);
void bruteforce_stop(BruteforceEngine *engine);
void bruteforce_get_snapshot(BruteforceEngine *engine, BruteforceSnapshot *out);

/* Public test API for scoring */
double bruteforce_test_score(
    const PayloadSet *payloads,
    int sample_lines,
    int sample_bytes,
    const unsigned char key[5]);

#ifdef __cplusplus
}
#endif

#endif
