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

/* ── Named constants (replaces magic numbers across bruteforce.cu) ── */
#define DMR_CIPHER_PACK_BYTES   21      /* 3 sub-frames × 7 RC4 bytes per burst */
#define RC4_SBOX_SIZE           256     /* RC4 S-box entries (S[] arrays, KSA init loops) */
#define RC4_DISCARD_BYTES       256     /* keystream bytes discarded before decryption */
#define STOP_POLL_MASK          0x3FFu  /* check stop-flag every 1024 kernel iterations */
#define LOCAL_KEYS_FLUSH        16384   /* flush local key counter to global atomicAdd */

#include <stddef.h>
#include <stdint.h>
#include "platform.h"
#include "payload_io.h"

/* Maximum path length for the progress sidecar file */
#ifndef PLAT_MAX_PATH
#  if defined(_WIN32)
#    define PLAT_MAX_PATH 260
#  else
#    define PLAT_MAX_PATH 4096
#  endif
#endif

typedef struct {
    uint64_t start_key;
    uint64_t end_key;
    int thread_count;
    int sample_lines;
    int sample_bytes;
    int gpu_split_pct;   /* GPU share of keyspace [50..95], default 80 */
    int has_seed_best;       /* 1 = seed_best_key/score are valid (checkpoint resume) */
    uint64_t seed_best_key;
    double   seed_best_score;
    int      has_resume_context;    /* 1 = original_start_key is valid */
    uint64_t original_start_key;    /* start key before any resume; used for progress % */
} BruteforceConfig;

typedef struct {
    uint64_t keys_tested;
    uint64_t gpu_keys_tested;
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

    plat_thread_t *thread_handles;
    void          *workers;
    plat_event_t   pause_event;

    plat_mutex_t    lock;
    plat_atomic32_t running;
    plat_atomic32_t paused;
    plat_atomic32_t stop_requested;
    plat_atomic32_t finished_threads;
    plat_atomic32_t search_completed;
    plat_atomic64_t keys_tested;
    plat_atomic64_t gpu_keys_tested; /* Keys tested by CUDA/HIP GPU only */

    uint64_t best_key;
    double   best_score;

    plat_hrtimer_t qpc_start;
    plat_hrfreq_t  qpc_freq;

    char cuda_error[256];              /* Last GPU error message, empty if OK */
    char cuda_device_name[128];        /* Active GPU device name */
    char progress_path[PLAT_MAX_PATH]; /* Path to .progress sidecar file, empty if unused */
    plat_atomic32_t cuda_active;       /* 1 when GPU backend is running */
    plat_atomic32_t cuda_stage;        /* 0=init, 1=autotune, 2=scanning, 3=done */
    plat_atomic32_t cuda_profile_cached;
    plat_atomic32_t cuda_tpb;
    plat_atomic32_t cuda_bpsm;
    plat_atomic32_t cuda_chunk_mult;
    plat_atomic32_t cuda_sm_count;
    plat_atomic32_t cuda_compute_major;
    plat_atomic32_t cuda_compute_minor;
    plat_atomic64_t cuda_last_update_ms;
} BruteforceEngine;

#ifdef __cplusplus
extern "C" {
#endif

// Host-side: Precompute cipher packs for all payloads (3x7 bytes per burst)
void precompute_cipher_packs(const PayloadSet *payloads, unsigned char *out_cipher_packs, int payload_limit);

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
void bruteforce_get_snapshot(const BruteforceEngine *engine, BruteforceSnapshot *out);

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
