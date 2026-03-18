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

#include "../include/bruteforce.h"

#include <float.h>
#include <math.h>
#include <process.h>
#include <windows.h>
#include <stdlib.h>

#include "../include/rc4.h"

typedef struct {
    BruteforceEngine *engine;
    uint64_t start_key;
    uint64_t end_key;
    int worker_index;
} WorkerCtx;

static void set_error(char *err, size_t err_len, const char *msg)
{
    if (err != NULL && err_len > 0) {
        size_t n = 0;
        while (msg[n] != '\0' && n + 1 < err_len) {
            err[n] = msg[n];
            n++;
        }
        err[n] = '\0';
    }
}

static uint64_t read_u64(const volatile LONG64 *value)
{
    return (uint64_t)InterlockedCompareExchange64((volatile LONG64 *)value, 0, 0);
}

static void close_worker_resources(BruteforceEngine *engine)
{
    int t;

    if (engine->thread_handles != NULL) {
        for (t = 0; t < engine->cfg.thread_count; ++t) {
            if (engine->thread_handles[t] != NULL) {
                CloseHandle(engine->thread_handles[t]);
            }
        }
        free(engine->thread_handles);
        engine->thread_handles = NULL;
    }

    free(engine->workers);
    engine->workers = NULL;

    if (engine->pause_event != NULL) {
        CloseHandle(engine->pause_event);
        engine->pause_event = NULL;
    }
}

static void key_to_5bytes(uint64_t key, unsigned char out[5])
{
    out[0] = (unsigned char)((key >> 32) & 0xFFu);
    out[1] = (unsigned char)((key >> 24) & 0xFFu);
    out[2] = (unsigned char)((key >> 16) & 0xFFu);
    out[3] = (unsigned char)((key >> 8) & 0xFFu);
    out[4] = (unsigned char)(key & 0xFFu);
}


/*
 * ==========================================================================
 * Heurística de scoring para DMR Basic Privacy (ARC4 40-bit) — v3
 * ==========================================================================
 *
 * PRINCIPIO FUNDAMENTAL:
 * En DMR, los 216 bits del burst están INTERLEAVED (BPTC), por lo que
 * los bytes consecutivos del payload NO corresponden a campos AMBE+2
 * específicos. Por tanto, patrones como "silence frame" (B9E88148) a
 * offsets fijos son INÚTILES.
 *
 * La ÚNICA señal aprovechable es la estructura INTRA-PAYLOAD:
 * relaciones estadísticas entre posiciones dentro de un mismo payload,
 * que cambian con el keystream mask de cada clave candidata.
 *
 * MÉTRICAS que SÍ discriminan:
 *
 * A) AUTOCORRELACIÓN MULTI-LAG: Hamming distance entre bytes a diferentes
 *    lags (distancias) dentro del payload. Datos estructurados tienden a
 *    tener autocorrelación a ciertos lags; datos random no.
 *
 * B) TASA DE TRANSICIONES BIT: Contar cambios 0→1 y 1→0 en el stream
 *    de bits. Datos AMBE interleaved tienen tasas de transición
 *    diferentes al 50% teórico de datos random.
 *
 * C) BIT RATIO (distribución de unos): Con clave correcta, el plaintext
 *    tiene bit ratio diferente al 50% de datos random.
 *    NOTA: bit ratio PER PAYLOAD sí depende de la clave (la mask XOR
 *    altera qué bits están a 1). Es un señal débil pero acumulativo.
 *
 * MÉTRICAS INÚTILES (eliminadas):
 *
 * - Silence frame matching: requiere de-interleaving que no hacemos
 * - Cross-payload hamming: matemáticamente invariante al key (RC4)
 * - Per-position byte statistics: invariante (XOR con cte = biyección)
 * - Byte quartile distribution: invariante
 * ==========================================================================
 */

#include <stdint.h>
#if defined(_MSC_VER)
#include <intrin.h>
#endif

/* Popcount portátil para contar bits activos */
static int popcount_byte(unsigned char b)
{
    int c = 0;
    while (b) { c += (b & 1); b >>= 1; }
    return c;
}

/* DMR AMBE de-interleave tables (verified identical to DSD-FME dmr_const.h) */
static const int rW_cpu[36] = {
    0,1,0,1,0,1, 0,1,0,1,0,1, 0,1,0,1,0,1, 0,1,0,1,0,2, 0,2,0,2,0,2, 0,2,0,2,0,2
};
static const int rX_cpu[36] = {
    23,10,22,9,21,8, 20,7,19,6,18,5, 17,4,16,3,15,2, 14,1,13,0,12,10, 11,9,10,8,9,7, 8,6,7,5,6,4
};
static const int rY_cpu[36] = {
    0,2,0,2,0,2, 0,2,0,3,0,3, 1,3,1,3,1,3, 1,3,1,3,1,3, 1,3,1,3,1,3, 1,3,1,3,1,3
};
static const int rZ_cpu[36] = {
    5,3,4,2,3,1, 2,0,1,13,0,12, 22,11,21,10,20,9, 19,8,18,7,17,6, 16,5,15,4,14,3, 13,2,12,1,11,0
};

/* Sub-frame dibit indices into 132-dibit payload */
static const int sf_dibit_idx_cpu[3][36] = {
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11,
      12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
      24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35 },
    { 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
      48, 49, 50, 51, 52, 53, 78, 79, 80, 81, 82, 83,
      84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95 },
    { 96, 97, 98, 99,100,101,102,103,104,105,106,107,
     108,109,110,111,112,113,114,115,116,117,118,119,
     120,121,122,123,124,125,126,127,128,129,130,131 }
};

static void rc4_discard_cpu(RC4_CTX *ctx, int nbytes)
{
    unsigned char dummy[64];
    unsigned char zeros[64];
    memset(zeros, 0, sizeof(zeros));
    while (nbytes > 0) {
        int step = nbytes > 64 ? 64 : nbytes;
        rc4_crypt(ctx, zeros, dummy, (size_t)step);
        nbytes -= step;
    }
}

static int is_rc4_alg_cpu(uint8_t alg)
{
    return alg == 0x21 || alg == 0x01 || ((alg & 0x07u) == 0x01u);
}

/*
 * Correct scoring pipeline for a single burst (33-byte payload).
 * Uses the proven DSD-FME / mbelib algorithm:
 *   deinterleave -> mbe_demodulate -> extract -> pack -> RC4 -> unpack -> score
 */
static double score_burst_correct_cpu(
    const unsigned char *payload33,
    const unsigned char key5[5],
    uint32_t mi,
    int burst_pos)
{
    unsigned char kmi9[9];
    int sf, i, j, bi;
    unsigned char dec24[3][24];

    kmi9[0] = key5[0]; kmi9[1] = key5[1]; kmi9[2] = key5[2];
    kmi9[3] = key5[3]; kmi9[4] = key5[4];
    kmi9[5] = (unsigned char)((mi >> 24) & 0xFFu);
    kmi9[6] = (unsigned char)((mi >> 16) & 0xFFu);
    kmi9[7] = (unsigned char)((mi >> 8) & 0xFFu);
    kmi9[8] = (unsigned char)(mi & 0xFFu);

    {
        RC4_CTX rc4;
        rc4_init(&rc4, kmi9, 9);
        rc4_discard_cpu(&rc4, 256 + burst_pos * 21);

        for (sf = 0; sf < 3; ++sf) {
            unsigned char ambe_fr[4][24];
            unsigned char bits49[49];
            unsigned char cipher7[7];
            unsigned char plain7[7];

            memset(ambe_fr, 0, sizeof(ambe_fr));

            /* De-interleave */
            for (i = 0; i < 36; ++i) {
                int d = sf_dibit_idx_cpu[sf][i];
                int byte_idx = d >> 2;
                int shift = (3 - (d & 3)) * 2;
                unsigned char dibit = (unsigned char)((payload33[byte_idx] >> shift) & 0x3u);
                ambe_fr[rW_cpu[i]][rX_cpu[i]] = (unsigned char)((dibit >> 1) & 1u);
                ambe_fr[rY_cpu[i]][rZ_cpu[i]] = (unsigned char)(dibit & 1u);
            }

            /* mbe_demodulate */
            {
                int foo = 0;
                int pr_val;
                for (i = 23; i >= 12; --i) foo = (foo << 1) | (int)ambe_fr[0][i];
                pr_val = 16 * foo;
                for (j = 22; j >= 0; --j) {
                    pr_val = (173 * pr_val + 13849) & 0xFFFF;
                    ambe_fr[1][j] ^= (unsigned char)(pr_val >> 15);
                }
            }

            /* Extract 49 bits */
            bi = 0;
            for (j = 23; j >= 12; --j) bits49[bi++] = ambe_fr[0][j];
            for (j = 22; j >= 11; --j) bits49[bi++] = ambe_fr[1][j];
            for (j = 10; j >=  0; --j) bits49[bi++] = ambe_fr[2][j];
            for (j = 13; j >=  0; --j) bits49[bi++] = ambe_fr[3][j];

            /* Pack 49 bits -> 7 bytes */
            memset(cipher7, 0, 7);
            for (i = 0; i < 49; ++i) {
                cipher7[i >> 3] |= (unsigned char)((bits49[i] & 1u) << (7 - (i & 7)));
            }

            /* RC4 decrypt 7 bytes */
            rc4_crypt(&rc4, cipher7, plain7, 7);

            /* Unpack first 24 bits */
            for (i = 0; i < 24; ++i) {
                dec24[sf][i] = (unsigned char)((plain7[i >> 3] >> (7 - (i & 7))) & 1u);
            }
        }
    }

    /* Inter-frame Hamming on first 24 bits (C0+C1) */
    {
        int h01 = 0, h12 = 0;
        for (i = 0; i < 24; ++i) {
            h01 += dec24[0][i] ^ dec24[1][i];
            h12 += dec24[1][i] ^ dec24[2][i];
        }
        return (double)(48 - h01 - h12);
    }
}

static double score_candidate(
    const PayloadSet *payloads,
    int sample_lines,
    int sample_bytes,
    const unsigned char key[5])
{
    size_t line_count;
    size_t line_idx;
    double score = 0.0;
    int mode_policy = 0;

    line_count = payloads->count;
    if (sample_lines > 0 && (size_t)sample_lines < line_count) {
        line_count = (size_t)sample_lines;
    }

    /* Determine mode policy: use correct pipeline if payloads have MI+RC4 */
    {
        int mi_rc4_lines = 0;
        for (line_idx = 0; line_idx < line_count; ++line_idx) {
            const PayloadLine *line = &payloads->items[line_idx];
            uint8_t alg = line->has_algid ? line->algid : payloads->global_algid;
            if (line->has_mi && is_rc4_alg_cpu(alg)) mi_rc4_lines++;
        }
        if (line_count > 0 && mi_rc4_lines * 3 >= (int)line_count) {
            mode_policy = 2;
        }
    }

    /* Correct pipeline path for payloads with MI */
    if (mode_policy >= 2) {
        for (line_idx = 0; line_idx < line_count; ++line_idx) {
            const PayloadLine *line = &payloads->items[line_idx];
            uint32_t mi = line->has_mi ? line->mi : payloads->global_mi;
            int burst_pos = (int)(line_idx % 6);
            if (line->len >= 33) {
                score += score_burst_correct_cpu(line->data, key, mi, burst_pos);
            }
        }
        return score;
    }

    /* Legacy path: plain RC4 without MI */
    {
    RC4_CTX rc4_base;
    rc4_init(&rc4_base, key, 5);

    for (line_idx = 0; line_idx < line_count; ++line_idx) {
        const PayloadLine *line = &payloads->items[line_idx];
        size_t bytes_to_test = line->len;
        __declspec(align(16)) unsigned char out[64];
        RC4_CTX rc4;
        size_t i;
        double local_score = 0.0;

        if (sample_bytes > 0 && (size_t)sample_bytes < bytes_to_test) {
            bytes_to_test = (size_t)sample_bytes;
        }
        if (bytes_to_test == 0) {
            continue;
        }
        if (bytes_to_test > sizeof(out)) {
            bytes_to_test = sizeof(out);
        }

        rc4 = rc4_base;
        rc4_crypt(&rc4, line->data, out, bytes_to_test);

        /* ---------------------------------------------------------------
         * A. AUTOCORRELACIÓN MULTI-LAG
         *
         * Para cada lag l (1..max_lag), computar la distancia hamming
         * entre out[0..n-l-1] y out[l..n-1].
         *
         * Con datos estructurados: ciertos lags muestran baja hamming
         * (estructura periódica del interleaving).
         * Con datos random: hamming ≈ 50% para TODOS los lags.
         *
         * Sumamos la desviación cuadrática del hamming respecto al
         * valor esperado (n_bits/2). Mayor desviación = más estructura.
         * ---------------------------------------------------------------*/
        {
            /* Lags de interés: 1-13 (cubren hasta half-payload) */
            int lag;
            int max_lag = (int)(bytes_to_test / 2);
            if (max_lag > 13) max_lag = 13;
            double autocorr_score = 0.0;

            for (lag = 1; lag <= max_lag; ++lag) {
                int n_bytes = (int)(bytes_to_test) - lag;
                int hamming = 0;
                int expected;
                int deviation;
                int j;

                for (j = 0; j < n_bytes; ++j) {
                    hamming += popcount_byte(out[j] ^ out[j + lag]);
                }
                /* Expected hamming for random: n_bytes * 4 */
                expected = n_bytes * 4;
                deviation = hamming - expected;
                /* Use absolute deviation — both positive and negative
                 * deviations indicate structure */
                if (deviation < 0) deviation = -deviation;
                autocorr_score += (double)deviation;
            }
            /* Scale: weight autocorrelation heavily */
            local_score += autocorr_score * 2.5;
        }

        /* ---------------------------------------------------------------
         * B. TASA DE TRANSICIONES BIT
         *
         * Contar el número de transiciones (0→1 o 1→0) en el stream
         * de bits del payload descifrado.
         *
         * Datos random: ~50% de los pares de bits consecutivos son
         * transiciones (esperado = n_bits - 1) / 2.
         * Datos AMBE: típicamente diferente (campos con runs de bits).
         *
         * Una desviación significativa del 50% indica datos estructurados.
         * ---------------------------------------------------------------*/
        {
            int transitions = 0;
            int total_bit_pairs = (int)(bytes_to_test * 8) - 1;
            int expected_transitions;
            int deviation;

            for (i = 0; i < bytes_to_test; ++i) {
                unsigned char b = out[i];
                /* Transitions within this byte (7 bit pairs) */
                int k;
                for (k = 0; k < 7; ++k) {
                    int bit_k = (b >> (7 - k)) & 1;
                    int bit_k1 = (b >> (6 - k)) & 1;
                    if (bit_k != bit_k1) transitions++;
                }
                /* Transition between last bit of this byte and first of next */
                if (i + 1 < bytes_to_test) {
                    int last_bit = b & 1;
                    int first_bit = (out[i + 1] >> 7) & 1;
                    if (last_bit != first_bit) transitions++;
                }
            }

            expected_transitions = total_bit_pairs / 2;
            deviation = transitions - expected_transitions;
            if (deviation < 0) deviation = -deviation;
            local_score += (double)deviation * 3.0;
        }

        /* ---------------------------------------------------------------
         * C. BIT RATIO (distribución de unos)
         *
         * Datos cifrados con clave errónea producen ~50% bits a 1.
         * Con clave correcta, el plaintext (AMBE interleaved) puede
         * tener un ratio consistentemente > 50% o < 50%.
         *
         * NOTA: bit ratio PER PAYLOAD depende del key porque la mask
         * XOR flipa bits específicos, cambiando el popcount.
         * El efecto es ACUMULATIVO sobre muchos payloads.
         *
         * Usamos desviación cuadrática del 50% para mayor sensibilidad.
         * ---------------------------------------------------------------*/
        {
            int total_bits = 0;
            double bit_ratio, dev;
            for (i = 0; i < bytes_to_test; ++i) {
                total_bits += popcount_byte(out[i]);
            }
            bit_ratio = (double)total_bits / (double)(bytes_to_test * 8);
            dev = bit_ratio - 0.5;
            /* Square the deviation for greater sensitivity, then scale */
            local_score += dev * dev * (double)(bytes_to_test * 8) * 60.0;
        }

        /* ---------------------------------------------------------------
         * D. CONSISTENCIA DE PARES DE BYTES
         *
         * Para datos estructurados, ciertos pares de bytes tienden a
         * tener relaciones específicas. Calculamos la varianza de los
         * valores XOR de pares (i, i+offset) para offsets específicos.
         * Alta varianza en XOR = datos random. Baja varianza = estructura.
         * ---------------------------------------------------------------*/
        if (bytes_to_test >= 10) {
            /* Check a few strategic offsets */
            static const int pair_offsets[] = { 1, 3, 9 };
            int p;
            for (p = 0; p < 3 && pair_offsets[p] < (int)bytes_to_test; ++p) {
                int off = pair_offsets[p];
                int n_pairs = (int)bytes_to_test - off;
                int xor_sum = 0;
                double mean_xor, var_xor;
                int j;

                /* Compute mean of XOR values (as integers 0-255) */
                for (j = 0; j < n_pairs; ++j) {
                    xor_sum += (int)(out[j] ^ out[j + off]);
                }
                mean_xor = (double)xor_sum / (double)n_pairs;

                /* Compute variance */
                var_xor = 0.0;
                for (j = 0; j < n_pairs; ++j) {
                    double d = (double)(out[j] ^ out[j + off]) - mean_xor;
                    var_xor += d * d;
                }
                var_xor /= (double)n_pairs;

                /* Random XOR of two uniform bytes: mean=127.5, var≈5440
                 * Structured data: lower or higher variance */
                {
                    double random_var = 5440.0;
                    double var_dev = var_xor - random_var;
                    if (var_dev < 0) var_dev = -var_dev;
                    local_score += var_dev * 0.008;
                }
            }
        }

        /* ---------------------------------------------------------------
         * E. PENALIZACIÓN POR BASURA PATENTE
         *
         * Si el descifrado produce runs muy largos de bytes iguales
         * o demasiados 0x00/0xFF, es probablemente basura.
         * Esto actúa como safety net para descartar claves claramente
         * malas, no como discriminador primario.
         * ---------------------------------------------------------------*/
        {
            int max_run = 1, run = 1;
            for (i = 1; i < bytes_to_test; ++i) {
                if (out[i] == out[i - 1]) {
                    run++;
                    if (run > max_run) max_run = run;
                } else {
                    run = 1;
                }
            }
            if (max_run > 5) {
                local_score -= (max_run - 5) * 50.0;
            }
        }

        score += local_score;
    }
    } /* end legacy path */

    return score;
}

static unsigned __stdcall worker_proc(void *arg)
{
    WorkerCtx *ctx = (WorkerCtx *)arg;
    BruteforceEngine *engine = ctx->engine;
    uint64_t k;
    uint64_t local_count = 0;
    double local_best_score = -DBL_MAX;

    // Afinidad de hilo: cada worker se fija a un core lógico distinto si es posible
    if (ctx->worker_index < 64) {
        SetThreadIdealProcessor(GetCurrentThread(), (DWORD)ctx->worker_index);
    }

    for (k = ctx->start_key; k <= ctx->end_key; ++k) {
        unsigned char key_bytes[5];
        double score;

        if ((local_count & 0xFFFu) == 0) {
            if (InterlockedCompareExchange(&engine->stop_requested, 0, 0) != 0) {
                break;
            }
            if (InterlockedCompareExchange(&engine->paused, 0, 0) != 0) {
                WaitForSingleObject(engine->pause_event, INFINITE);
                if (InterlockedCompareExchange(&engine->stop_requested, 0, 0) != 0) {
                    break;
                }
            }
        }

        key_to_5bytes(k, key_bytes);
        score = score_candidate(engine->payloads, engine->cfg.sample_lines, engine->cfg.sample_bytes, key_bytes);

        if (score > local_best_score) {
            local_best_score = score;
            EnterCriticalSection(&engine->lock);
            if (score > engine->best_score) {
                engine->best_score = score;
                engine->best_key = k;
            }
            LeaveCriticalSection(&engine->lock);
        }

        local_count++;
        if ((local_count & 0x3FFu) == 0) {
            InterlockedAdd64(&engine->keys_tested, 1024);
        }

        if (k == ctx->end_key) {
            break;
        }
    }

    if ((local_count & 0x3FFu) != 0) {
        InterlockedAdd64(&engine->keys_tested, (LONG64)(local_count & 0x3FFu));
    }

    if (InterlockedIncrement(&engine->finished_threads) == engine->cfg.thread_count) {
        if (InterlockedCompareExchange(&engine->stop_requested, 0, 0) == 0) {
            InterlockedExchange(&engine->search_completed, 1);
        }
        InterlockedExchange(&engine->running, 0);
        SetEvent(engine->pause_event);
    }

    return 0;
}

void bruteforce_engine_init(BruteforceEngine *engine)
{
    ZeroMemory(engine, sizeof(*engine));
    InitializeCriticalSection(&engine->lock);
    QueryPerformanceFrequency(&engine->qpc_freq);
}

void bruteforce_engine_destroy(BruteforceEngine *engine)
{
    bruteforce_stop(engine);
    close_worker_resources(engine);
    DeleteCriticalSection(&engine->lock);
}

int bruteforce_start(
    BruteforceEngine *engine,
    const BruteforceConfig *cfg,
    const PayloadSet *payloads,
    char *err,
    size_t err_len)
{
    int t;
    uintptr_t th;
    uint64_t total;
    uint64_t chunk;
    uint64_t rem;
    uint64_t start;

    if (InterlockedCompareExchange(&engine->running, 0, 0) != 0) {
        set_error(err, err_len, "A search is already running");
        return 0;
    }

    close_worker_resources(engine);

    if (cfg->thread_count <= 0 || cfg->thread_count > 64) {
        set_error(err, err_len, "Invalid thread count (must be 1..64)");
        return 0;
    }
    if (cfg->start_key > cfg->end_key) {
        set_error(err, err_len, "Start key must be <= end key");
        return 0;
    }
    if (cfg->end_key > 0xFFFFFFFFFFull) {
        set_error(err, err_len, "End key exceeds 40 bits");
        return 0;
    }
    if (payloads == NULL || payloads->count == 0) {
        set_error(err, err_len, "No payloads loaded");
        return 0;
    }

    engine->cfg = *cfg;
    if (engine->cfg.sample_bytes <= 0) {
        engine->cfg.sample_bytes = 33;
    }
    if (engine->cfg.sample_lines <= 0 || (size_t)engine->cfg.sample_lines > payloads->count) {
        engine->cfg.sample_lines = (int)payloads->count;
    }
    engine->payloads = payloads;


    engine->thread_handles = (HANDLE *)calloc((size_t)engine->cfg.thread_count, sizeof(HANDLE));
    engine->workers = calloc((size_t)engine->cfg.thread_count, sizeof(WorkerCtx));
    if (engine->thread_handles == NULL || engine->workers == NULL) {
        close_worker_resources(engine);
        set_error(err, err_len, "Out of memory allocating worker threads");
        return 0;
    }
    WorkerCtx *workers = (WorkerCtx *)engine->workers;

    engine->pause_event = CreateEventA(NULL, TRUE, TRUE, NULL);
    if (engine->pause_event == NULL) {
        close_worker_resources(engine);
        set_error(err, err_len, "Could not create pause event");
        return 0;
    }

    total = (engine->cfg.end_key - engine->cfg.start_key) + 1ull;
    if ((uint64_t)engine->cfg.thread_count > total) {
        engine->cfg.thread_count = (int)total;
    }
    chunk = total / (uint64_t)engine->cfg.thread_count;
    rem = total % (uint64_t)engine->cfg.thread_count;
    start = engine->cfg.start_key;

    InterlockedExchange64(&engine->keys_tested, 0);
    InterlockedExchange(&engine->stop_requested, 0);
    InterlockedExchange(&engine->paused, 0);
    InterlockedExchange(&engine->finished_threads, 0);
    InterlockedExchange(&engine->search_completed, 0);
    engine->best_key = engine->cfg.start_key;
    engine->best_score = -DBL_MAX;
    QueryPerformanceCounter(&engine->qpc_start);
    InterlockedExchange(&engine->running, 1);

    for (t = 0; t < engine->cfg.thread_count; ++t) {
        uint64_t this_count = chunk + ((uint64_t)t < rem ? 1ull : 0ull);
        uint64_t end = start + this_count - 1ull;

        workers[t].engine = engine;
        workers[t].start_key = start;
        workers[t].end_key = end;
        workers[t].worker_index = t;

        th = _beginthreadex(NULL, 0, worker_proc, &workers[t], 0, NULL);
        if (th == 0) {
            InterlockedExchange(&engine->running, 0);
            InterlockedExchange(&engine->stop_requested, 1);
            SetEvent(engine->pause_event);
            bruteforce_stop(engine);
            set_error(err, err_len, "Error creating brute-force threads");
            return 0;
        }

        engine->thread_handles[t] = (HANDLE)th;
        start = end + 1ull;
    }

    return 1;
}

void bruteforce_pause(BruteforceEngine *engine)
{
    if (InterlockedCompareExchange(&engine->running, 0, 0) == 0) {
        return;
    }
    InterlockedExchange(&engine->paused, 1);
    ResetEvent(engine->pause_event);
}

void bruteforce_resume(BruteforceEngine *engine)
{
    if (InterlockedCompareExchange(&engine->running, 0, 0) == 0) {
        return;
    }
    InterlockedExchange(&engine->paused, 0);
    SetEvent(engine->pause_event);
}

void bruteforce_stop(BruteforceEngine *engine)
{
    if (engine->thread_handles == NULL) {
        InterlockedExchange(&engine->running, 0);
        return;
    }

    InterlockedExchange(&engine->stop_requested, 1);
    InterlockedExchange(&engine->paused, 0);
    SetEvent(engine->pause_event);

    WaitForMultipleObjects((DWORD)engine->cfg.thread_count, engine->thread_handles, TRUE, INFINITE);
    InterlockedExchange(&engine->running, 0);
    close_worker_resources(engine);
}

void bruteforce_get_snapshot(BruteforceEngine *engine, BruteforceSnapshot *out)
{
    LARGE_INTEGER now;
    double elapsed;
    uint64_t keys;
    uint64_t total;

    keys = read_u64(&engine->keys_tested);
    total = 0;
    if (engine->cfg.end_key >= engine->cfg.start_key) {
        total = (engine->cfg.end_key - engine->cfg.start_key) + 1ull;
    }

    QueryPerformanceCounter(&now);
    elapsed = (double)(now.QuadPart - engine->qpc_start.QuadPart) / (double)engine->qpc_freq.QuadPart;
    if (elapsed < 0.0) {
        elapsed = 0.0;
    }

    out->keys_tested = keys;
    out->total_keys = total;
    EnterCriticalSection(&engine->lock);
    out->best_key = engine->best_key;
    out->best_score = engine->best_score;
    LeaveCriticalSection(&engine->lock);
    out->elapsed_seconds = elapsed;
    out->running = InterlockedCompareExchange(&engine->running, 0, 0);
    out->paused = InterlockedCompareExchange(&engine->paused, 0, 0);
    out->finished = InterlockedCompareExchange(&engine->search_completed, 0, 0);

    if (elapsed > 0.0) {
        out->keys_per_second = (double)keys / elapsed;
    } else {
        out->keys_per_second = 0.0;
    }

    if (out->keys_per_second > 0.0 && total > keys) {
        out->eta_seconds = (double)(total - keys) / out->keys_per_second;
    } else {
        out->eta_seconds = -1.0;
    }
}

double bruteforce_test_score(
    const PayloadSet *payloads,
    int sample_lines,
    int sample_bytes,
    const unsigned char key[5])
{
    return score_candidate(payloads, sample_lines, sample_bytes, key);
}
