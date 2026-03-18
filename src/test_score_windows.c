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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>

#include "../include/payload_io.h"
#include "../include/bruteforce.h"

static void copy_window(const PayloadSet *src, PayloadSet *dst, int start, int count)
{
    int i;
    payload_set_init(dst);
    dst->items = (PayloadLine *)calloc((size_t)count, sizeof(PayloadLine));
    if (!dst->items) return;
    dst->capacity = (size_t)count;
    dst->has_global_mi = src->has_global_mi;
    dst->has_global_algid = src->has_global_algid;
    dst->has_global_keyid = src->has_global_keyid;
    dst->global_mi = src->global_mi;
    dst->global_algid = src->global_algid;
    dst->global_keyid = src->global_keyid;
    for (i = 0; i < count; ++i) {
        const PayloadLine *pl = &src->items[start + i];
        uint8_t *buf = (uint8_t *)malloc(pl->len);
        if (!buf) break;
        memcpy(buf, pl->data, pl->len);
        dst->items[dst->count].data = buf;
        dst->items[dst->count].len = pl->len;
        dst->items[dst->count].has_mi = pl->has_mi;
        dst->items[dst->count].has_algid = pl->has_algid;
        dst->items[dst->count].has_keyid = pl->has_keyid;
        dst->items[dst->count].mi = pl->mi;
        dst->items[dst->count].algid = pl->algid;
        dst->items[dst->count].keyid = pl->keyid;
        dst->count++;
    }
}

int main(int argc, char *argv[])
{
    PayloadSet all;
    char err[512] = {0};
    const char *bin_path;
    unsigned char key[5] = {0x00,0xAA,0x00,0xBB,0x00};
    int win = 32;
    int step = 16;
    int n_random = 600;
    int sample_bytes = 0;
    int start;

    if (argc < 2) {
        fprintf(stderr, "Uso: test_score_windows <archivo.bin> [key_hex] [window] [step] [n_random] [sample_bytes]\n");
        return 1;
    }
    bin_path = argv[1];

    if (argc >= 3 && strlen(argv[2]) == 10) {
        int i;
        for (i = 0; i < 5; ++i) {
            unsigned int b;
            sscanf(argv[2] + i*2, "%02x", &b);
            key[i] = (unsigned char)b;
        }
    }
    if (argc >= 4) win = atoi(argv[3]);
    if (argc >= 5) step = atoi(argv[4]);
    if (argc >= 6) n_random = atoi(argv[5]);
    if (argc >= 7) sample_bytes = atoi(argv[6]);
    if (win < 10) win = 10;
    if (step < 1) step = 1;
    if (n_random < 100) n_random = 100;

    payload_set_init(&all);
    if (!load_payload_file(bin_path, 0, &all, err, sizeof(err))) {
        fprintf(stderr, "ERROR: %s\n", err);
        return 1;
    }

    if (sample_bytes <= 0) {
        size_t max_len = 0;
        for (size_t i = 0; i < all.count; ++i) {
            if (all.items[i].len > max_len) max_len = all.items[i].len;
        }
        sample_bytes = (max_len >= 33) ? 33 : 27;
    }

    printf("BIN=%s payloads=%zu key=%02X%02X%02X%02X%02X win=%d step=%d random=%d sample_bytes=%d\n\n",
        bin_path, all.count, key[0],key[1],key[2],key[3],key[4], win, step, n_random, sample_bytes);

    srand((unsigned)time(NULL));

    for (start = 0; start + win <= (int)all.count; start += step) {
        PayloadSet w;
        double s_key;
        double sum = 0.0, sum_sq = 0.0;
        double mean, stddev, z;
        int r;

        copy_window(&all, &w, start, win);
        if (w.count == 0) continue;

        s_key = bruteforce_test_score(&w, 0, sample_bytes, key);

        for (r = 0; r < n_random; ++r) {
            unsigned char rk[5];
            double s;
            rk[0] = (unsigned char)(rand() & 0xFF);
            rk[1] = (unsigned char)(rand() & 0xFF);
            rk[2] = (unsigned char)(rand() & 0xFF);
            rk[3] = (unsigned char)(rand() & 0xFF);
            rk[4] = (unsigned char)(rand() & 0xFF);
            s = bruteforce_test_score(&w, 0, sample_bytes, rk);
            sum += s;
            sum_sq += s * s;
        }

        mean = sum / n_random;
        stddev = sqrt(sum_sq / n_random - mean * mean);
        z = (stddev > 0.0) ? ((s_key - mean) / stddev) : 0.0;

        printf("win[%3d..%3d] key=%.1f mean=%.1f std=%.1f z=%6.2f\n",
            start, start + win - 1, s_key, mean, stddev, z);

        payload_set_free(&w);
    }

    payload_set_free(&all);
    return 0;
}
