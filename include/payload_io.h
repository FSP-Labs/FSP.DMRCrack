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

#ifndef PAYLOAD_IO_H
#define PAYLOAD_IO_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint8_t *data;
    size_t len;
    uint8_t has_mi;
    uint8_t has_algid;
    uint8_t has_keyid;
    uint8_t silence_candidate; /* 1 = first voice burst of a new TX; voicing bit expected = 0 */
    uint8_t algid;
    uint8_t keyid;
    uint32_t mi;
} PayloadLine;

typedef struct {
    PayloadLine *items;
    size_t count;
    size_t capacity;
    uint8_t has_global_mi;
    uint8_t has_global_algid;
    uint8_t has_global_keyid;
    uint8_t global_algid;
    uint8_t global_keyid;
    uint32_t global_mi;
    /* KPA silence frame index cache (built by load_payload_file) */
    uint16_t silence_indices[64];
    uint8_t  n_silence;          /* count, capped at 64 */
} PayloadSet;

#ifdef __cplusplus
extern "C" {
#endif

void payload_set_init(PayloadSet *set);
void payload_set_free(PayloadSet *set);

int load_payload_file(const char *file_path, size_t max_lines, PayloadSet *out_set, char *err, size_t err_len);
int payload_save_file(const char *path, const PayloadSet *payloads, char *err, size_t err_len);

/*
 * dsp_convert_to_bin - convert a DSD-FME -Q DSP output file into a .bin
 * payload file understood by FSP.DMRCrack.
 *
 * dsp_path : path to the DSP structured output file produced by dsd-fme -Q
 * out_path : path for the output .bin file
 * log_path : path to the dsd-fme stderr log (for ALG/KID/MI tags); may be NULL
 * err / err_len : optional error message buffer
 *
 * Returns 1 on success (>= 1 voice burst written), 0 on error.
 * Replaces the Python script tools/dsdfme_dsp_to_bin.py - no Python needed.
 */
int dsp_convert_to_bin(const char *dsp_path, const char *out_path,
                       const char *log_path, char *err, size_t err_len);

void validate_payload_set(const PayloadSet *ps,
                          char *summary, size_t summary_len,
                          char *warn,    size_t warn_len);

/* Algorithm classification for a loaded capture, so the user learns up front
 * whether it is crackable instead of after a long search. */
typedef enum {
    PAYLOAD_CLASS_MOTOTRBO_RC4 = 0, /* RC4 EP + MI: crackable (strict pipeline)   */
    PAYLOAD_CLASS_HYTERA_EP,        /* Hytera EP + MI: crackable                  */
    PAYLOAD_CLASS_RC4_NO_MI,        /* RC4 algid but no MI: weak fallback only    */
    PAYLOAD_CLASS_UNSUPPORTED,      /* non-RC4 cipher (likely AES): NOT crackable */
    PAYLOAD_CLASS_NONE              /* no encryption metadata                     */
} PayloadClass;

/* Classify a loaded set and write a one-line human verdict into msg.
 * crackable (out, optional): 1 if the recommended pipeline can recover a key. */
PayloadClass payload_classify(const PayloadSet *ps, int *crackable,
                              char *msg, size_t msg_len);

#ifdef __cplusplus
}
#endif

#endif
