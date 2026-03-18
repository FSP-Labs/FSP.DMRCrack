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
} PayloadSet;

#ifdef __cplusplus
extern "C" {
#endif

void payload_set_init(PayloadSet *set);
void payload_set_free(PayloadSet *set);

int load_payload_file(const char *file_path, size_t max_lines, PayloadSet *out_set, char *err, size_t err_len);
int payload_save_file(const char *path, const PayloadSet *payloads, char *err, size_t err_len);

#ifdef __cplusplus
}
#endif

#endif
