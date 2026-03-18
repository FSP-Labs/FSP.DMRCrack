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

#include "../include/payload_io.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void set_error(char *err, size_t err_len, const char *msg)
{
    if (err != NULL && err_len > 0) {
        strncpy(err, msg, err_len - 1);
        err[err_len - 1] = '\0';
    }
}

static int hex_value(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    return -1;
}

static const char *find_tag_ci(const char *s, const char *tag)
{
    size_t i, tlen;
    if (s == NULL || tag == NULL) return NULL;
    tlen = strlen(tag);
    if (tlen == 0) return NULL;
    for (i = 0; s[i] != '\0'; ++i) {
        size_t k = 0;
        while (k < tlen && s[i + k] != '\0') {
            char a = s[i + k];
            char b = tag[k];
            if (a >= 'a' && a <= 'z') a = (char)(a - 'a' + 'A');
            if (b >= 'a' && b <= 'z') b = (char)(b - 'a' + 'A');
            if (a != b) break;
            ++k;
        }
        if (k == tlen) return s + i;
    }
    return NULL;
}

static int parse_hex_token_u32(const char *p, int max_digits, uint32_t *out_val, int *out_digits)
{
    int digits = 0;
    uint32_t v = 0;
    while (*p != '\0' && digits < max_digits) {
        int hv = hex_value(*p);
        if (hv < 0) break;
        v = (v << 4) | (uint32_t)hv;
        ++digits;
        ++p;
    }
    if (digits <= 0) return 0;
    *out_val = v;
    if (out_digits) *out_digits = digits;
    return 1;
}

void payload_set_init(PayloadSet *set)
{
    if (set == NULL) {
        return;
    }
    set->items = NULL;
    set->count = 0;
    set->capacity = 0;
    set->has_global_mi = 0;
    set->has_global_algid = 0;
    set->has_global_keyid = 0;
    set->global_algid = 0;
    set->global_keyid = 0;
    set->global_mi = 0;
}

void payload_set_free(PayloadSet *set)
{
    size_t i;

    if (set == NULL) {
        return;
    }

    for (i = 0; i < set->count; ++i) {
        free(set->items[i].data);
    }

    free(set->items);
    set->items = NULL;
    set->count = 0;
    set->capacity = 0;
    set->has_global_mi = 0;
    set->has_global_algid = 0;
    set->has_global_keyid = 0;
    set->global_algid = 0;
    set->global_keyid = 0;
    set->global_mi = 0;
}

static int payload_set_push(PayloadSet *set, uint8_t *data, size_t len)
{
    PayloadLine *new_items;

    if (set->count == set->capacity) {
        size_t new_capacity = (set->capacity == 0) ? 64 : set->capacity * 2;
        new_items = (PayloadLine *)realloc(set->items, new_capacity * sizeof(PayloadLine));
        if (new_items == NULL) {
            return 0;
        }
        set->items = new_items;
        set->capacity = new_capacity;
    }

    set->items[set->count].data = data;
    set->items[set->count].len = len;
    set->items[set->count].has_mi = 0;
    set->items[set->count].has_algid = 0;
    set->items[set->count].has_keyid = 0;
    set->items[set->count].algid = 0;
    set->items[set->count].keyid = 0;
    set->items[set->count].mi = 0;
    set->count++;
    return 1;
}

static void parse_line_metadata(
    const char *line,
    int *has_mi, uint32_t *mi,
    int *has_alg, uint8_t *alg,
    int *has_kid, uint8_t *kid)
{
    const char *p;
    uint32_t v;
    int digits;

    *has_mi = 0;
    *has_alg = 0;
    *has_kid = 0;

    p = find_tag_ci(line, "MI=");
    if (p != NULL && parse_hex_token_u32(p + 3, 8, &v, &digits)) {
        if (digits <= 8) {
            *has_mi = 1;
            *mi = v;
        }
    }

    p = find_tag_ci(line, "ALG=");
    if (p != NULL && parse_hex_token_u32(p + 4, 2, &v, &digits)) {
        if (digits <= 2) {
            *has_alg = 1;
            *alg = (uint8_t)v;
        }
    }

    p = find_tag_ci(line, "KID=");
    if (p != NULL && parse_hex_token_u32(p + 4, 2, &v, &digits)) {
        if (digits <= 2) {
            *has_kid = 1;
            *kid = (uint8_t)v;
        }
    }
}

static void extract_payload_hex_part(const char *line, char *out_hex, size_t out_sz)
{
    size_t i = 0;
    size_t o = 0;

    while (line[i] != '\0' && o + 1 < out_sz) {
        if (line[i] == ';' || line[i] == '#') break;
        out_hex[o++] = line[i++];
    }
    out_hex[o] = '\0';
}

static int parse_hex_line(const char *line, uint8_t **out_data, size_t *out_len, char *err, size_t err_len)
{
    size_t cap = 64;
    size_t len = 0;
    uint8_t *buf = NULL;
    int have_high = 0;
    int high_nibble = 0;
    size_t i;

    buf = (uint8_t *)malloc(cap);
    if (buf == NULL) {
        set_error(err, err_len, "Out of memory parsing line");
        return 0;
    }

    for (i = 0; line[i] != '\0'; ++i) {
        int hv;
        unsigned char ch = (unsigned char)line[i];

        if (ch == '\r' || ch == '\n') {
            break;
        }

        if (isspace(ch) || ch == ',' || ch == ';') {
            continue;
        }

        hv = hex_value((char)ch);
        if (hv < 0) {
            free(buf);
            set_error(err, err_len, "Non-hex character found in payload line");
            return 0;
        }

        if (!have_high) {
            high_nibble = hv;
            have_high = 1;
        } else {
            uint8_t value = (uint8_t)((high_nibble << 4) | hv);
            have_high = 0;

            if (len == cap) {
                size_t new_cap = cap * 2;
                uint8_t *tmp = (uint8_t *)realloc(buf, new_cap);
                if (tmp == NULL) {
                    free(buf);
                    set_error(err, err_len, "Out of memory expanding line buffer");
                    return 0;
                }
                buf = tmp;
                cap = new_cap;
            }

            buf[len++] = value;
        }
    }

    if (have_high) {
        free(buf);
        set_error(err, err_len, "Odd number of hex nibbles in line");
        return 0;
    }

    if (len == 0) {
        free(buf);
        *out_data = NULL;
        *out_len = 0;
        return 1;
    }

    *out_data = buf;
    *out_len = len;
    return 1;
}

int load_payload_file(const char *file_path, size_t max_lines, PayloadSet *out_set, char *err, size_t err_len)
{
    FILE *f;
    char line[8192];
    char hex_part[8192];
    PayloadSet tmp;

    payload_set_init(&tmp);

    f = fopen(file_path, "rb");
    if (f == NULL) {
        set_error(err, err_len, "Could not open .bin file");
        return 0;
    }

    while (fgets(line, (int)sizeof(line), f) != NULL) {
        uint8_t *data = NULL;
        size_t data_len = 0;
        int has_mi = 0, has_alg = 0, has_kid = 0;
        uint32_t mi = 0;
        uint8_t alg = 0, kid = 0;

        parse_line_metadata(line, &has_mi, &mi, &has_alg, &alg, &has_kid, &kid);
        extract_payload_hex_part(line, hex_part, sizeof(hex_part));

        if (!parse_hex_line(hex_part, &data, &data_len, err, err_len)) {
            payload_set_free(&tmp);
            fclose(f);
            return 0;
        }

        if (data_len == 0) {
            continue;
        }

        if (!payload_set_push(&tmp, data, data_len)) {
            free(data);
            payload_set_free(&tmp);
            fclose(f);
            set_error(err, err_len, "Out of memory storing payloads");
            return 0;
        }

        if (tmp.count > 0) {
            PayloadLine *pl = &tmp.items[tmp.count - 1];
            if (has_mi) {
                pl->has_mi = 1;
                pl->mi = mi;
                tmp.has_global_mi = 1;
                tmp.global_mi = mi;
            }
            if (has_alg) {
                pl->has_algid = 1;
                pl->algid = alg;
                tmp.has_global_algid = 1;
                tmp.global_algid = alg;
            }
            if (has_kid) {
                pl->has_keyid = 1;
                pl->keyid = kid;
                tmp.has_global_keyid = 1;
                tmp.global_keyid = kid;
            }
        }

        if (max_lines > 0 && tmp.count >= max_lines) {
            break;
        }
    }

    fclose(f);

    if (tmp.count == 0) {
        payload_set_free(&tmp);
        set_error(err, err_len, "No valid payloads found in file");
        return 0;
    }

    payload_set_free(out_set);
    *out_set = tmp;
    return 1;
}

/* =========================================================================
 * DSP → BIN converter (native C replacement for dsdfme_dsp_to_bin.py)
 * ========================================================================= */

#define MAX_PI_PER_SLOT 8192

typedef struct { uint32_t mi; uint8_t alg; uint8_t kid; } PiEntry;
typedef struct { PiEntry *e; int n; int cap; } PiList;

static uint32_t lfsr_advance(uint32_t mi, int steps)
{
    int i;
    for (i = 0; i < steps; i++) {
        uint32_t bit = ((mi >> 31) ^ (mi >> 3) ^ (mi >> 1)) & 1u;
        mi = (mi << 1) | bit;
    }
    return mi;
}

/* Parse one log line for a PI header.
 * Expected pattern (case-insensitive substrings):
 *   "Slot N ... ALG ID: XX ... KEY ID: XX ... MI(32): XXXXXXXX"
 * Returns 1 if all four fields found, 0 otherwise.
 */
static int parse_pi_line(const char *line, int *slot_out,
                          uint8_t *alg_out, uint8_t *kid_out, uint32_t *mi_out)
{
    const char *p;
    unsigned int v;

    p = strstr(line, "Slot ");
    if (!p) return 0;
    p += 5;
    while (*p == ' ') p++;
    if (*p != '1' && *p != '2') return 0;
    *slot_out = *p - '0';

    p = strstr(line, "ALG ID:");
    if (!p) return 0;
    p += 7;
    while (*p == ' ') p++;
    if (sscanf(p, "%x", &v) != 1) return 0;
    *alg_out = (uint8_t)v;

    p = strstr(line, "KEY ID:");
    if (!p) return 0;
    p += 7;
    while (*p == ' ') p++;
    if (sscanf(p, "%x", &v) != 1) return 0;
    *kid_out = (uint8_t)v;

    p = strstr(line, "MI(32):");
    if (!p) return 0;
    p += 7;
    while (*p == ' ') p++;
    if (sscanf(p, "%x", &v) != 1) return 0;
    *mi_out = (uint32_t)v;

    return 1;
}

static void pi_list_push(PiList *pl, uint32_t mi, uint8_t alg, uint8_t kid)
{
    if (pl->n == pl->cap) {
        int new_cap = pl->cap ? pl->cap * 2 : 64;
        PiEntry *tmp = (PiEntry *)realloc(pl->e, (size_t)new_cap * sizeof(PiEntry));
        if (!tmp) return;
        pl->e = tmp;
        pl->cap = new_cap;
    }
    pl->e[pl->n].mi  = mi;
    pl->e[pl->n].alg = alg;
    pl->e[pl->n].kid = kid;
    pl->n++;
}

static void load_pi_lists(const char *log_path, PiList pi[2])
{
    FILE *f;
    char line[2048];

    pi[0].e = pi[1].e = NULL;
    pi[0].n = pi[1].n = pi[0].cap = pi[1].cap = 0;

    if (!log_path || !*log_path) return;
    f = fopen(log_path, "r");
    if (!f) return;

    while (fgets(line, sizeof(line), f)) {
        int slot;
        uint8_t alg, kid;
        uint32_t mi;
        if (!parse_pi_line(line, &slot, &alg, &kid, &mi)) continue;
        if (slot < 1 || slot > 2) continue;
        if (pi[slot-1].n < MAX_PI_PER_SLOT)
            pi_list_push(&pi[slot-1], mi, alg, kid);
    }
    fclose(f);
}

int dsp_convert_to_bin(const char *dsp_path, const char *out_path,
                       const char *log_path, char *err, size_t err_len)
{
    FILE *fin, *fout;
    char line[16384];
    char hex[16384];
    PiList pi[2];
    int burst_count[2] = {0, 0};
    int voice_count = 0;

    load_pi_lists(log_path, pi);

    fin = fopen(dsp_path, "r");
    if (!fin) {
        free(pi[0].e); free(pi[1].e);
        set_error(err, err_len, "Could not open DSP file");
        return 0;
    }

    fout = fopen(out_path, "w");
    if (!fout) {
        fclose(fin);
        free(pi[0].e); free(pi[1].e);
        set_error(err, err_len, "Could not create output .bin file");
        return 0;
    }

    while (fgets(line, sizeof(line), fin)) {
        int slot, si, sf_idx;
        unsigned int burst_type;
        size_t hexlen, k;
        uint32_t mi = 0;
        uint8_t alg = 0, kid = 0;
        int has_meta = 0;

        /* DSP line: "<slot> <type_hex> <payload_hex>" */
        if (sscanf(line, "%d %x %16383s", &slot, &burst_type, hex) != 3) continue;
        if (slot < 1 || slot > 2) continue;
        if (burst_type != 0x10) continue;   /* 0x10 = voice burst */

        hexlen = strlen(hex);
        if (hexlen < 66) continue;
        hex[66] = '\0';
        for (k = 0; k < 66; k++)
            if (hex[k] >= 'a' && hex[k] <= 'f') hex[k] = (char)(hex[k] - 'a' + 'A');

        si = slot - 1;
        if (pi[si].n > 0) {
            sf_idx = burst_count[si] / 6;
            if (sf_idx < pi[si].n) {
                mi  = pi[si].e[sf_idx].mi;
                alg = pi[si].e[sf_idx].alg;
                kid = pi[si].e[sf_idx].kid;
            } else {
                int extra = sf_idx - (pi[si].n - 1);
                mi  = lfsr_advance(pi[si].e[pi[si].n - 1].mi, 32 * extra);
                alg = pi[si].e[pi[si].n - 1].alg;
                kid = pi[si].e[pi[si].n - 1].kid;
            }
            has_meta = 1;
        }

        if (has_meta)
            fprintf(fout, "%s;ALG=%02X;KID=%02X;MI=%08X\n", hex, alg, kid, mi);
        else
            fprintf(fout, "%s\n", hex);

        burst_count[si]++;
        voice_count++;
    }

    fclose(fin);
    fclose(fout);
    free(pi[0].e);
    free(pi[1].e);

    if (voice_count == 0) {
        set_error(err, err_len, "No voice bursts found in DSP file");
        return 0;
    }
    return 1;
}

/* ========================================================================= */

int payload_save_file(const char *path, const PayloadSet *payloads, char *err, size_t err_len)
{
    FILE *f;
    size_t i, j;

    if (payloads == NULL || payloads->count == 0) {
        set_error(err, err_len, "No payloads to export");
        return 0;
    }

    f = fopen(path, "w");
    if (f == NULL) {
        set_error(err, err_len, "Could not create output .bin file");
        return 0;
    }

    for (i = 0; i < payloads->count; ++i) {
        const PayloadLine *line = &payloads->items[i];
        for (j = 0; j < line->len; ++j)
            fprintf(f, "%02X", line->data[j]);
        if (line->has_algid) fprintf(f, ";ALG=%02X", line->algid);
        if (line->has_keyid) fprintf(f, ";KID=%02X", line->keyid);
        if (line->has_mi)    fprintf(f, ";MI=%08X", line->mi);
        fprintf(f, "\n");
    }

    fclose(f);
    return 1;
}
