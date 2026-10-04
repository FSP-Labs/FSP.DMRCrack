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

/* 64-bit variant for the MI tag (Hytera EP uses a 40-bit / 10-hex MI). */
static int parse_hex_token_u64(const char *p, int max_digits, uint64_t *out_val, int *out_digits)
{
    int digits = 0;
    uint64_t v = 0;
    while (*p != '\0' && digits < max_digits) {
        int hv = hex_value(*p);
        if (hv < 0) break;
        v = (v << 4) | (uint64_t)hv;
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
    set->n_silence = 0;
    memset(set->silence_indices, 0, sizeof(set->silence_indices));
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
    set->n_silence = 0;
    memset(set->silence_indices, 0, sizeof(set->silence_indices));
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
    set->items[set->count].silence_candidate = 0;
    set->count++;
    return 1;
}

static void parse_line_metadata(
    const char *line,
    int *has_mi, uint64_t *mi,
    int *has_alg, uint8_t *alg,
    int *has_kid, uint8_t *kid,
    int *out_silence)
{
    const char *p;
    uint32_t v;
    int digits;

    *has_mi = 0;
    *has_alg = 0;
    *has_kid = 0;
    *out_silence = 0;

    /* MI may be up to 40 bits (10 hex) for Hytera EP, or 32 bits (8 hex) for MOTOTRBO. */
    p = find_tag_ci(line, "MI=");
    if (p != NULL) {
        uint64_t miv;
        int midigits;
        if (parse_hex_token_u64(p + 3, 10, &miv, &midigits) && midigits <= 10) {
            *has_mi = 1;
            *mi = miv;
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

    /* SILENCE tag */
    p = find_tag_ci(line, "SILENCE=");
    if (p != NULL) {
        uint32_t sv = 0; int sd = 0;
        if (parse_hex_token_u32(p + 8, 1, &sv, &sd))
            *out_silence = (sv != 0) ? 1 : 0;
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
        int has_mi = 0, has_alg = 0, has_kid = 0, silence_cand = 0;
        uint64_t mi = 0;
        uint8_t alg = 0, kid = 0;

        parse_line_metadata(line, &has_mi, &mi, &has_alg, &alg, &has_kid, &kid, &silence_cand);
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
            pl->silence_candidate = (uint8_t)silence_cand;
        }

        if (max_lines > 0 && tmp.count >= max_lines) {
            break;
        }
    }

    fclose(f);

    /* Build the KPA silence-frame cache. The KPA pre-filter HARD-rejects any key
     * for which a cached "silence" frame does not decrypt to C0=C1=0, so a frame
     * wrongly tagged SILENCE prunes the *correct* key. Some DSP layouts emit a
     * type-0x98 marker before every voice burst, which makes the converter's
     * "first burst after a header" heuristic tag (nearly) every line -- that is
     * not real silence. Guard against it: if an implausible fraction of frames is
     * tagged, the tagging is untrustworthy, so build NO cache (KPA off) and fall
     * back to full scoring (slower but correct) instead of pruning the real key. */
    {
        size_t silence_cand = 0;
        for (size_t i = 0; i < tmp.count; i++)
            if (tmp.items[i].silence_candidate && tmp.items[i].has_mi) silence_cand++;

        tmp.n_silence = 0;
        /* Real captures are overwhelmingly speech; >50% "silence" means the
         * converter over-tagged (see DSP type-0x98 case above). */
        if (silence_cand * 2 <= tmp.count) {
            for (size_t i = 0; i < tmp.count && tmp.n_silence < 64; i++) {
                if (tmp.items[i].silence_candidate && tmp.items[i].has_mi) {
                    tmp.silence_indices[tmp.n_silence++] = (uint16_t)i;
                }
            }
        }
    }

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
 * DSP -> BIN converter (native C replacement for dsdfme_dsp_to_bin.py)
 * ========================================================================= */

#define MAX_PI_PER_SLOT 8192

typedef struct { uint64_t mi; uint8_t alg; uint8_t kid; int sf; } PiEntry;
typedef struct { PiEntry *e; int n; int cap; int first_sf; } PiList;

static uint32_t lfsr_advance(uint32_t mi, int steps)
{
    int i;
    for (i = 0; i < steps; i++) {
        uint32_t bit = ((mi >> 31) ^ (mi >> 3) ^ (mi >> 1)) & 1u;
        mi = (mi << 1) | bit;
    }
    return mi;
}

/* Exact inverse of lfsr_advance: step the MOTOTRBO MI LFSR backward. Used to
 * recover the MI of voice bursts decoded BEFORE the first PI header (DSD-FME
 * often locks onto voice several superframes before it decodes a clean PI).
 * Derivation: forward is cur = (prev<<1)|bit with bit = XOR(prev bits 31,3,1);
 * prev's dropped high bit is b31 = (cur&1) ^ (cur>>4 &1) ^ (cur>>2 &1). */
static uint32_t lfsr_reverse(uint32_t mi, int steps)
{
    int i;
    for (i = 0; i < steps; i++) {
        uint32_t b31 = ((mi & 1u) ^ ((mi >> 4) & 1u) ^ ((mi >> 2) & 1u)) & 1u;
        mi = ((mi >> 1) & 0x7FFFFFFFu) | (b31 << 31);
    }
    return mi;
}

/* Advance a 40-bit Hytera EP MI by one superframe. Unlike MOTOTRBO's single
 * 32-bit LFSR, Hytera runs FIVE independent 8-bit Galois LFSRs -- one per MI
 * byte, each with its own tap -- stepped once per superframe. Verbatim from
 * DSD-FME (audio_work) dmr_pi.c hytera_lfsr(), taps {0x12,0x24,0x48,0x22,0x14},
 * called once per superframe (at VC6, algid 0x02). Lets a converter extrapolate
 * the MI across a whole capture from a single CRC-valid Hytera PI header. */
static uint64_t hytera_mi_lfsr_step(uint64_t v)
{
    static const uint8_t taps[5] = {0x12, 0x24, 0x48, 0x22, 0x14};
    uint8_t mi[5];
    uint64_t o = 0;
    int i;
    mi[0] = (uint8_t)(v >> 32); mi[1] = (uint8_t)(v >> 24);
    mi[2] = (uint8_t)(v >> 16); mi[3] = (uint8_t)(v >> 8); mi[4] = (uint8_t)v;
    for (i = 0; i < 5; i++) {
        uint8_t bit = (uint8_t)((mi[i] >> 7) & 1u);
        mi[i] = (uint8_t)(mi[i] << 1);
        if (bit) mi[i] ^= taps[i];
        mi[i] |= bit;
    }
    for (i = 0; i < 5; i++) o = (o << 8) | mi[i];
    return o;
}

/* Format the MI tag value: 8 hex for a 32-bit MOTOTRBO MI (keeps legacy output
 * byte-identical), 10 hex for a 40-bit Hytera EP MI. */
static void format_mi_tag(char *buf, size_t n, uint64_t mi)
{
    if (mi > 0xFFFFFFFFULL)
        snprintf(buf, n, "%010llX", (unsigned long long)mi);
    else
        snprintf(buf, n, "%08llX", (unsigned long long)mi);
}

/* Parse one log line for a PI header. DSD-FME uses a common "DMR PI H-" prefix
 * for both ciphers; they are distinguished by the MI field width, NOT the prefix:
 *   MOTOTRBO/DMRA RC4: "Slot N DMR PI H- ALG ID: 21; KEY ID: 01; MI(32): XXXXXXXX; DMRA RC4;"
 *   Hytera Enhanced:   "Slot N DMR PI H- ALG ID: 02; KEY ID: XX; MI(40): XXXXXXXXXX; Hytera Enhanced;"
 * The "Slot N" is parsed inline when present; *slot_known is set to 0 only when
 * it is absent, so the caller can supply the slot from the surrounding sync.
 * Returns 1 if a PI header was parsed, 0 otherwise.
 */
static int parse_pi_line(const char *line, int *slot_out, int *slot_known,
                          uint8_t *alg_out, uint8_t *kid_out, uint64_t *mi_out)
{
    const char *p;
    unsigned int v;

    *slot_known = 0;
    p = strstr(line, "Slot ");
    if (p) {
        p += 5;
        while (*p == ' ') p++;
        if (*p == '1' || *p == '2') { *slot_out = *p - '0'; *slot_known = 1; }
    }

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

    /* MI: Hytera 40-bit (MI(40)) preferred, else MOTOTRBO 32-bit (MI(32)). */
    p = strstr(line, "MI(40):");
    if (p) {
        unsigned long long mv;
        p += 7;
        while (*p == ' ') p++;
        if (sscanf(p, "%llx", &mv) != 1) return 0;
        *mi_out = (uint64_t)mv;
        return 1;
    }
    p = strstr(line, "MI(32):");
    if (p) {
        p += 7;
        while (*p == ' ') p++;
        if (sscanf(p, "%x", &v) != 1) return 0;
        *mi_out = (uint64_t)v;
        return 1;
    }
    return 0;
}

/* Track which slot's burst a line belongs to from the bracketed sync marker,
 * e.g. "Sync: +DMR  [SLOT1]  slot2" or "[slot1]". Returns 1/2, or 0 if none. */
static int sync_active_slot(const char *line)
{
    if (strstr(line, "[SLOT1]") || strstr(line, "[slot1]")) return 1;
    if (strstr(line, "[SLOT2]") || strstr(line, "[slot2]")) return 2;
    return 0;
}

/* Classify a DSD-FME log line as a voice superframe-START marker, so the
 * converter can locate the first PI's true superframe. The marker differs by
 * capture mode: repeater/TDMA logs "VC1*..VC6" (six per superframe, only the
 * "VCn*" first burst carries the '*' sync flag), while simplex/MS logs a single
 * "VC*" per superframe. Returns 1 for a repeater start ("VCn*"), 2 for a simplex
 * start ("VC*"), 0 otherwise. "VC2".."VC6" (no '*') are NOT starts. */
static int superframe_start_kind(const char *line)
{
    const char *p;
    /* Repeater/TDMA: every superframe's first burst logs "VC1" (the '*' sync
     * flag only appears on the initial lock / re-syncs, so match VC1 with or
     * without it). "VC2".."VC6" are mid-superframe and must NOT count. */
    if (strstr(line, "VC1")) return 1;
    /* Simplex/MS: one bare "VC*" per superframe (VC immediately followed by *). */
    p = strstr(line, "VC");
    while (p) {
        if (p[2] == '*') return 2;
        p = strstr(p + 2, "VC");
    }
    return 0;
}

/* Parse a DSD-FME late-entry recovery line, e.g.
 *   "Slot 1 PI/LFSR and Late Entry MI Mismatch - 00000000 : 69EDB979 (CRC OK)"
 * The second value is the MI recovered from the voice superframe's embedded
 * signalling; it carries "(CRC OK)" only when it passed CRC, which is what makes
 * it trustworthy when the PI header's own MI field decoded to zero. Returns 1
 * (with slot + MI) on a CRC-OK line, 0 otherwise (CRC-ERR lines are rejected).
 */
static int parse_late_entry_mi(const char *line, int *slot_out, uint64_t *mi_out)
{
    const char *p = strstr(line, "Late Entry MI Mismatch");
    if (!p) return 0;
    if (!strstr(line, "(CRC OK)")) return 0;

    const char *s = strstr(line, "Slot ");
    int slot = 0;
    if (s) {
        s += 5;
        while (*s == ' ') s++;
        if (*s == '1' || *s == '2') slot = *s - '0';
    }
    if (slot != 1 && slot != 2) return 0;

    /* MI is the hex value after the colon in "- <pi_mi> : <late_mi> (CRC OK)". */
    p = strchr(p, ':');
    if (!p) return 0;
    p++;
    while (*p == ' ') p++;
    unsigned long long mv;
    if (sscanf(p, "%llx", &mv) != 1) return 0;

    *slot_out = slot;
    *mi_out = (uint64_t)mv;
    return 1;
}

static void pi_list_push(PiList *pl, uint64_t mi, uint8_t alg, uint8_t kid, int sf)
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
    pl->e[pl->n].sf  = sf;
    pl->n++;
}

static void load_pi_lists(const char *log_path, PiList pi[2])
{
    FILE *f;
    char line[2048];

    pi[0].e = pi[1].e = NULL;
    pi[0].n = pi[1].n = pi[0].cap = pi[1].cap = 0;
    pi[0].first_sf = pi[1].first_sf = 0;

    if (!log_path || !*log_path) return;
    f = fopen(log_path, "r");
    if (!f) return;

    int cur_slot = 0;         /* last active slot seen in a sync line          */
    int rep_sf[2] = {0, 0};   /* repeater superframe starts ("VCn*") per slot  */
    int simp_sf[2] = {0, 0};  /* simplex superframe markers ("VC*") per slot   */
    while (fgets(line, sizeof(line), f)) {
        int slot = 0, slot_known = 0;
        uint8_t alg, kid;
        uint64_t mi;
        int s = sync_active_slot(line);
        if (s) cur_slot = s;
        /* Count voice superframe-start markers so we can learn WHICH superframe
         * the first decoded PI belongs to -- DSD-FME often locks onto voice
         * several superframes before it decodes a clean PI header, so pi.e[0] is
         * usually NOT superframe 0. Repeater and simplex mark superframes
         * differently (see superframe_start_kind), so count each kind. */
        {
            int k = superframe_start_kind(line);
            int vslot = s ? s : (cur_slot ? cur_slot : 1);  /* simplex/MS -> slot 1 */
            if (vslot >= 1 && vslot <= 2) {
                if      (k == 1) rep_sf[vslot - 1]++;
                else if (k == 2) simp_sf[vslot - 1]++;
            }
        }
        /* Backfill a zeroed PI MI from a following CRC-OK late-entry recovery:
         * DSD-FME emits the PI header (MI decoded to 0) then, on the next line,
         * the true MI recovered from the voice superframe. Without this the whole
         * superframe is scored with MI=0 -- pure noise against the correct key. */
        {
            int le_slot;
            uint64_t le_mi;
            if (parse_late_entry_mi(line, &le_slot, &le_mi)) {
                PiList *pl = &pi[le_slot - 1];
                if (pl->n > 0 && pl->e[pl->n - 1].mi == 0)
                    pl->e[pl->n - 1].mi = le_mi;
                continue;
            }
        }
        if (!parse_pi_line(line, &slot, &slot_known, &alg, &kid, &mi)) continue;
        if (!slot_known) slot = cur_slot;   /* Hytera PI: use surrounding sync context */
        if (slot < 1 || slot > 2) continue;
        {
            /* Pin EACH PI's true superframe index (not just the first one). A
             * repeater "VCn*" start precedes the mid-superframe PI, so the running
             * count includes the PI's own superframe (subtract 1); a simplex "VC*"
             * follows the PI, so the count is the superframes fully before it (use
             * as-is). Per-PI superframes are what let a burst find the PI of its own
             * transmission on multi-call captures (see the mapping below). */
            int r = rep_sf[slot-1], sp = simp_sf[slot-1];
            int cur_sf = r ? (r - 1) : sp;
            if (pi[slot-1].n == 0) pi[slot-1].first_sf = cur_sf;
            if (pi[slot-1].n < MAX_PI_PER_SLOT)
                pi_list_push(&pi[slot-1], mi, alg, kid, cur_sf);
        }
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
        uint64_t mi = 0;
        uint8_t alg = 0, kid = 0;
        int has_meta = 0;

        /* DSP line: "<slot> <type_hex> <payload_hex>" */
        if (sscanf(line, "%d %x %16383s", &slot, &burst_type, hex) != 3) continue;
        if (slot < 1 || slot > 2) continue;
        /* Type 0x98 is the CACH, which DSD-FME emits before EVERY voice burst --
         * it is not a silence marker. An earlier heuristic tagged the following
         * burst SILENCE, which tagged (nearly) every frame and, via the KPA
         * pre-filter, pruned the correct key. There is no reliable silence signal
         * in the -Q dump (encrypted voice cannot be classified without the key),
         * so we skip the CACH and never emit SILENCE from the converter. */
        if (burst_type == 0x98) continue;
        if (burst_type != 0x10) continue;  /* skip everything else */

        hexlen = strlen(hex);
        if (hexlen < 66) continue;
        hex[66] = '\0';
        for (k = 0; k < 66; k++)
            if (hex[k] >= 'a' && hex[k] <= 'f') hex[k] = (char)(hex[k] - 'a' + 'A');

        si = slot - 1;
        if (pi[si].n > 0) {
            /* Map this burst's superframe to the PI whose OWN superframe governs it:
             * the most recent PI with e[j].sf <= sf_idx (PIs are in ascending superframe
             * order), so each burst anchors to the PI of its own transmission. Indexing
             * densely by (sf_idx - first_sf) breaks on multi-call captures: a boundary
             * superframe carries two PIs (an outgoing C- plus the next call's H-), so a
             * dense index runs one ahead per call and misaligns every later MI. */
            int j, gi = -1;
            sf_idx = burst_count[si] / 6;
            for (j = 0; j < pi[si].n; j++) {
                if (pi[si].e[j].sf <= sf_idx) gi = j;
                else break;                       /* ascending: no later PI qualifies */
            }
            if (gi < 0) {
                /* Bursts before the first decoded PI: back-extrapolate from e[0]. */
                int back = pi[si].e[0].sf - sf_idx;
                alg = pi[si].e[0].alg;
                kid = pi[si].e[0].kid;
                if (IS_HYTERA_EP_ALG(alg))
                    mi = pi[si].e[0].mi;   /* Hytera 5-byte LFSR inverse not modeled */
                else
                    mi = lfsr_reverse((uint32_t)pi[si].e[0].mi, 32 * back);
            } else if (pi[si].e[gi].sf == sf_idx) {
                /* Exact superframe match. When two PIs share it (an outgoing C- then
                 * a new-call H-), prefer the FIRST -- it continues the call these
                 * bursts belong to; the H- governs from the next superframe. A lone
                 * H- start is the only entry and wins by default. */
                while (gi > 0 && pi[si].e[gi - 1].sf == sf_idx) gi--;
                mi  = pi[si].e[gi].mi;
                alg = pi[si].e[gi].alg;
                kid = pi[si].e[gi].kid;
            } else {
                /* Gap between PIs: forward-extrapolate from the most recent one. A
                 * new-call H- re-anchors here, so extrapolation never crosses a call
                 * boundary. MOTOTRBO advances 32 LFSR steps/superframe; Hytera steps
                 * its 5-byte LFSR once/superframe. */
                int extra = sf_idx - pi[si].e[gi].sf;
                alg = pi[si].e[gi].alg;
                kid = pi[si].e[gi].kid;
                if (IS_HYTERA_EP_ALG(alg)) {
                    int s2;
                    mi = pi[si].e[gi].mi;
                    for (s2 = 0; s2 < extra; s2++) mi = hytera_mi_lfsr_step(mi);
                } else {
                    mi = lfsr_advance((uint32_t)pi[si].e[gi].mi, 32 * extra);
                }
            }
            has_meta = 1;
        }

        if (has_meta) {
            char mibuf[16];
            format_mi_tag(mibuf, sizeof(mibuf), mi);
            fprintf(fout, "%s;ALG=%02X;KID=%02X;MI=%s\n", hex, alg, kid, mibuf);
        } else {
            fprintf(fout, "%s\n", hex);
        }

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
        if (line->has_mi)    { char mibuf[16]; format_mi_tag(mibuf, sizeof(mibuf), line->mi); fprintf(f, ";MI=%s", mibuf); }
        if (line->silence_candidate) fprintf(f, ";SILENCE=1");
        fprintf(f, "\n");
    }

    fclose(f);
    return 1;
}

void validate_payload_set(const PayloadSet *ps,
                          char *summary, size_t summary_len,
                          char *warn,    size_t warn_len)
{
    size_t kmi9 = 0, hyt = 0, i;
    unsigned char first_kid = 0;
    int has_kid = 0;

    if (!ps || ps->count == 0) {
        snprintf(summary, summary_len, "0 payloads");
        snprintf(warn, warn_len, "No payloads loaded");
        return;
    }

    for (i = 0; i < ps->count; i++) {
        const PayloadLine *it = &ps->items[i];
        if (it->has_mi && it->has_algid) {
            if (it->algid == 0x21 || it->algid == 0x01) kmi9++;
            else if (IS_HYTERA_EP_ALG(it->algid))       hyt++;
        }
        if (!has_kid && it->has_mi) {
            first_kid = it->keyid;
            has_kid = 1;
        }
    }

    if (has_kid && hyt > kmi9)
        snprintf(summary, summary_len, "%zu payloads  \xb7  Hytera EP: %zu/%zu  \xb7  KID=%02X",
                 ps->count, hyt, ps->count, (unsigned)first_kid);
    else if (has_kid)
        snprintf(summary, summary_len, "%zu payloads  \xb7  KMI9: %zu/%zu  \xb7  KID=%02X",
                 ps->count, kmi9, ps->count, (unsigned)first_kid);
    else
        snprintf(summary, summary_len, "%zu payloads  (no MI metadata)", ps->count);

    warn[0] = '\0';
    if (ps->count < 30)
        snprintf(warn, warn_len, "! Only %zu payloads -- low confidence", ps->count);
}

/* Human name for a non-RC4 PI algid, per DSD-FME's algid table (dmr_le.c). Used
 * only for the "unsupported cipher" message so it names the real family instead
 * of always guessing "AES". */
static const char *alg_family_name(uint8_t alg)
{
    switch (alg) {
        case 0x22: return "DES-56";
        case 0x24: return "AES-128";
        case 0x25: return "AES-256";
        case 0x35: case 0x36: case 0x37: return "Kirisun";
        default:   return "non-RC4";
    }
}

PayloadClass payload_classify(const PayloadSet *ps, int *crackable,
                              char *msg, size_t msg_len)
{
    size_t i;
    size_t total, with_mi = 0, rc4_mi = 0, hytera_mi = 0, other_mi = 0;
    unsigned char other_alg = 0;
    PayloadClass cls;
    int ck = 0;
    char scratch[1];
    /* Capture-quality signals: an all-"silence" capture or one with too few
     * distinct MI cannot yield a verifiable key even when the cipher is
     * supported -- the two failure modes behind most "it found nothing" reports.
     * Counted here so the verdict can name them up front. */
    size_t silence_n = 0;
    uint64_t seen_mi[64];
    int distinct_mi = 0, distinct_capped = 0;

    /* msg is an optional out-param; route writes to a throwaway when NULL so the
     * snprintf calls below never dereference a null pointer. */
    if (!msg) { msg = scratch; msg_len = sizeof(scratch); }
    if (msg_len) msg[0] = '\0';
    if (crackable) *crackable = 0;
    if (!ps || ps->count == 0) {
        snprintf(msg, msg_len, "No payloads loaded");
        return PAYLOAD_CLASS_NONE;
    }
    total = ps->count;

    for (i = 0; i < total; i++) {
        const PayloadLine *it = &ps->items[i];
        unsigned char alg = it->has_algid ? it->algid
                          : (ps->has_global_algid ? ps->global_algid : 0);
        int has_mi = it->has_mi || ps->has_global_mi;
        int is_rc4 = (alg == 0x21 || alg == 0x01 || ((alg & 0x07u) == 0x01u));
        int is_hyt = IS_HYTERA_EP_ALG(alg);
        if (has_mi) {
            with_mi++;
            if      (is_rc4) rc4_mi++;
            else if (is_hyt) hytera_mi++;
            else if (it->has_algid || ps->has_global_algid) {
                other_mi++;
                if (!other_alg) other_alg = alg;
            }
        }
        if (it->silence_candidate) silence_n++;
        if (has_mi && !distinct_capped) {
            uint64_t m = it->has_mi ? it->mi : ps->global_mi;
            int seen = 0, k;
            for (k = 0; k < distinct_mi; k++) if (seen_mi[k] == m) { seen = 1; break; }
            if (!seen) {
                if (distinct_mi < 64) seen_mi[distinct_mi++] = m;
                else distinct_capped = 1;
            }
        }
    }

    /* Same precedence as the engine's mode auto-selection. */
    if (hytera_mi * 10 >= total * 9) {
        cls = PAYLOAD_CLASS_HYTERA_EP; ck = 1;
        snprintf(msg, msg_len,
            "Hytera Enhanced Privacy (RC4-40) + MI -- crackable (%zu/%zu frames)",
            hytera_mi, total);
    } else if (rc4_mi * 3 >= total) {
        cls = PAYLOAD_CLASS_MOTOTRBO_RC4; ck = 1;
        snprintf(msg, msg_len,
            "MOTOTRBO Enhanced Privacy (RC4-40) + MI -- crackable (%zu/%zu frames%s)",
            rc4_mi, total, (rc4_mi * 10 >= total * 9) ? ", strict" : ", relaxed");
    } else if (other_mi > rc4_mi && other_mi > hytera_mi) {
        cls = PAYLOAD_CLASS_UNSUPPORTED;
        snprintf(msg, msg_len,
            "Unsupported cipher (ALG=0x%02X, %s) -- NOT crackable by this tool",
            (unsigned)other_alg, alg_family_name(other_alg));
    } else if (rc4_mi > 0) {
        cls = PAYLOAD_CLASS_MOTOTRBO_RC4; ck = 1;
        snprintf(msg, msg_len,
            "RC4-40 + MI, weak signal -- crackable but only %zu/%zu frames carry MI",
            rc4_mi, total);
    } else if (with_mi == 0) {
        cls = PAYLOAD_CLASS_RC4_NO_MI;
        snprintf(msg, msg_len,
            "No MI metadata -- only the weak statistical fallback can run");
    } else {
        cls = PAYLOAD_CLASS_NONE;
        snprintf(msg, msg_len, "No recognizable Enhanced Privacy metadata");
    }

    /* Append the capture-quality suffix whenever MI metadata is present, so the
     * user sees the two most common failure signals before a long run: a low
     * distinct-MI count (weak validation) and a high silence-tag fraction (an
     * over-tagged capture, which also disables the KPA cache). */
    if (with_mi > 0) {
        size_t used = strlen(msg);
        char micount[8];
        if (distinct_capped) snprintf(micount, sizeof(micount), "64+");
        else                 snprintf(micount, sizeof(micount), "%d", distinct_mi);
        if (used < msg_len)
            snprintf(msg + used, msg_len - used,
                     " [MI %s, sil %d%%%s]", micount,
                     (int)((silence_n * 100 + total / 2) / total),
                     (silence_n * 2 > total) ? " over-tag" : "");
    }

    if (crackable) *crackable = ck;
    return cls;
}
