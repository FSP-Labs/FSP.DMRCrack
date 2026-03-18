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

#include "../include/rc4.h"

void rc4_init(RC4_CTX *ctx, const unsigned char *key, size_t keylen)
{
    unsigned int i;
    unsigned int j;

    for (i = 0; i < 256; ++i) {
        ctx->S[i] = (unsigned char)i;
    }

    j = 0;
    for (i = 0; i < 256; ++i) {
        unsigned int t;
        j = (j + ctx->S[i] + key[i % keylen]) & 0xFFu;
        t = ctx->S[i];
        ctx->S[i] = ctx->S[j];
        ctx->S[j] = (unsigned char)t;
    }

    ctx->i = 0;
    ctx->j = 0;
}

void rc4_crypt(RC4_CTX *ctx, const unsigned char *in, unsigned char *out, size_t len)
{
    size_t n;

    for (n = 0; n < len; ++n) {
        unsigned int t;
        ctx->i = (ctx->i + 1u) & 0xFFu;
        ctx->j = (ctx->j + ctx->S[ctx->i]) & 0xFFu;

        t = ctx->S[ctx->i];
        ctx->S[ctx->i] = ctx->S[ctx->j];
        ctx->S[ctx->j] = (unsigned char)t;

        t = (ctx->S[ctx->i] + ctx->S[ctx->j]) & 0xFFu;
        out[n] = (unsigned char)(in[n] ^ ctx->S[t]);
    }
}
