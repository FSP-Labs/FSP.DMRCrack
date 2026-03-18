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

/*
 * updater.c - Background update check using WinHTTP + GitHub Releases API
 */
#include "../include/updater.h"
#include "../include/version.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winhttp.h>

#pragma comment(lib, "winhttp.lib")

/* HTTP response buffer — GitHub releases JSON is well under 64 KB */
#define BUF_SIZE   65536

/* Timeouts in ms: resolve / connect / send / receive */
#define TIMEOUT_MS 8000

typedef struct {
    HWND hwnd;
    UINT msg_id;
} UpdateCtx;

/* Parse "major.minor.patch" -> integers.  Returns 1 on success. */
static int parse_ver(const char *s, int *ma, int *mi, int *pa)
{
    return sscanf(s, "%d.%d.%d", ma, mi, pa) == 3;
}

/* Returns 1 if remote > local (both as "M.m.p" strings). */
static int is_newer(const char *remote, const char *local)
{
    int rM, rm, rp, lM, lm, lp;
    if (!parse_ver(remote, &rM, &rm, &rp)) return 0;
    if (!parse_ver(local,  &lM, &lm, &lp)) return 0;
    if (rM != lM) return rM > lM;
    if (rm != lm) return rm > lm;
    return rp > lp;
}

/*
 * Extract the tag_name value from a GitHub releases JSON response.
 * Strips a leading 'v' / 'V'.  Writes into buf (max len bytes).
 * Returns 1 on success.
 */
static int extract_tag(const char *json, char *buf, int len)
{
    const char *p = strstr(json, "\"tag_name\"");
    if (!p) return 0;
    p = strchr(p, ':');
    if (!p) return 0;
    p++;
    while (*p == ' ' || *p == '"') p++;
    if (*p == 'v' || *p == 'V') p++;
    int i = 0;
    while (*p && *p != '"' && *p != ',' && i < len - 1)
        buf[i++] = *p++;
    buf[i] = '\0';
    return i > 0;
}

/* Convert a narrow ASCII string to a newly-allocated wide string. */
static wchar_t *to_wide(const char *s)
{
    int n = MultiByteToWideChar(CP_ACP, 0, s, -1, NULL, 0);
    if (n <= 0) return NULL;
    wchar_t *w = (wchar_t *)malloc(n * sizeof(wchar_t));
    if (w) MultiByteToWideChar(CP_ACP, 0, s, -1, w, n);
    return w;
}

static DWORD WINAPI update_thread(LPVOID param)
{
    UpdateCtx *ctx     = (UpdateCtx *)param;
    HINTERNET  session = NULL, conn = NULL, req = NULL;
    char      *body    = NULL;
    wchar_t   *ua      = NULL, *api_path = NULL;
    DWORD      bytes_read = 0, total = 0;
    char       tag[64] = {0};

    body = (char *)malloc(BUF_SIZE);
    if (!body) goto done;

    /* Build User-Agent: "FSP.DMRCrack/0.1.0" */
    {
        char ua_narrow[64];
        snprintf(ua_narrow, sizeof(ua_narrow), "FSP.DMRCrack/%s", DMRCRACK_VERSION);
        ua = to_wide(ua_narrow);
        if (!ua) goto done;
    }

    /* Build API path: "/repos/FSP-Labs/FSP.DMRCrack/releases/latest" */
    {
        char path_narrow[256];
        snprintf(path_narrow, sizeof(path_narrow),
                 "/repos/%s/%s/releases/latest",
                 DMRCRACK_GITHUB_OWNER, DMRCRACK_GITHUB_REPO);
        api_path = to_wide(path_narrow);
        if (!api_path) goto done;
    }

    session = WinHttpOpen(ua,
                          WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                          WINHTTP_NO_PROXY_NAME,
                          WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) goto done;

    WinHttpSetTimeouts(session, TIMEOUT_MS, TIMEOUT_MS, TIMEOUT_MS, TIMEOUT_MS);

    conn = WinHttpConnect(session, L"api.github.com",
                          INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!conn) goto done;

    req = WinHttpOpenRequest(conn, L"GET", api_path,
                             NULL, WINHTTP_NO_REFERER,
                             WINHTTP_DEFAULT_ACCEPT_TYPES,
                             WINHTTP_FLAG_SECURE);
    if (!req) goto done;

    WinHttpAddRequestHeaders(req,
        L"Accept: application/vnd.github+json\r\n"
        L"X-GitHub-Api-Version: 2022-11-28\r\n",
        (DWORD)-1, WINHTTP_ADDREQ_FLAG_ADD);

    if (!WinHttpSendRequest(req, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                            WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) goto done;
    if (!WinHttpReceiveResponse(req, NULL)) goto done;

    while (total < BUF_SIZE - 1) {
        if (!WinHttpReadData(req, body + total,
                             BUF_SIZE - 1 - total, &bytes_read)) break;
        if (bytes_read == 0) break;
        total += bytes_read;
    }
    body[total] = '\0';

    if (extract_tag(body, tag, sizeof(tag)) && is_newer(tag, DMRCRACK_VERSION)) {
        char *ver = (char *)malloc(strlen(tag) + 1);
        if (ver) {
            strcpy(ver, tag);
            PostMessageA(ctx->hwnd, ctx->msg_id, 0, (LPARAM)ver);
        }
    }

done:
    if (req)     WinHttpCloseHandle(req);
    if (conn)    WinHttpCloseHandle(conn);
    if (session) WinHttpCloseHandle(session);
    free(body);
    free(ua);
    free(api_path);
    free(ctx);
    return 0;
}

void updater_check_async(HWND hwnd, UINT msg_id)
{
    UpdateCtx *ctx = (UpdateCtx *)malloc(sizeof(UpdateCtx));
    if (!ctx) return;
    ctx->hwnd   = hwnd;
    ctx->msg_id = msg_id;

    HANDLE t = CreateThread(NULL, 0, update_thread, ctx, 0, NULL);
    if (t)
        CloseHandle(t);   /* detached — thread frees ctx on exit */
    else
        free(ctx);
}
