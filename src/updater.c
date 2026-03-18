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
 * updater.c - Background update check + download using WinHTTP + GitHub API
 */
#include "../include/updater.h"
#include "../include/version.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winhttp.h>
#include <urlmon.h>
#include <shellapi.h>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "urlmon.lib")

/* HTTP response buffer — GitHub releases JSON is well under 64 KB */
#define BUF_SIZE   65536

/* Timeouts in ms: resolve / connect / send / receive */
#define TIMEOUT_MS 8000

typedef struct {
    HWND hwnd;
    UINT msg_id;
} CheckCtx;

typedef struct {
    char url[1024];
    HWND hwnd;
    UINT msg_done;
} DownloadCtx;

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

/*
 * Extract the browser_download_url for the first .exe asset.
 * Writes into buf (max len bytes).  Returns 1 on success.
 */
static int extract_download_url(const char *json, char *buf, int len)
{
    /* Find the "assets" array, then look for browser_download_url ending in .exe */
    const char *assets = strstr(json, "\"assets\"");
    if (!assets) return 0;

    const char *p = assets;
    while ((p = strstr(p, "\"browser_download_url\"")) != NULL) {
        p = strchr(p, ':');
        if (!p) return 0;
        p++;
        while (*p == ' ' || *p == '"') p++;
        /* Copy the URL */
        int i = 0;
        while (*p && *p != '"' && i < len - 1)
            buf[i++] = *p++;
        buf[i] = '\0';
        /* Check if it ends in -Setup.exe */
        if (i > 10 && strstr(buf, "-Setup.exe")) return 1;
        /* Also accept .exe as fallback */
        if (i > 4 && strcmp(buf + i - 4, ".exe") == 0) return 1;
    }
    return 0;
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

static DWORD WINAPI check_thread(LPVOID param)
{
    CheckCtx  *ctx     = (CheckCtx *)param;
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
        UpdateInfo *info = (UpdateInfo *)calloc(1, sizeof(UpdateInfo));
        if (info) {
            snprintf(info->version, sizeof(info->version), "%s", tag);
            extract_download_url(body, info->download_url, sizeof(info->download_url));
            PostMessageA(ctx->hwnd, ctx->msg_id, 0, (LPARAM)info);
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
    CheckCtx *ctx = (CheckCtx *)malloc(sizeof(CheckCtx));
    if (!ctx) return;
    ctx->hwnd   = hwnd;
    ctx->msg_id = msg_id;

    HANDLE t = CreateThread(NULL, 0, check_thread, ctx, 0, NULL);
    if (t)
        CloseHandle(t);   /* detached — thread frees ctx on exit */
    else
        free(ctx);
}

/* --- Download + install -------------------------------------------------- */

static DWORD WINAPI download_thread(LPVOID param)
{
    DownloadCtx *ctx = (DownloadCtx *)param;
    int ok = 0;

    /* Build temp path: %TEMP%\FSP.DMRCrack-Update-Setup.exe */
    char tmp_dir[MAX_PATH], tmp_file[MAX_PATH];
    GetTempPathA(MAX_PATH, tmp_dir);
    snprintf(tmp_file, sizeof(tmp_file), "%sFSP.DMRCrack-Update-Setup.exe", tmp_dir);

    /* Delete any previous download */
    DeleteFileA(tmp_file);

    /* URLDownloadToFile handles HTTPS + GitHub redirects automatically */
    HRESULT hr = URLDownloadToFileA(NULL, ctx->url, tmp_file, 0, NULL);
    if (SUCCEEDED(hr)) {
        /* Verify the file was actually written and has some size */
        DWORD attr = GetFileAttributesA(tmp_file);
        if (attr != INVALID_FILE_ATTRIBUTES) {
            /* Launch the installer and request app close */
            HINSTANCE ret = ShellExecuteA(NULL, "open", tmp_file,
                                          NULL, NULL, SW_SHOWNORMAL);
            if ((INT_PTR)ret > 32) ok = 1;
        }
    }

    PostMessageA(ctx->hwnd, ctx->msg_done, (WPARAM)ok, 0);
    free(ctx);
    return 0;
}

void updater_download_and_install(const char *url, HWND hwnd, UINT msg_done)
{
    DownloadCtx *ctx = (DownloadCtx *)calloc(1, sizeof(DownloadCtx));
    if (!ctx) {
        PostMessageA(hwnd, msg_done, 0, 0);
        return;
    }
    snprintf(ctx->url, sizeof(ctx->url), "%s", url);
    ctx->hwnd     = hwnd;
    ctx->msg_done = msg_done;

    HANDLE t = CreateThread(NULL, 0, download_thread, ctx, 0, NULL);
    if (t)
        CloseHandle(t);
    else {
        free(ctx);
        PostMessageA(hwnd, msg_done, 0, 0);
    }
}
