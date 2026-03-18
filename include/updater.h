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
 * updater.h - Automatic update check + download via GitHub Releases API
 *
 * updater_check_async:
 *   Background thread queries /repos/<owner>/<repo>/releases/latest.
 *   If a newer version is found, posts msg_id to hwnd with a heap-allocated
 *   UpdateInfo* in lParam.  The caller must free() it after handling.
 *
 * updater_download_and_install:
 *   Downloads the installer from the given URL to %TEMP%, launches it,
 *   and posts msg_done to hwnd when done (or on error).
 */
#ifndef UPDATER_H
#define UPDATER_H

#include <windows.h>

typedef struct {
    char version[64];
    char download_url[1024];
} UpdateInfo;

/*
 * updater_check_async - start background update check (non-blocking).
 * hwnd   : window that receives msg_id when an update is found
 * msg_id : WM_APP+N message id defined by the caller
 * lParam will be a heap-allocated UpdateInfo* (caller must free).
 */
void updater_check_async(HWND hwnd, UINT msg_id);

/*
 * updater_download_and_install - download installer and run it.
 * url     : browser_download_url from GitHub releases
 * hwnd    : window to notify
 * msg_done: posted when download completes (wParam=1 success, 0 failure)
 */
void updater_download_and_install(const char *url, HWND hwnd, UINT msg_done);

#endif /* UPDATER_H */
