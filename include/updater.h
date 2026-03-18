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
 * updater.h - Automatic update check via GitHub Releases API
 *
 * Launches a background thread that queries:
 *   GET https://api.github.com/repos/<owner>/<repo>/releases/latest
 *
 * If a newer version is found the thread posts msg_id to hwnd with the
 * new version string (heap-allocated) in lParam.  The caller must free()
 * the lParam string after handling the message.
 */
#ifndef UPDATER_H
#define UPDATER_H

#include <windows.h>

/*
 * updater_check_async - start background update check (non-blocking).
 * hwnd   : window that receives msg_id when an update is found
 * msg_id : WM_APP+N message id defined by the caller
 */
void updater_check_async(HWND hwnd, UINT msg_id);

#endif /* UPDATER_H */
