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
 * updater.c - WinSparkle integration for automatic updates
 *
 * Replaces the previous hand-rolled WinHTTP + GitHub API updater.
 * WinSparkle fetches an appcast XML, verifies the EdDSA signature of the
 * installer, downloads it, and launches it — all with its own UI.
 */
#include "../include/updater.h"
#include "../include/version.h"

#include <windows.h>
#include <winsparkle.h>

#define APP_CLASS_NAME "FSPDMRCrackWindow"

/*
 * Called by WinSparkle on a background thread when an update requires the
 * application to shut down (e.g. to replace the running executable).
 * We post WM_CLOSE to trigger the normal WM_DESTROY cleanup path.
 */
static void __cdecl on_shutdown_request(void)
{
    HWND hwnd = FindWindowA(APP_CLASS_NAME, NULL);
    if (hwnd)
        PostMessageA(hwnd, WM_CLOSE, 0, 0);
}

void updater_init(void)
{
    win_sparkle_set_appcast_url(DMRCRACK_APPCAST_URL);
    win_sparkle_set_app_details(L"FSP-Labs", L"FSP.DMRCrack", DMRCRACK_VERSION_W);
    win_sparkle_set_eddsa_public_key(DMRCRACK_EDDSA_PUB_KEY);
    win_sparkle_set_shutdown_request_callback(on_shutdown_request);
    win_sparkle_init();
}

void updater_cleanup(void)
{
    win_sparkle_cleanup();
}

void updater_check_now(void)
{
    win_sparkle_check_update_with_ui();
}
