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
 * updater.h - Automatic updates via WinSparkle + EdDSA-signed appcast
 *
 * Call updater_init() once at startup (after GUI is created) and
 * updater_cleanup() before exit.  WinSparkle handles the rest:
 * checking the appcast, showing UI, downloading, verifying the
 * EdDSA signature, and launching the installer.
 */
#ifndef UPDATER_H
#define UPDATER_H

/* Initialize WinSparkle (call once in WM_CREATE). */
void updater_init(void);

/* Shut down WinSparkle background threads (call in WM_DESTROY). */
void updater_cleanup(void);

/* Trigger a manual update check with WinSparkle's built-in UI. */
void updater_check_now(void);

#endif /* UPDATER_H */
