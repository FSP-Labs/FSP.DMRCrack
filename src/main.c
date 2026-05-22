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

#include <windows.h>

#include "../include/gui.h"

/* Force NVIDIA Optimus and AMD switchable-graphics systems to use the
 * high-performance discrete GPU for this process.
 * Without these exports the OS may route a laptop app to the integrated
 * GPU, causing cudaGetDeviceCount() to return 0 or cudaErrorInitializationError. */
__declspec(dllexport) unsigned long NvOptimusEnablement                = 1;
__declspec(dllexport) int          AmdPowerXpressRequestHighPerformance = 1;

int WINAPI WinMain(HINSTANCE h_instance, HINSTANCE h_prev, LPSTR lp_cmd_line, int n_cmd_show)
{
    (void)h_prev;
    (void)lp_cmd_line;

    /* Enable per-monitor DPI awareness for crisp rendering on high-DPI displays */
    SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);

    return run_gui(h_instance, n_cmd_show);
}
