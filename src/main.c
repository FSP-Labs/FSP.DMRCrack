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
#include <shellapi.h>
#include <stdio.h>
#include <wchar.h>

#include "../include/gui.h"
#include "../include/version.h"

/* Force NVIDIA Optimus and AMD switchable-graphics systems to use the
 * high-performance discrete GPU for this process.
 * Without these exports the OS may route a laptop app to the integrated
 * GPU, causing cudaGetDeviceCount() to return 0 or cudaErrorInitializationError. */
__declspec(dllexport) unsigned long NvOptimusEnablement                = 1;
__declspec(dllexport) int          AmdPowerXpressRequestHighPerformance = 1;

static void attach_output_console(void)
{
    FILE *stream;

    if (!AttachConsole(ATTACH_PARENT_PROCESS)) {
        AllocConsole();
    }

    freopen_s(&stream, "CONOUT$", "w", stdout);
    freopen_s(&stream, "CONOUT$", "w", stderr);
}

static int handle_command_line_flags(void)
{
    int argc = 0;
    int handled = 0;
    LPWSTR *argv = CommandLineToArgvW(GetCommandLineW(), &argc);

    if (argv == NULL) {
        return 0;
    }

    if (argc == 2 && wcscmp(argv[1], L"--version") == 0) {
        attach_output_console();
        printf("FSP.DMRCrack %s\n", DMRCRACK_VERSION);
        handled = 1;
    } else if (argc == 2 && wcscmp(argv[1], L"--help") == 0) {
        attach_output_console();
        printf("Usage: dmrcrack.exe [--help] [--version]\n");
        handled = 1;
    }

    LocalFree(argv);
    return handled;
}

int WINAPI WinMain(HINSTANCE h_instance, HINSTANCE h_prev, LPSTR lp_cmd_line, int n_cmd_show)
{
    (void)h_prev;
    (void)lp_cmd_line;

    if (handle_command_line_flags()) {
        return 0;
    }

    /* Enable per-monitor DPI awareness for crisp rendering on high-DPI displays */
    SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);

    return run_gui(h_instance, n_cmd_show);
}
