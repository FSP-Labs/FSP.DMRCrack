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

int WINAPI WinMain(HINSTANCE h_instance, HINSTANCE h_prev, LPSTR lp_cmd_line, int n_cmd_show)
{
    (void)h_prev;
    (void)lp_cmd_line;
    return run_gui(h_instance, n_cmd_show);
}
