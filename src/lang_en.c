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
 * lang_en.c - English string table (default language)
 *
 * To add a new language, copy this file to lang_XX.c, translate the strings,
 * and link lang_XX.c instead of lang_en.c.
 */
#include "../include/lang.h"

const Lang g_lang = {
    /* ---- Section headers ---- */
    .section_capture    = "CAPTURE",
    .section_bruteforce = "BRUTE FORCE",

    /* ---- Static labels ---- */
    .label_audio      = "Audio:",
    .label_file       = "File:",
    .label_start_key  = "Start:",
    .label_end_key    = "End:",
    .label_threads    = "Threads:",
    .label_samples    = "Samples:",

    /* ---- Buttons ---- */
    .btn_demodulate = "Demodulate",
    .btn_export     = "Export",
    .btn_start      = "Start",
    .btn_pause      = "Pause",
    .btn_resume     = "Resume",
    .btn_stop       = "Stop",
    .btn_ready      = "Ready",

    /* ---- Demodulation status / errors ---- */
    .status_demodulating       = "Demodulating with DSD-FME... [1/2]",
    .status_converting         = "Converting DSP to BIN... [2/2]",
    .status_demod_in_memory    = "(demodulated in memory)",
    .err_demod_already_running = "Demodulation already in progress",
    .err_demod_thread          = "Error creating demodulation thread",
    .err_no_audio_selected     = "Error: select an audio file first",
    .err_audio_not_found       = "Error: audio file not found or inaccessible",
    .err_path_has_quotes       = "Error: path contains invalid characters (\")",
    .err_cygwin_dlls_missing   = "Error: Cygwin DLLs missing next to dsd-fme.exe "
                                 "(cygwin1.dll, cyggcc_s-seh-1.dll, ...)",
    .err_dll_not_found_exit    = "Error: DLL not found when launching DSD-FME "
                                 "(place cygwin1.dll and deps next to dsd-fme.exe)",
    .err_dsd_failed            = "DSD-FME failed (see details)",
    .err_dsd_launch            = "Error launching DSD-FME",
    .err_no_dsp_output         = "Error: DSP output not found (see details)",
    .err_dsp_conversion        = "Error: DSP->BIN conversion failed",
    .err_dsd_missing           = "Error: dsd-fme.exe missing — reinstall the app",
    .err_py_script_missing     = "Error: missing tools\\dsdfme_dsp_to_bin.py",
    .err_bin_load              = "Error loading generated BIN file",

    /* ---- Brute-force validation errors ---- */
    .err_no_bin_selected  = "Select a .bin payload file first",
    .err_start_key_invalid = "Invalid start key (hex, 1-10 digits)",
    .err_end_key_invalid   = "Invalid end key (hex, 1-10 digits)",
    .err_threads_empty    = "Invalid thread count",
    .err_threads_range    = "Threads must be between 1 and 64",
    .err_samples_empty    = "Invalid sample count",
    .err_samples_range    = "Samples must be between 1 and 100000",
    .warn_few_payloads    = "Warning: few payload lines (<64).\n"
                            "Consider capturing more voice frames.",

    /* ---- Export ---- */
    .err_no_payloads_export = "No payloads loaded to export.",
    .msg_exported           = "Exported %zu lines to:\n%s",
    .dlg_export_filter      = "BIN payload file (*.bin)\0*.bin\0All files (*.*)\0*.*\0",

    /* ---- Fatal / startup errors ---- */
    .err_wnd_class  = "Failed to register window class",
    .err_wnd_create = "Failed to create main window",

    /* ---- Status panel format strings ---- */
    .fmt_keys_tested    = "Keys tested: %llu / %llu (%.2f%%)",
    .fmt_speed          = "Speed: %.2f keys/s",
    .fmt_time           = "Time: %s  |  ETA: %s",
    .fmt_backend        = "Backend: %s",
    .fmt_best_candidate = "Best candidate: %s",
    .fmt_best_score     = "Best score: %s",
    .fmt_status         = "Status: %s",
    .fmt_cuda_error     = "CUDA error: %s",
    .fmt_payloads_loaded = "%zu payloads loaded",

    /* ---- State labels ---- */
    .state_running = "RUNNING",
    .state_paused  = "PAUSED",
    .state_stopped = "STOPPED",

    /* ---- Graph titles ---- */
    .graph_keys_title  = "Keys/s (history)",
    .graph_score_title = "Best score (evolution)",

    /* ---- File dialog filters ---- */
    .dlg_bin_filter   = "BIN payload (*.bin)\0*.bin\0All files (*.*)\0*.*\0",
    .dlg_audio_filter = "DMR Audio (*.wav;*.mp3;*.flac;*.ogg)\0*.wav;*.mp3;*.flac;*.ogg\0"
                        "WAV (*.wav)\0*.wav\0All files (*.*)\0*.*\0",

    /* ---- Copy / notification ---- */
    .btn_copy_key   = "Copy",
    .msg_key_found  = "Key found! %s (score: %.1f)",
    .msg_key_copied = "Key copied to clipboard",

};
