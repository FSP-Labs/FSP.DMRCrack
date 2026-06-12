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

const Lang g_lang_en = {
    /* ---- Static labels ---- */
    .label_audio      = "WAV:",
    .label_file       = ".bin:",
    .label_start_key  = "Start:",
    .label_end_key    = "End:",
    .label_threads    = "Threads:",
    .label_samples    = "Samples:",
    .label_gpu_pct    = "GPU %:",

    /* Tile titles */
    .tile_throughput     = "THROUGHPUT",
    .tile_progress       = "PROGRESS",
    .tile_candidate      = "BEST CANDIDATE",
    /* Tile body formats */
    .tile_cpu_only            = "CPU only",
    .tile_split_fmt           = "GPU  %s  \xb7  CPU  %s",
    .tile_score_fmt           = "Score  %.2f",
    .tile_progress_meta_fmt   = "%s keys   \xb7   ETA  %s   \xb7   elapsed  %s",
    .empty_hint               = "Load a .bin or capture live, then press Start",
    .status_idle              = "Idle",
    .status_searching         = "Searching...",
    .graph_waiting            = "waiting for data",
    /* KPA badge */
    .kpa_silence_fmt          = "KPA: %u silence frames",
    /* Status strip */
    .status_backend_cuda = "CUDA GPU",
    .status_backend_cpu  = "CPU",
    .msg_cuda_fallback   = "CUDA error \x97 continued on CPU",
    /* Payload validation */
    .val_payloads_ok     = "%zu payloads  \xb7  KMI9: %zu/%zu  \xb7  KID=%02X",
    .val_align_warn      = "! Burst alignment warning",
    .warn_low_payloads_n = "! Only %zu payloads -- low confidence, risk of false positive",

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
    .err_dsd_missing           = "Error: dsd-fme.exe missing \x97 reinstall the app",
    .err_dsd_missing_detail    = "dsd-fme.exe was not found in the tools\\ folder.\n\n"
                                 "The installation may be incomplete or corrupted.\n"
                                 "Please reinstall FSP.DMRCrack.",
    .warn_dsd_missing_startup  = "WARNING: dsd-fme.exe not found \x97 reinstall the app",
    .msg_demod_ok_fmt          = "OK: %zu payloads -> %s",
    .err_dsd_detail_fmt        = "%s (exit %lu)\n\nLog: %s\n\n%s",
    .err_no_dsp_detail_fmt     = "%s\n\nLog: %s\n\ndsd-fme output:\n%s",
    .lbl_empty_log             = "(empty log)",
    .lbl_empty_log_no_output   = "(empty log \x97 dsd-fme produced no output)",
    .err_py_script_missing     = "Error: missing tools\\dsdfme_dsp_to_bin.py",
    .err_bin_load              = "Error loading generated BIN file",

    /* ---- Listen: decrypt recovered audio to WAV ---- */
    .btn_listen                 = "Listen",
    .status_decrypting          = "Decrypting audio with DSD-FME...",
    .err_listen_already_running = "Decryption already in progress",
    .err_listen_thread          = "Error creating decryption thread",
    .err_listen_no_source       = "Select the source WAV (audio field) to play decrypted audio",
    .err_listen_no_key          = "No recovered key yet - run a search first",
    .msg_listen_ok_fmt          = "Decrypted audio: %s",

    /* ---- Live capture (RTL-SDR, unattended supervised) ---- */
    .btn_capture_start          = "Live capture",
    .btn_capture_stop           = "Stop capture",
    .err_capture_no_spec        = "Enter an RTL-SDR spec in the Audio field, e.g. rtl:0:451.2M:22",
    .err_capture_launch         = "Could not start live capture (check DSD-FME / RTL-SDR)",
    .err_capture_no_device      = "RTL-SDR not opened: plugged in? WinUSB driver (Zadig)? Closed in SDR#/other SDR app?",
    .err_capture_died           = "dsd-fme exited early - see live.log in the session folder",
    .cap_sync_ok                = "signal OK",
    .cap_sync_none              = "no signal",
    .cap_status_fmt             = "Live capture | %s | %zu encrypted frames | %s",
    .cap_target_fmt             = "Target reached (%zu frames) - starting crack",
    .cap_dlg_title              = "Listen to a radio channel",
    .cap_intro                  = "Plug in your SDR receiver and antenna, then type the frequency you\r\nwant to listen to. The app captures encrypted calls on its own and\r\nstarts cracking once it has enough. Just press Start and wait.",
    .cap_lbl_freq               = "Radio frequency",
    .cap_freq_hint              = "In MHz - for example  461.8375",
    .cap_adv_show               = "More options",
    .cap_adv_hide               = "Fewer options",
    .cap_lbl_dev                = "SDR device number",
    .cap_hint_dev               = "Leave 0 if you have a single SDR",
    .cap_lbl_gain               = "Signal gain",
    .cap_hint_gain              = "0 = automatic (recommended)",
    .cap_lbl_ppm                = "Frequency correction",
    .cap_hint_ppm               = "Leave 0 if you are not sure",
    .cap_btn_ok                 = "Start",
    .cap_btn_cancel             = "Cancel",

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

    /* ---- Engine start errors ---- */
    .err_search_already_active = "A search is already active",
    .err_start_gt_end          = "Start key must be <= end key",
    .err_end_exceeds_40bit     = "End key exceeds 40 bits",
    .err_no_payloads_loaded    = "No payloads loaded",
    .err_pause_event_failed    = "Could not create pause event",
    .err_oom_cpu_threads       = "Out of memory allocating CPU worker threads",
    .err_create_cpu_threads    = "Error creating CPU brute-force threads",
    .err_oom_handles           = "Out of memory allocating thread handles",
    .err_create_cuda_thread    = "Error creating CUDA launcher thread",

    /* ---- Status panel format strings ---- */
    .fmt_keys_tested    = "Keys tested: %llu / %llu (%.2f%%)",
    .fmt_speed          = "Speed: %.2f keys/s",
    .fmt_time           = "Time: %s  |  ETA: %s",
    .fmt_backend        = "Backend: %s",
    .fmt_best_candidate = "Best candidate: %s",
    .fmt_best_score     = "Best score: %s",
    .fmt_status         = "Status: %s",
    .fmt_cuda_error     = "CUDA error: %s",
    .warn_gpu_not_found = "No CUDA-capable GPU was found -- the search will run on CPU only.\n\n"
                          "Details: %s\n\n"
                          "To enable GPU acceleration:\n"
                          "  1. Confirm your NVIDIA driver is installed (nvidia-smi should show your GPU).\n"
                          "  2. Install the CUDA Toolkit that matches your driver's CUDA version.\n"
                          "  3. Open an x64 Native Tools Command Prompt for VS, run build.bat,\n"
                          "     and confirm it prints BUILD SUCCEEDED.\n"
                          "  4. Verify your GPU is not in TCC mode:\n"
                          "     nvidia-smi -q | findstr \"Compute Mode\"  (must say Default).",
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

    /* ---- Help dialog ---- */
    .btn_help  = "Help",
    .help_title = "DMRCrack - Quick-Start Guide",
    .help_content =
"STEP 1 - CAPTURE AUDIO WITH SDR#\r\n"
"=================================\r\n"
"\r\n"
"  1. Open SDR# and connect to your SDR device.\r\n"
"  2. Tune to the DMR channel frequency.\r\n"
"  3. Set demodulation mode to NFM.\r\n"
"  4. Set filter bandwidth to 12500 Hz.\r\n"
"  5. UNCHECK 'Filter Audio' (or 'De-emphasis').\r\n"
"     DSD-FME needs raw discriminator output without\r\n"
"     de-emphasis. If this is not disabled, decoding fails.\r\n"
"  6. Set audio sample rate to 48000 Hz.\r\n"
"  7. Open the Audio Recorder plugin.\r\n"
"     Select recording mode 'Audio' (NOT 'Baseband').\r\n"
"     Baseband records raw IQ which DSD-FME cannot read.\r\n"
"  8. Record at least 30-60 seconds of encrypted voice.\r\n"
"     More is better: 60+ payloads recommended.\r\n"
"  9. Stop recording and note the .wav file path.\r\n"
"\r\n"
"  Other SDR programs: use NFM with de-emphasis OFF.\r\n"
"    SDR++: De-emphasis = NONE.  GQRX: 'No de-emphasis'.\r\n"
"\r\n"
"\r\n"
"STEP 2 - DEMODULATE\r\n"
"====================\r\n"
"\r\n"
"  1. Click 'Browse WAV...' and select the .wav file.\r\n"
"  2. Click 'Demodulate'.\r\n"
"  3. Wait until 'N payloads loaded' appears.\r\n"
"  4. (Optional) Click 'Export' to save the .bin file.\r\n"
"\r\n"
"\r\n"
"STEP 3 - BRUTE-FORCE\r\n"
"=====================\r\n"
"\r\n"
"  1. Set Start = 0000000000, End = FFFFFFFFFF.\r\n"
"  2. Click 'Start'.\r\n"
"  3. When the Best Score spikes (Z > 7), the key is found.\r\n"
"  4. Click 'Copy' to copy the key to the clipboard.\r\n"
"\r\n"
"\r\n"
"NOTES\r\n"
"=====\r\n"
"\r\n"
"  - NVIDIA GPU recommended. CPU fallback is much slower.\r\n"
"  - Minimum 6 payloads needed, 60+ recommended.\r\n"
"  - WAV must be mono, 48000 Hz, 16-bit PCM.\r\n",

};
