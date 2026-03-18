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
 * lang.h - Internationalization string table
 *
 * All user-visible strings are accessed through the global g_lang struct.
 * To add a new language, create lang_XX.c defining the same Lang struct
 * and link it instead of (or conditionally with) lang_en.c.
 */
#ifndef LANG_H
#define LANG_H

typedef struct {
    /* ---- Section headers ---- */
    const char *section_capture;
    const char *section_bruteforce;

    /* ---- Static labels ---- */
    const char *label_audio;
    const char *label_file;
    const char *label_start_key;
    const char *label_end_key;
    const char *label_threads;
    const char *label_samples;

    /* ---- Buttons ---- */
    const char *btn_demodulate;
    const char *btn_export;
    const char *btn_start;
    const char *btn_pause;
    const char *btn_resume;
    const char *btn_stop;
    const char *btn_ready;

    /* ---- Demodulation status / errors ---- */
    const char *status_demodulating;          /* "Demodulating with DSD-FME... [1/2]" */
    const char *status_converting;            /* "Converting DSP to BIN... [2/2]"     */
    const char *status_demod_in_memory;       /* "(demodulated in memory)"             */
    const char *err_demod_already_running;    /* "Demodulation already in progress"    */
    const char *err_demod_thread;             /* "Error creating demodulation thread"  */
    const char *err_no_audio_selected;
    const char *err_audio_not_found;
    const char *err_path_has_quotes;
    const char *err_cygwin_dlls_missing;
    const char *err_dll_not_found_exit;
    const char *err_dsd_failed;               /* "DSD-FME failed. Check .dslog.txt"   */
    const char *err_dsd_launch;               /* "Error launching DSD-FME"            */
    const char *err_no_dsp_output;
    const char *err_dsp_conversion;
    const char *err_dsd_missing;              /* "Error: missing DSD-FME (tools\dsd-fme.exe)" */
    const char *err_py_script_missing;        /* "Error: missing tools\dsdfme_dsp_to_bin.py"  */
    const char *err_bin_load;                 /* "Error loading generated BIN"                */

    /* ---- Brute-force validation errors ---- */
    const char *err_no_bin_selected;
    const char *err_start_key_invalid;
    const char *err_end_key_invalid;
    const char *err_threads_empty;
    const char *err_threads_range;            /* "Threads must be 1..64"              */
    const char *err_samples_empty;
    const char *err_samples_range;            /* "Samples must be 1..100000"          */
    const char *warn_few_payloads;            /* shown when payload count < 64        */

    /* ---- Export ---- */
    const char *err_no_payloads_export;
    const char *msg_exported;                 /* printf format: %zu lines, path       */
    const char *dlg_export_filter;            /* file-open filter string (double-NUL) */

    /* ---- Fatal / startup errors ---- */
    const char *err_wnd_class;
    const char *err_wnd_create;

    /* ---- Auto-update ---- */
    const char *update_available;   /* printf format: %s = new version string */
    const char *update_title;
    const char *update_downloading; /* "Downloading update..."                */
    const char *update_failed;      /* "Update download failed"               */
} Lang;

/* Implemented in lang_en.c (or another lang_XX.c). */
extern const Lang g_lang;

#endif /* LANG_H */
