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
 * gui.c - Modern dark-themed Win32 GUI for FSP.DMRCrack
 */
#include "../include/gui.h"

#include <commctrl.h>
#include <commdlg.h>
#include <dwmapi.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../include/bruteforce.h"
#include "../include/lang.h"
#include "../include/payload_io.h"
#include "../include/updater.h"
#include "../include/version.h"

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "dwmapi.lib")
#pragma comment(linker, "\"/manifestdependency:type='win32' " \
    "name='Microsoft.Windows.Common-Controls' version='6.0.0.0' " \
    "processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

#define APP_CLASS_NAME "FSPDMRCrackWindow"
#define APP_TITLE "FSP.DMRCrack - RC4 40-bit DMR Brute Forcer"

/* --- Control IDs --- */
#define ID_EDIT_FILE    1001
#define ID_BTN_BROWSE   1002
#define ID_EDIT_START   1003
#define ID_EDIT_END     1004
#define ID_EDIT_THREADS 1005
#define ID_EDIT_SAMPLES 1006
#define ID_BTN_START    1007
#define ID_BTN_PAUSE    1008
#define ID_BTN_STOP     1009
#define ID_STATUS_TEXT  1010
#define ID_EDIT_WAV     1011
#define ID_BTN_BROWSE_WAV 1012
#define ID_BTN_DEMOD    1013
#define ID_BTN_EXPORT   1014
#define ID_BTN_COPY_KEY 1015
#define ID_PAYLOAD_LABEL 1016
#define ID_BTN_HELP     1017
#define ID_BTN_LANG     1018
#define ID_RADIO_WAV        1019
#define ID_RADIO_RTL        1020
#define ID_EDIT_FREQ        1021
#define ID_EDIT_GAIN        1022
#define ID_EDIT_PPM         1023
#define ID_EDIT_DEVICE      1024
#define ID_COMBO_SLOT       1025
#define ID_CHK_INVERTED     1026
#define ID_BTN_STOP_CAPTURE 1027
#define ID_EDIT_GPU_PCT  1028
#define ID_SPIN_GPU      1029

#define IDT_UI_REFRESH  2001
#define WM_APP_DEMOD_DONE        (WM_APP + 1)

/* --- Dark theme colors --- */
/* --- Dark theme colors (Operator Dashboard) --- */
#define CLR_HEADER       RGB(20,  20,  21)
#define CLR_BG           RGB(26,  26,  27)
#define CLR_PANEL        RGB(37,  37,  38)
#define CLR_TILE         RGB(45,  45,  48)
#define CLR_INPUT        RGB(51,  51,  51)
#define CLR_INPUT_BORDER RGB(62,  62,  66)
#define CLR_TEXT         RGB(204, 204, 204)
#define CLR_BRIGHT       RGB(255, 255, 255)
#define CLR_DIM          RGB(100, 100, 100)
#define CLR_ACCENT       RGB(0,   122, 204)
#define CLR_ACCENT_HOV   RGB(28,  145, 235)
#define CLR_ACCENT_PRESS RGB(0,   84,  153)
#define CLR_METRIC       RGB(255, 255, 255)
#define CLR_METRIC_LABEL RGB(156, 220, 254)
#define CLR_RUNNING      RGB(78,  201, 176)
#define CLR_PAUSED       RGB(206, 145, 120)
#define CLR_STOPPED      RGB(106, 106, 106)
#define CLR_WARN         RGB(244, 71,  71)
#define CLR_GREEN        RGB(78,  201, 176)
#define CLR_ORANGE       RGB(206, 145, 120)
#define CLR_RED          RGB(244, 71,  71)
#define CLR_GRAPH_BG     RGB(37,  37,  38)
#define CLR_GRAPH_AXIS   RGB(80,  80,  80)
#define CLR_GRAPH_LINE1  RGB(86,  156, 214)
#define CLR_GRAPH_LINE2  RGB(215, 186, 125)
#define CLR_GRAPH_THRESH RGB(78,  201, 176)
#define CLR_PROGRESS_BG  RGB(45,  45,  48)
#define CLR_SECTION      RGB(0,   122, 204)

#define HEADER_H    38   /* header bar height in pixels */

/* --- Application state --- */
typedef struct {
    HWND hwnd;
    HWND edit_file;
    HWND edit_start;
    HWND edit_end;
    HWND edit_threads;
    HWND edit_samples;
    HWND btn_start;
    HWND btn_pause;
    HWND btn_stop;
    HWND edit_wav;
    HWND btn_browse_wav;
    HWND btn_demod;
    HWND btn_export;
    HWND demod_label;
    HWND btn_copy_key;
    HWND payload_label;
    HWND btn_help;
    HWND hwnd_help;
    HWND btn_lang;

    /* RTL-SDR capture controls */
    HWND radio_wav;
    HWND radio_rtl;
    HWND lbl_freq;
    HWND edit_freq;
    HWND lbl_gain;
    HWND edit_gain;
    HWND lbl_ppm;
    HWND edit_ppm;
    HWND lbl_device;
    HWND edit_device;
    HWND combo_slot;
    HWND chk_inverted;
    HWND lbl_slot;
    HWND lbl_inverted_label;
    HWND btn_stop_capture;   /* "Stop" for RTL capture */
    int  capture_mode;       /* 0=WAV, 1=RTL */

    /* Metric tile rects (painted in WM_PAINT) */
    RECT tile_throughput_rect;
    RECT tile_progress_rect;
    RECT tile_candidate_rect;
    RECT header_rect;
    RECT status_strip_rect;

    /* CPU fallback state */
    int  fallback_triggered;
    int  fallback_banner_ticks;    /* countdown in UI ticks (250ms each) */
    BruteforceConfig last_cfg;     /* saved to restart on fallback */

    /* Extra fonts */
    HFONT font_tile_metric;   /* Consolas 14pt bold */
    HFONT font_tile_label;    /* Segoe UI 8pt regular */
    HFONT font_header;        /* Segoe UI 10pt bold */
    HFONT font_header_sub;    /* Segoe UI 8pt regular */

    RECT graph_rect;
    RECT score_graph_rect;
    RECT progress_rect;

    PayloadSet payloads;
    BruteforceEngine engine;
    BruteforceSnapshot snapshot;

    double kps_history[120];
    int hist_count;
    int hist_pos;

    double score_history[120];
    int score_hist_count;
    int score_hist_pos;

    volatile LONG demod_running;
    HANDLE demod_thread;

    HFONT ui_font;
    HFONT ui_font_bold;
    HFONT ui_font_section;
    HBRUSH br_bg;
    HBRUSH br_panel;
    HBRUSH br_input;
    char loaded_file[MAX_PATH];
    char loaded_wav[MAX_PATH];
    int notified_completion;

    /* Static label HWNDs for layout */
    HWND lbl_audio;
    HWND lbl_file;
    HWND lbl_start;
    HWND lbl_end;
    HWND lbl_threads;
    HWND lbl_samples;
    HWND btn_browse_file;
    HWND edit_gpu_pct;
    HWND lbl_gpu_pct;
    HWND spin_gpu_split;
    int  gpu_split_pct;   /* 50..95, default 80 */

    HWND lbl_kpa_badge;  /* "KPA: N silence frames" — visible when n_silence > 0 */
} AppState;

static AppState g_app;

/* --- GDI helpers --- */
static void create_theme_brushes(void)
{
    g_app.br_bg    = CreateSolidBrush(CLR_BG);
    g_app.br_panel = CreateSolidBrush(CLR_PANEL);
    g_app.br_input = CreateSolidBrush(CLR_INPUT);
}

static void destroy_theme_brushes(void)
{
    if (g_app.br_bg)    { DeleteObject(g_app.br_bg);    g_app.br_bg = NULL; }
    if (g_app.br_panel) { DeleteObject(g_app.br_panel); g_app.br_panel = NULL; }
    if (g_app.br_input) { DeleteObject(g_app.br_input); g_app.br_input = NULL; }
}

static HFONT create_ui_font(int bold, int size_delta)
{
    NONCLIENTMETRICSA ncm;
    ncm.cbSize = sizeof(ncm);
    if (SystemParametersInfoA(SPI_GETNONCLIENTMETRICS, sizeof(ncm), &ncm, 0)) {
        if (bold) ncm.lfMessageFont.lfWeight = FW_SEMIBOLD;
        if (size_delta) ncm.lfMessageFont.lfHeight += size_delta;
        return CreateFontIndirectA(&ncm.lfMessageFont);
    }
    return (HFONT)GetStockObject(DEFAULT_GUI_FONT);
}

static void set_children_font(HWND parent, HFONT font)
{
    HWND child = GetWindow(parent, GW_CHILD);
    while (child) {
        SendMessageA(child, WM_SETFONT, (WPARAM)font, TRUE);
        child = GetWindow(child, GW_HWNDNEXT);
    }
}

/* --- Clipboard --- */
static void copy_key_to_clipboard(HWND hwnd)
{
    char key_str[16];
    HGLOBAL hMem;
    char *pMem;

    if (!isfinite(g_app.snapshot.best_score) || g_app.snapshot.best_score <= -1e30)
        return;

    snprintf(key_str, sizeof(key_str), "%010llX",
             (unsigned long long)(g_app.snapshot.best_key & 0xFFFFFFFFFFull));

    hMem = GlobalAlloc(GMEM_MOVEABLE, strlen(key_str) + 1);
    if (!hMem) return;
    pMem = (char *)GlobalLock(hMem);
    if (!pMem) { GlobalFree(hMem); return; }
    strcpy(pMem, key_str);
    GlobalUnlock(hMem);

    if (OpenClipboard(hwnd)) {
        EmptyClipboard();
        SetClipboardData(CF_TEXT, hMem);
        CloseClipboard();
    } else {
        GlobalFree(hMem);
    }
}

/* --- Layout: reposition controls for current window size --- */
static void layout_controls(int cw, int ch)
{
    int y, row2_y, ctrl_w, graph_h, gap;

    if (cw < 960) cw = 960;
    if (ch < 740) ch = 740;

    ctrl_w = cw - 40;

    /* Header buttons — positioned at top right inside header bar */
    if (g_app.btn_help) MoveWindow(g_app.btn_help, cw - 96,  (HEADER_H - 22) / 2, 50, 22, TRUE);
    if (g_app.btn_lang) MoveWindow(g_app.btn_lang, cw - 38,  (HEADER_H - 22) / 2, 32, 22, TRUE);

    /* CAPTURE section — left panel */
    {
        int cap_x = 20, cap_right = cw / 2 - 10;
        int cap_w = cap_right - cap_x;
        y = HEADER_H + 14;
        y += 22;  /* space for section header */

        /* Radio buttons */
        if (g_app.radio_wav) MoveWindow(g_app.radio_wav, cap_x, y, 55, 20, TRUE);
        if (g_app.radio_rtl) MoveWindow(g_app.radio_rtl, cap_x + 62, y, 75, 20, TRUE);
        y += 26;

        /* WAV controls */
        if (g_app.lbl_audio)     MoveWindow(g_app.lbl_audio,     cap_x,           y+2, 55, 18, TRUE);
        if (g_app.edit_wav)      MoveWindow(g_app.edit_wav,      cap_x+60,        y,   cap_w-98, 24, TRUE);
        if (g_app.btn_browse_wav)MoveWindow(g_app.btn_browse_wav, cap_right-34,   y,   30, 24, TRUE);

        /* RTL controls (same y, shown/hidden) */
        if (g_app.lbl_freq)   MoveWindow(g_app.lbl_freq,   cap_x,      y+2, 60, 18, TRUE);
        if (g_app.edit_freq)  MoveWindow(g_app.edit_freq,  cap_x+65,   y,   70, 24, TRUE);
        if (g_app.lbl_gain)   MoveWindow(g_app.lbl_gain,   cap_x+142,  y+2, 40, 18, TRUE);
        if (g_app.edit_gain)  MoveWindow(g_app.edit_gain,  cap_x+185,  y,   40, 24, TRUE);
        if (g_app.lbl_ppm)    MoveWindow(g_app.lbl_ppm,    cap_x+232,  y+2, 30, 18, TRUE);
        if (g_app.edit_ppm)   MoveWindow(g_app.edit_ppm,   cap_x+264,  y,   40, 24, TRUE);
        if (g_app.lbl_device) MoveWindow(g_app.lbl_device, cap_x+310,  y+2, 50, 18, TRUE);
        if (g_app.edit_device)MoveWindow(g_app.edit_device,cap_x+360,  y,   35, 24, TRUE);
        y += 30;

        /* Slot + Inverted row */
        if (g_app.lbl_slot)         MoveWindow(g_app.lbl_slot,         cap_x,      y+2,  30, 18, TRUE);
        if (g_app.combo_slot)       MoveWindow(g_app.combo_slot,       cap_x+35,   y,    80, 120, TRUE);
        if (g_app.lbl_inverted_label)MoveWindow(g_app.lbl_inverted_label,cap_x+122, y+2, 50, 18, TRUE);
        if (g_app.chk_inverted)     MoveWindow(g_app.chk_inverted,     cap_x+175,  y,    20, 20, TRUE);
        y += 28;

        /* Buttons row */
        if (g_app.btn_demod)        MoveWindow(g_app.btn_demod,        cap_x,       y, 100, 28, TRUE);
        if (g_app.btn_stop_capture) MoveWindow(g_app.btn_stop_capture, cap_x+108,   y,  60, 28, TRUE);
        if (g_app.btn_export)       MoveWindow(g_app.btn_export,       cap_x+176,   y,  60, 28, TRUE);
        y += 32;

        /* Demod status label */
        if (g_app.demod_label) MoveWindow(g_app.demod_label, cap_x, y, cap_w, 16, TRUE);
    }

    /* BRUTE FORCE section — right panel */
    {
        int bf_x = cw / 2 + 10, bf_right = cw - 20;
        int bf_w = bf_right - bf_x;
        int yb = HEADER_H + 14;
        yb += 22;  /* section header space */

        /* .bin file row */
        if (g_app.lbl_file)        MoveWindow(g_app.lbl_file,        bf_x,        yb+2, 40, 18, TRUE);
        if (g_app.edit_file)       MoveWindow(g_app.edit_file,       bf_x+45,     yb,   bf_w-82, 24, TRUE);
        if (g_app.btn_browse_file) MoveWindow(g_app.btn_browse_file, bf_right-32, yb,   30, 24, TRUE);
        yb += 28;
        /* Payload label + KPA badge (same row, badge right-aligned) */
        if (g_app.payload_label) MoveWindow(g_app.payload_label, bf_x, yb, bf_w - 130, 16, TRUE);
        if (g_app.lbl_kpa_badge) MoveWindow(g_app.lbl_kpa_badge, bf_right - 125, yb, 125, 16, FALSE);
        yb += 22;

        /* Key range row */
        if (g_app.lbl_start) MoveWindow(g_app.lbl_start, bf_x,      yb+2, 35, 18, TRUE);
        if (g_app.edit_start)MoveWindow(g_app.edit_start, bf_x+38,   yb,  100, 24, TRUE);
        if (g_app.lbl_end)   MoveWindow(g_app.lbl_end,    bf_x+145,  yb+2, 20, 18, TRUE);
        if (g_app.edit_end)  MoveWindow(g_app.edit_end,   bf_x+168,  yb,  100, 24, TRUE);
        yb += 30;

        /* GPU% + Hilos + Muestras — single row */
        if (g_app.lbl_gpu_pct)  MoveWindow(g_app.lbl_gpu_pct,  bf_x,        yb+2, 38, 18, TRUE);
        if (g_app.edit_gpu_pct) MoveWindow(g_app.edit_gpu_pct, bf_x+40,     yb,   48, 24, TRUE);
        if (g_app.lbl_threads)  MoveWindow(g_app.lbl_threads,  bf_x+98,     yb+2, 40, 18, TRUE);
        if (g_app.edit_threads) MoveWindow(g_app.edit_threads, bf_x+142,    yb,   38, 24, TRUE);
        if (g_app.lbl_samples)  MoveWindow(g_app.lbl_samples,  bf_x+188,    yb+2, 55, 18, TRUE);
        if (g_app.edit_samples) MoveWindow(g_app.edit_samples, bf_x+248,    yb,   55, 24, TRUE);
        yb += 32;

        /* Action buttons row */
        if (g_app.btn_start)    MoveWindow(g_app.btn_start,    bf_x,      yb,  90, 30, TRUE);
        if (g_app.btn_pause)    MoveWindow(g_app.btn_pause,    bf_x+98,   yb,  90, 30, TRUE);
        if (g_app.btn_stop)     MoveWindow(g_app.btn_stop,     bf_x+196,  yb,  90, 30, TRUE);
        if (g_app.btn_copy_key) MoveWindow(g_app.btn_copy_key, bf_x+294,  yb,  65, 30, TRUE);

        row2_y = yb;
    }

    /* Metric tiles row: below both panels */
    {
        int tile_y = row2_y + 12;
        int tile_h = 80;
        int tile_gap = 8;
        int tile_total = cw - 40;
        /* Throughput: 22%, Progress: 46%, Candidate: 32% */
        int tile_w1 = (tile_total * 22) / 100;
        int tile_w3 = (tile_total * 32) / 100;
        int tile_w2 = tile_total - tile_w1 - tile_w3 - tile_gap * 2;

        g_app.tile_throughput_rect.left   = 20;
        g_app.tile_throughput_rect.top    = tile_y;
        g_app.tile_throughput_rect.right  = 20 + tile_w1;
        g_app.tile_throughput_rect.bottom = tile_y + tile_h;

        g_app.tile_progress_rect.left   = 20 + tile_w1 + tile_gap;
        g_app.tile_progress_rect.top    = tile_y;
        g_app.tile_progress_rect.right  = 20 + tile_w1 + tile_gap + tile_w2;
        g_app.tile_progress_rect.bottom = tile_y + tile_h;

        g_app.tile_candidate_rect.left   = 20 + tile_w1 + tile_gap + tile_w2 + tile_gap;
        g_app.tile_candidate_rect.top    = tile_y;
        g_app.tile_candidate_rect.right  = cw - 20;
        g_app.tile_candidate_rect.bottom = tile_y + tile_h;

        /* Status strip below tiles */
        int strip_y = tile_y + tile_h + 6;
        g_app.status_strip_rect.left   = 20;
        g_app.status_strip_rect.top    = strip_y;
        g_app.status_strip_rect.right  = cw - 20;
        g_app.status_strip_rect.bottom = strip_y + 18;

        y = strip_y + 18;
    }

    /* Graphs: side by side below tiles + strip */
    {
        int graph_y = y + 10;
        graph_h = ch - graph_y - 35 - 6;
        if (graph_h < 80) graph_h = 80;
        int graph_mid = cw / 2 - 5;

        g_app.graph_rect.left   = 20;
        g_app.graph_rect.top    = graph_y;
        g_app.graph_rect.right  = graph_mid;
        g_app.graph_rect.bottom = graph_y + graph_h;

        g_app.score_graph_rect.left   = graph_mid + 10;
        g_app.score_graph_rect.top    = graph_y;
        g_app.score_graph_rect.right  = cw - 20;
        g_app.score_graph_rect.bottom = graph_y + graph_h;

        /* Progress bar at bottom */
        g_app.progress_rect.left   = 20;
        g_app.progress_rect.top    = graph_y + graph_h + 8;
        g_app.progress_rect.right  = cw - 20;
        g_app.progress_rect.bottom = g_app.progress_rect.top + 22;
    }
}

/* --- Utility --- */
static int parse_hex40(const char *txt, uint64_t *out)
{
    char *end = NULL;
    unsigned long long v;
    if (!txt || strlen(txt) == 0 || strlen(txt) > 10) return 0;
    v = strtoull(txt, &end, 16);
    if (!end || *end != '\0' || v > 0xFFFFFFFFFFull) return 0;
    *out = (uint64_t)v;
    return 1;
}

static void fmt_hhmmss(double seconds, char *out, size_t out_len)
{
    if (seconds < 0.0 || !isfinite(seconds)) {
        snprintf(out, out_len, "--:--:--");
        return;
    }
    {
        unsigned long long total = (unsigned long long)(seconds + 0.5);
        snprintf(out, out_len, "%02llu:%02llu:%02llu",
                 total / 3600ull, (total % 3600ull) / 60ull, total % 60ull);
    }
}

static void update_status_text(void)
{
    char eta[32], elapsed[32], score_buf[64], best_key_buf[32], text[1024];
    double pct = 0.0;
    const char *cuda_stage = "INIT";
    LONG stage_v = InterlockedCompareExchange(&g_app.engine.cuda_stage, 0, 0);
    LONG profile_cached = InterlockedCompareExchange(&g_app.engine.cuda_profile_cached, 0, 0);
    LONG tpb = InterlockedCompareExchange(&g_app.engine.cuda_tpb, 0, 0);
    LONG bpsm = InterlockedCompareExchange(&g_app.engine.cuda_bpsm, 0, 0);
    LONG chunk_mult = InterlockedCompareExchange(&g_app.engine.cuda_chunk_mult, 0, 0);

    if (stage_v == 1) cuda_stage = "AUTOTUNE";
    else if (stage_v == 2) cuda_stage = "SCANNING";
    else if (stage_v == 3) cuda_stage = "DONE";
    else if (stage_v == 4) cuda_stage = "DICT";

    fmt_hhmmss(g_app.snapshot.elapsed_seconds, elapsed, sizeof(elapsed));
    fmt_hhmmss(g_app.snapshot.eta_seconds, eta, sizeof(eta));

    if (g_app.snapshot.total_keys > 0)
        pct = ((double)g_app.snapshot.keys_tested * 100.0) / (double)g_app.snapshot.total_keys;

    if (!isfinite(g_app.snapshot.best_score) || g_app.snapshot.best_score <= -1e30) {
        strcpy_s(best_key_buf, sizeof(best_key_buf), "----------");
    } else {
        snprintf(best_key_buf, sizeof(best_key_buf), "%010llX",
                 (unsigned long long)(g_app.snapshot.best_key & 0xFFFFFFFFFFull));
    }

    {
        char line[256];
        int pos = 0;
        snprintf(line, sizeof(line), g_lang.fmt_keys_tested,
                 (unsigned long long)g_app.snapshot.keys_tested,
                 (unsigned long long)g_app.snapshot.total_keys, pct);
        pos = (int)strlen(text);
        snprintf(text + pos, sizeof(text) - pos, "%s\r\n", line);

        snprintf(line, sizeof(line), g_lang.fmt_speed, g_app.snapshot.keys_per_second);
        pos = (int)strlen(text);
        snprintf(text + pos, sizeof(text) - pos, "%s\r\n", line);

        snprintf(line, sizeof(line), g_lang.fmt_time, elapsed, eta);
        pos = (int)strlen(text);
        snprintf(text + pos, sizeof(text) - pos, "%s\r\n", line);

        snprintf(line, sizeof(line), g_lang.fmt_backend,
                 g_app.engine.cuda_active ? "CUDA GPU" : "CPU");
        pos = (int)strlen(text);
        snprintf(text + pos, sizeof(text) - pos, "%s\r\n", line);

        snprintf(line, sizeof(line), g_lang.fmt_best_candidate, best_key_buf);
        pos = (int)strlen(text);
        snprintf(text + pos, sizeof(text) - pos, "%s\r\n", line);

        snprintf(line, sizeof(line), g_lang.fmt_best_score,
                 (!isfinite(g_app.snapshot.best_score) || g_app.snapshot.best_score <= -1e30) ? "---" :
                     (snprintf(score_buf, sizeof(score_buf), "%.4f", g_app.snapshot.best_score), score_buf));
        pos = (int)strlen(text);
        snprintf(text + pos, sizeof(text) - pos, "%s\r\n", line);

        snprintf(line, sizeof(line), g_lang.fmt_status,
                 g_app.snapshot.running ? (g_app.snapshot.paused ? g_lang.state_paused : g_lang.state_running) : g_lang.state_stopped);
        pos = (int)strlen(text);
        snprintf(text + pos, sizeof(text) - pos, "%s", line);
    }

    if (g_app.engine.cuda_active && g_app.engine.cuda_device_name[0]) {
        LONG sm_count = InterlockedCompareExchange(&g_app.engine.cuda_sm_count, 0, 0);
        LONG cc_major = InterlockedCompareExchange(&g_app.engine.cuda_compute_major, 0, 0);
        LONG cc_minor = InterlockedCompareExchange(&g_app.engine.cuda_compute_minor, 0, 0);
        if (sm_count > 0 && cc_major > 0)
            snprintf(text + strlen(text), sizeof(text) - strlen(text),
                     "\r\nGPU: %s (sm_%ld%ld, %ld SMs)",
                     g_app.engine.cuda_device_name, cc_major, cc_minor, sm_count);
        else
            snprintf(text + strlen(text), sizeof(text) - strlen(text),
                     "\r\nGPU: %s", g_app.engine.cuda_device_name);
    }

    if (g_app.engine.cuda_active) {
        snprintf(text + strlen(text), sizeof(text) - strlen(text),
                 "\r\nCUDA stage: %s  | profile: %s",
                 cuda_stage, profile_cached ? "CACHE" : "TUNED");
        if (tpb > 0 && bpsm > 0 && chunk_mult > 0) {
            snprintf(text + strlen(text), sizeof(text) - strlen(text),
                     "\r\nLaunch: TPB=%ld BPSM=%ld CHUNK=%ld",
                     tpb, bpsm, chunk_mult);
        }
    }

    if (g_app.engine.cuda_error[0])
        snprintf(text + strlen(text), sizeof(text) - strlen(text),
                 "\r\n");
        {
            char cuda_err_line[300];
            snprintf(cuda_err_line, sizeof(cuda_err_line), g_lang.fmt_cuda_error, g_app.engine.cuda_error);
            snprintf(text + strlen(text), sizeof(text) - strlen(text), "%s", cuda_err_line);
        }

    (void)text; /* status_text removed; replaced by painted tiles in Task 7 */
}

/* --- Drawing: header bar --- */
static void draw_header(HDC hdc, int cw)
{
    RECT r = { 0, 0, cw, HEADER_H };
    HBRUSH hdr_br = CreateSolidBrush(CLR_HEADER);
    FillRect(hdc, &r, hdr_br);
    DeleteObject(hdr_br);

    /* Bottom border line */
    {
        HPEN pen = CreatePen(PS_SOLID, 1, CLR_ACCENT);
        HPEN old = (HPEN)SelectObject(hdc, pen);
        MoveToEx(hdc, 0, HEADER_H - 1, NULL);
        LineTo(hdc, cw, HEADER_H - 1);
        SelectObject(hdc, old);
        DeleteObject(pen);
    }

    SetBkMode(hdc, TRANSPARENT);

    /* App name */
    {
        HFONT old = (HFONT)SelectObject(hdc, g_app.font_header);
        SetTextColor(hdc, CLR_BRIGHT);
        RECT tr = { 12, 0, 300, HEADER_H };
        DrawTextA(hdc, "FSP.DMRCrack", -1, &tr, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
        SelectObject(hdc, old);
    }

    /* GPU info (center) */
    if (g_app.engine.cuda_active && g_app.engine.cuda_device_name[0]) {
        char gpu_info[256];
        LONG cc_maj = InterlockedCompareExchange(&g_app.engine.cuda_compute_major, 0, 0);
        LONG cc_min = InterlockedCompareExchange(&g_app.engine.cuda_compute_minor, 0, 0);
        LONG sm_cnt = InterlockedCompareExchange(&g_app.engine.cuda_sm_count, 0, 0);
        LONG stage  = InterlockedCompareExchange(&g_app.engine.cuda_stage, 0, 0);
        COLORREF dot_clr = (stage == 2) ? CLR_RUNNING :
                           (stage == 3) ? CLR_STOPPED : CLR_PAUSED;
        if (cc_maj > 0 && sm_cnt > 0)
            snprintf(gpu_info, sizeof(gpu_info), "%s  \xb7  sm_%ld%ld  \xb7  %ld SMs",
                     g_app.engine.cuda_device_name, cc_maj, cc_min, sm_cnt);
        else
            snprintf(gpu_info, sizeof(gpu_info), "%s", g_app.engine.cuda_device_name);

        HFONT old = (HFONT)SelectObject(hdc, g_app.font_header_sub);
        RECT tr = { 200, 0, cw - 100, HEADER_H };

        /* Colored dot */
        {
            HBRUSH dot_br = CreateSolidBrush(dot_clr);
            RECT dot_r = { 200, (HEADER_H - 8) / 2, 208, (HEADER_H - 8) / 2 + 8 };
            FillRect(hdc, &dot_r, dot_br);
            DeleteObject(dot_br);
        }
        tr.left = 214;
        SetTextColor(hdc, CLR_DIM);
        DrawTextA(hdc, gpu_info, -1, &tr, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
        SelectObject(hdc, old);
    }
}

/* --- Drawing: section header --- */
static void draw_section_header(HDC hdc, int x, int y, int w, const char *label)
{
    HFONT old = (HFONT)SelectObject(hdc, g_app.ui_font_section);
    RECT r = { x, y, x + w, y + 22 };
    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, CLR_ACCENT);
    DrawTextA(hdc, label, -1, &r, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    SelectObject(hdc, old);
    /* underline */
    {
        HPEN pen = CreatePen(PS_SOLID, 1, CLR_ACCENT);
        HPEN old_pen = (HPEN)SelectObject(hdc, pen);
        MoveToEx(hdc, x, y + 20, NULL);
        LineTo(hdc, x + w, y + 20);
        SelectObject(hdc, old_pen);
        DeleteObject(pen);
    }
}

/* --- Drawing: metric tiles --- */
static void draw_tile(HDC hdc, const RECT *r,
                      const char *title, const char *primary,
                      const char *line2,  const char *line3)
{
    HBRUSH bg = CreateSolidBrush(CLR_TILE);
    FillRect(hdc, r, bg);
    DeleteObject(bg);

    { HPEN pen = CreatePen(PS_SOLID, 2, CLR_ACCENT);
      HPEN old = (HPEN)SelectObject(hdc, pen);
      MoveToEx(hdc, r->left, r->top + 1, NULL);
      LineTo(hdc, r->right, r->top + 1);
      SelectObject(hdc, old);
      DeleteObject(pen); }

    SetBkMode(hdc, TRANSPARENT);
    int x = r->left + 10, w = r->right - r->left - 20;

    { HFONT old = (HFONT)SelectObject(hdc, g_app.font_tile_label);
      SetTextColor(hdc, CLR_METRIC_LABEL);
      RECT tr = { x, r->top + 6, x + w, r->top + 18 };
      DrawTextA(hdc, title, -1, &tr, DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS);
      SelectObject(hdc, old); }

    { HFONT old = (HFONT)SelectObject(hdc, g_app.font_tile_metric);
      SetTextColor(hdc, CLR_METRIC);
      RECT tr = { x, r->top + 20, x + w, r->top + 46 };
      DrawTextA(hdc, primary, -1, &tr, DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS);
      SelectObject(hdc, old); }

    { HFONT old = (HFONT)SelectObject(hdc, g_app.font_tile_label);
      SetTextColor(hdc, CLR_DIM);
      if (line2 && line2[0]) {
          RECT tr = { x, r->top + 50, x + w, r->top + 63 };
          DrawTextA(hdc, line2, -1, &tr, DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS);
      }
      if (line3 && line3[0]) {
          RECT tr = { x, r->top + 64, x + w, r->top + 77 };
          DrawTextA(hdc, line3, -1, &tr, DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS);
      }
      SelectObject(hdc, old); }
}

static void draw_progress_tile(HDC hdc, const RECT *r,
                                const char *title, double pct,
                                const char *line2,  const char *line3)
{
    HBRUSH bg = CreateSolidBrush(CLR_TILE);
    FillRect(hdc, r, bg);
    DeleteObject(bg);

    { HPEN pen = CreatePen(PS_SOLID, 2, CLR_ACCENT);
      HPEN old = (HPEN)SelectObject(hdc, pen);
      MoveToEx(hdc, r->left, r->top + 1, NULL);
      LineTo(hdc, r->right, r->top + 1);
      SelectObject(hdc, old);
      DeleteObject(pen); }

    SetBkMode(hdc, TRANSPARENT);
    int x = r->left + 10, w = r->right - r->left - 20;

    { HFONT old = (HFONT)SelectObject(hdc, g_app.font_tile_label);
      SetTextColor(hdc, CLR_METRIC_LABEL);
      RECT tr = { x, r->top + 6, x + w, r->top + 18 };
      DrawTextA(hdc, title, -1, &tr, DT_LEFT | DT_SINGLELINE);
      SelectObject(hdc, old); }

    { RECT bar = { x, r->top + 22, x + w, r->top + 34 };
      HBRUSH bar_bg = CreateSolidBrush(CLR_PROGRESS_BG);
      FillRect(hdc, &bar, bar_bg);
      DeleteObject(bar_bg);
      if (pct > 0.0) {
          if (pct > 1.0) pct = 1.0;
          RECT fill = bar;
          fill.right = bar.left + (int)((bar.right - bar.left) * pct);
          HBRUSH fill_br = CreateSolidBrush(CLR_ACCENT);
          FillRect(hdc, &fill, fill_br);
          DeleteObject(fill_br);
      } }

    { char pct_str[32];
      snprintf(pct_str, sizeof(pct_str), "%.1f%%", pct * 100.0);
      HFONT old = (HFONT)SelectObject(hdc, g_app.font_tile_metric);
      SetTextColor(hdc, CLR_METRIC);
      RECT tr = { x, r->top + 38, x + w, r->top + 60 };
      DrawTextA(hdc, pct_str, -1, &tr, DT_LEFT | DT_SINGLELINE);
      SelectObject(hdc, old); }

    { HFONT old = (HFONT)SelectObject(hdc, g_app.font_tile_label);
      SetTextColor(hdc, CLR_DIM);
      if (line2 && line2[0]) {
          RECT tr = { x, r->top + 56, x + w, r->top + 69 };
          DrawTextA(hdc, line2, -1, &tr, DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS);
      }
      if (line3 && line3[0]) {
          RECT tr = { x, r->top + 70, x + w, r->top + 80 };
          DrawTextA(hdc, line3, -1, &tr, DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS);
      }
      SelectObject(hdc, old); }
}

static void draw_all_tiles(HDC hdc)
{
    char primary[64], line2[80], line3[80];
    double pct = 0.0;

    /* THROUGHPUT tile */
    {
        double total_kps = g_app.snapshot.keys_per_second;
        double gpu_frac  = (g_app.snapshot.keys_tested > 0)
            ? (double)g_app.snapshot.gpu_keys_tested / (double)g_app.snapshot.keys_tested
            : (g_app.engine.cuda_active ? 1.0 : 0.0);
        double gpu_kps = total_kps * gpu_frac;
        double cpu_kps = total_kps * (1.0 - gpu_frac);

        if      (total_kps >= 1e9) snprintf(primary, sizeof(primary), "%.2f G/s", total_kps/1e9);
        else if (total_kps >= 1e6) snprintf(primary, sizeof(primary), "%.1f M/s", total_kps/1e6);
        else if (total_kps >= 1e3) snprintf(primary, sizeof(primary), "%.0f K/s", total_kps/1e3);
        else                       snprintf(primary, sizeof(primary), "%.0f /s",  total_kps);

        if (g_app.engine.cuda_active) {
            char g[32], c[32];
            if (gpu_kps >= 1e6) snprintf(g, sizeof(g), "%.1f M/s", gpu_kps/1e6);
            else snprintf(g, sizeof(g), "%.0f K/s", gpu_kps/1e3);
            if (cpu_kps >= 1e3) snprintf(c, sizeof(c), "%.0f K/s", cpu_kps/1e3);
            else snprintf(c, sizeof(c), "%.0f /s", cpu_kps);
            snprintf(line2, sizeof(line2), "GPU  %s", g);
            snprintf(line3, sizeof(line3), "CPU  %s", c);
        } else {
            snprintf(line2, sizeof(line2), "CPU only");
            line3[0] = '\0';
        }
        draw_tile(hdc, &g_app.tile_throughput_rect,
                  g_lang.tile_throughput, primary, line2, line3);
    }

    /* PROGRESS tile */
    {
        if (g_app.snapshot.total_keys > 0)
            pct = (double)g_app.snapshot.keys_tested / (double)g_app.snapshot.total_keys;
        if (pct > 1.0) pct = 1.0;

        char keys_str[64], eta_str[64], elapsed_str[64];
        double tk = (double)g_app.snapshot.total_keys;
        double kk = (double)g_app.snapshot.keys_tested;
        if (tk >= 1e12)
            snprintf(keys_str, sizeof(keys_str), "%.1fT / %.2fT keys", kk/1e12, tk/1e12);
        else if (tk >= 1e9)
            snprintf(keys_str, sizeof(keys_str), "%.1fG / %.2fG keys", kk/1e9, tk/1e9);
        else
            snprintf(keys_str, sizeof(keys_str), "%.1fM / %.1fM keys", kk/1e6, tk/1e6);

        fmt_hhmmss(g_app.snapshot.elapsed_seconds, elapsed_str, sizeof(elapsed_str));
        fmt_hhmmss(g_app.snapshot.eta_seconds, eta_str, sizeof(eta_str));
        snprintf(line2, sizeof(line2), "%s", keys_str);
        snprintf(line3, sizeof(line3), "ETA %s   Elapsed %s", eta_str, elapsed_str);

        draw_progress_tile(hdc, &g_app.tile_progress_rect,
                           g_lang.tile_progress, pct, line2, line3);
    }

    /* CANDIDATE tile */
    {
        if (!isfinite(g_app.snapshot.best_score) || g_app.snapshot.best_score <= -1e30) {
            strcpy_s(primary, sizeof(primary), "----------");
            line2[0] = '\0';
        } else {
            unsigned long long k = g_app.snapshot.best_key & 0xFFFFFFFFFFull;
            snprintf(primary, sizeof(primary), "%04llX %04llX %02llX",
                     (k >> 24) & 0xFFFF, (k >> 8) & 0xFFFF, k & 0xFF);
            snprintf(line2, sizeof(line2), "Score  %.2f", g_app.snapshot.best_score);
        }
        line3[0] = '\0';
        draw_tile(hdc, &g_app.tile_candidate_rect,
                  g_lang.tile_candidate, primary, line2, line3);
    }
}

static void draw_status_strip(HDC hdc)
{
    const RECT *r = &g_app.status_strip_rect;
    HBRUSH bg = CreateSolidBrush(CLR_BG);
    FillRect(hdc, r, bg);
    DeleteObject(bg);
    SetBkMode(hdc, TRANSPARENT);
    HFONT old_f = (HFONT)SelectObject(hdc, g_app.font_tile_label);

    int running = g_app.snapshot.running;
    int paused  = g_app.snapshot.paused;
    COLORREF dot_clr = running ? (paused ? CLR_PAUSED : CLR_RUNNING) : CLR_STOPPED;
    const char *state_str = running
        ? (paused ? g_lang.state_paused : g_lang.state_running)
        : g_lang.state_stopped;

    { HBRUSH dot_br = CreateSolidBrush(dot_clr);
      int dy = r->top + (r->bottom - r->top - 8) / 2;
      RECT dot = { r->left, dy, r->left + 8, dy + 8 };
      FillRect(hdc, &dot, dot_br);
      DeleteObject(dot_br); }

    { char strip[512];
      LONG stage_v = InterlockedCompareExchange(&g_app.engine.cuda_stage, 0, 0);
      LONG tpb     = InterlockedCompareExchange(&g_app.engine.cuda_tpb, 0, 0);
      LONG bpsm    = InterlockedCompareExchange(&g_app.engine.cuda_bpsm, 0, 0);
      LONG chunk   = InterlockedCompareExchange(&g_app.engine.cuda_chunk_mult, 0, 0);
      const char *stage_s = (stage_v==1) ? "AUTOTUNE" :
                            (stage_v==2) ? "SCANNING" :
                            (stage_v==3) ? "DONE"     : "INIT";
      const char *backend = g_app.engine.cuda_active
          ? g_lang.status_backend_cuda : g_lang.status_backend_cpu;

      if (g_app.fallback_banner_ticks > 0)
          snprintf(strip, sizeof(strip), "%s  \xb7  %s  \xb7  %s",
                   state_str, g_lang.msg_cuda_fallback, backend);
      else if (g_app.engine.cuda_active && tpb > 0)
          snprintf(strip, sizeof(strip),
                   "%s  \xb7  %s  \xb7  Stage: %s  \xb7  TPB=%ld  BPSM=%ld  CHUNK=%ld",
                   state_str, backend, stage_s, tpb, bpsm, chunk);
      else
          snprintf(strip, sizeof(strip), "%s  \xb7  %s", state_str, backend);

      SetTextColor(hdc, CLR_DIM);
      RECT tr = { r->left + 14, r->top, r->right, r->bottom };
      DrawTextA(hdc, strip, -1, &tr, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS); }

    SelectObject(hdc, old_f);
}

/* --- Drawing: graphs --- */
static void draw_graph(HDC hdc, const RECT *rect)
{
    HBRUSH bg = CreateSolidBrush(CLR_GRAPH_BG);
    HPEN axis_pen = CreatePen(PS_SOLID, 1, CLR_GRAPH_AXIS);
    HPEN line_pen = CreatePen(PS_SOLID, 2, CLR_GRAPH_LINE1);
    int i;
    double max_val = 1.0;

    FillRect(hdc, rect, bg);
    DeleteObject(bg);

    SelectObject(hdc, axis_pen);
    MoveToEx(hdc, rect->left + 30, rect->bottom - 25, NULL);
    LineTo(hdc, rect->right - 10, rect->bottom - 25);
    MoveToEx(hdc, rect->left + 30, rect->top + 10, NULL);
    LineTo(hdc, rect->left + 30, rect->bottom - 25);

    for (i = 0; i < g_app.hist_count; ++i) {
        double v = g_app.kps_history[(g_app.hist_pos + i) % 120];
        if (v > max_val) max_val = v;
    }

    /* Grid lines at 25%, 50%, 75% */
    {
        HPEN grid_pen = CreatePen(PS_DOT, 1, RGB(55, 55, 58));
        HPEN old_pen2 = (HPEN)SelectObject(hdc, grid_pen);
        int gh = rect->bottom - rect->top - 40;
        int gi;
        SetBkMode(hdc, TRANSPARENT);
        SetTextColor(hdc, CLR_DIM);
        for (gi = 1; gi <= 3; ++gi) {
            int gy = rect->bottom - 25 - (gh * gi) / 4;
            char tick[32];
            double tv = max_val * gi / 4.0;
            MoveToEx(hdc, rect->left + 31, gy, NULL);
            LineTo(hdc, rect->right - 10, gy);
            if (tv >= 1e9) snprintf(tick, sizeof(tick), "%.0fG", tv / 1e9);
            else if (tv >= 1e6) snprintf(tick, sizeof(tick), "%.0fM", tv / 1e6);
            else if (tv >= 1e3) snprintf(tick, sizeof(tick), "%.0fK", tv / 1e3);
            else snprintf(tick, sizeof(tick), "%.0f", tv);
            TextOutA(hdc, rect->left + 2, gy - 7, tick, (int)strlen(tick));
        }
        SelectObject(hdc, old_pen2);
        DeleteObject(grid_pen);
    }

    /* Area fill under the line */
    if (g_app.hist_count > 1) {
        int n = g_app.hist_count;
        POINT *pts = (POINT *)malloc((n + 2) * sizeof(POINT));
        if (pts) {
            int axis_y = rect->bottom - 25;
            int w = rect->right - rect->left - 45;
            int gh = rect->bottom - rect->top - 40;
            pts[0].x = rect->left + 30;
            pts[0].y = axis_y;
            for (int pi = 0; pi < n; pi++) {
                double v = g_app.kps_history[(g_app.hist_pos + pi) % 120];
                pts[pi+1].x = rect->left + 30 + (pi * w) / (n - 1);
                pts[pi+1].y = axis_y - (int)((v / max_val) * gh);
            }
            pts[n+1].x = pts[n].x;
            pts[n+1].y = axis_y;
            HBRUSH fill_br = CreateSolidBrush(RGB(40, 80, 130));
            HBRUSH old_br = (HBRUSH)SelectObject(hdc, fill_br);
            HPEN null_pen = (HPEN)GetStockObject(NULL_PEN);
            HPEN old_pen = (HPEN)SelectObject(hdc, null_pen);
            Polygon(hdc, pts, n + 2);
            SelectObject(hdc, old_br);
            SelectObject(hdc, old_pen);
            DeleteObject(fill_br);
            free(pts);
        }
    }

    if (g_app.hist_count > 1) {
        SelectObject(hdc, line_pen);
        for (i = 0; i < g_app.hist_count; ++i) {
            double v = g_app.kps_history[(g_app.hist_pos + i) % 120];
            int x = rect->left + 30 + (i * (rect->right - rect->left - 45)) / (g_app.hist_count - 1);
            int y = rect->bottom - 25 - (int)((v / max_val) * (rect->bottom - rect->top - 40));
            if (i == 0) MoveToEx(hdc, x, y, NULL);
            else LineTo(hdc, x, y);
        }
    }

    DeleteObject(axis_pen);
    DeleteObject(line_pen);

    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, CLR_GRAPH_LINE1);
    TextOutA(hdc, rect->left + 35, rect->top + 6, g_lang.graph_keys_title, (int)strlen(g_lang.graph_keys_title));
    /* Current value top-right */
    if (g_app.hist_count > 0) {
        char val[32];
        double last = g_app.kps_history[(g_app.hist_pos + g_app.hist_count - 1) % 120];
        if (last >= 1e9) snprintf(val, sizeof(val), "%.1f G/s", last / 1e9);
        else if (last >= 1e6) snprintf(val, sizeof(val), "%.1f M/s", last / 1e6);
        else if (last >= 1e3) snprintf(val, sizeof(val), "%.1f K/s", last / 1e3);
        else snprintf(val, sizeof(val), "%.0f /s", last);
        SetTextColor(hdc, CLR_BRIGHT);
        TextOutA(hdc, rect->right - 100, rect->top + 6, val, (int)strlen(val));
    }

    /* Border */
    {
        HPEN bpen = CreatePen(PS_SOLID, 1, RGB(55, 55, 58));
        HPEN old_p = (HPEN)SelectObject(hdc, bpen);
        HBRUSH null_b = (HBRUSH)GetStockObject(NULL_BRUSH);
        HBRUSH old_b = (HBRUSH)SelectObject(hdc, null_b);
        Rectangle(hdc, rect->left, rect->top, rect->right, rect->bottom);
        SelectObject(hdc, old_p);
        SelectObject(hdc, old_b);
        DeleteObject(bpen);
    }
}

static void draw_score_graph(HDC hdc, const RECT *rect)
{
    HBRUSH bg = CreateSolidBrush(CLR_GRAPH_BG);
    HPEN axis_pen = CreatePen(PS_SOLID, 1, CLR_GRAPH_AXIS);
    HPEN line_pen = CreatePen(PS_SOLID, 2, CLR_GRAPH_LINE2);
    HPEN thresh_pen = CreatePen(PS_DOT, 1, CLR_GRAPH_THRESH);
    int i;
    double max_val = 1.0;

    FillRect(hdc, rect, bg);
    DeleteObject(bg);

    SelectObject(hdc, axis_pen);
    MoveToEx(hdc, rect->left + 30, rect->bottom - 25, NULL);
    LineTo(hdc, rect->right - 10, rect->bottom - 25);
    MoveToEx(hdc, rect->left + 30, rect->top + 10, NULL);
    LineTo(hdc, rect->left + 30, rect->bottom - 25);

    for (i = 0; i < g_app.score_hist_count; ++i) {
        double v = g_app.score_history[(g_app.score_hist_pos + i) % 120];
        if (v > max_val) max_val = v;
    }

    /* Grid lines at 25%, 50%, 75% */
    {
        HPEN grid_pen = CreatePen(PS_DOT, 1, RGB(55, 55, 58));
        HPEN old_pen2 = (HPEN)SelectObject(hdc, grid_pen);
        int gh = rect->bottom - rect->top - 40;
        int gi;
        SetBkMode(hdc, TRANSPARENT);
        SetTextColor(hdc, CLR_DIM);
        for (gi = 1; gi <= 3; ++gi) {
            int gy = rect->bottom - 25 - (gh * gi) / 4;
            char tick[32];
            double tv = max_val * gi / 4.0;
            MoveToEx(hdc, rect->left + 31, gy, NULL);
            LineTo(hdc, rect->right - 10, gy);
            snprintf(tick, sizeof(tick), "%.0f", tv);
            TextOutA(hdc, rect->left + 2, gy - 7, tick, (int)strlen(tick));
        }
        SelectObject(hdc, old_pen2);
        DeleteObject(grid_pen);
    }

    if (max_val > 0.0) {
        double thresh_norm = 400.0 / max_val;
        if (thresh_norm <= 1.0) {
            int ty = rect->bottom - 25 - (int)(thresh_norm * (rect->bottom - rect->top - 40));
            SelectObject(hdc, thresh_pen);
            MoveToEx(hdc, rect->left + 30, ty, NULL);
            LineTo(hdc, rect->right - 10, ty);
        }
    }

    if (g_app.score_hist_count > 1) {
        SelectObject(hdc, line_pen);
        for (i = 0; i < g_app.score_hist_count; ++i) {
            double v = g_app.score_history[(g_app.score_hist_pos + i) % 120];
            int x = rect->left + 30 + (i * (rect->right - rect->left - 45)) / (g_app.score_hist_count - 1);
            int y = rect->bottom - 25 - (int)((v / max_val) * (rect->bottom - rect->top - 40));
            if (i == 0) MoveToEx(hdc, x, y, NULL);
            else LineTo(hdc, x, y);
        }
    }

    DeleteObject(axis_pen);
    DeleteObject(line_pen);
    DeleteObject(thresh_pen);

    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, CLR_GRAPH_LINE2);
    TextOutA(hdc, rect->left + 35, rect->top + 6, g_lang.graph_score_title, (int)strlen(g_lang.graph_score_title));
    /* Current value */
    if (g_app.score_hist_count > 0) {
        char val[32];
        double last = g_app.score_history[(g_app.score_hist_pos + g_app.score_hist_count - 1) % 120];
        snprintf(val, sizeof(val), "%.1f", last);
        SetTextColor(hdc, CLR_BRIGHT);
        TextOutA(hdc, rect->right - 80, rect->top + 6, val, (int)strlen(val));
    }

    /* Border */
    {
        HPEN bpen = CreatePen(PS_SOLID, 1, RGB(55, 55, 58));
        HPEN old_p = (HPEN)SelectObject(hdc, bpen);
        HBRUSH null_b = (HBRUSH)GetStockObject(NULL_BRUSH);
        HBRUSH old_b = (HBRUSH)SelectObject(hdc, null_b);
        Rectangle(hdc, rect->left, rect->top, rect->right, rect->bottom);
        SelectObject(hdc, old_p);
        SelectObject(hdc, old_b);
        DeleteObject(bpen);
    }
}

static void draw_progress(HDC hdc, const RECT *rect)
{
    HBRUSH bg = CreateSolidBrush(CLR_PROGRESS_BG);
    RECT fill_rect = *rect;
    char label[128];
    double pct = 0.0;

    FillRect(hdc, rect, bg);
    DeleteObject(bg);

    if (g_app.snapshot.total_keys > 0) {
        pct = (double)g_app.snapshot.keys_tested / (double)g_app.snapshot.total_keys;
        if (pct > 1.0) pct = 1.0;
    }

    fill_rect.right = fill_rect.left + (int)((rect->right - rect->left) * pct);
    {
        HBRUSH fill = CreateSolidBrush(CLR_ACCENT);
        FillRect(hdc, &fill_rect, fill);
        DeleteObject(fill);
    }

    snprintf(label, sizeof(label), "%.2f%%", pct * 100.0);
    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, CLR_BRIGHT);
    {
        RECT tr = *rect;
        DrawTextA(hdc, label, -1, &tr, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    }
}

/* --- KPA silence badge --- */
static void update_kpa_badge(void)
{
    if (!g_app.lbl_kpa_badge) return;
    if (g_app.payloads.n_silence > 0) {
        char kpa_text[64];
        snprintf(kpa_text, sizeof(kpa_text), "KPA: %u silence frame%s",
                 (unsigned)g_app.payloads.n_silence,
                 g_app.payloads.n_silence == 1 ? "" : "s");
        SetWindowTextA(g_app.lbl_kpa_badge, kpa_text);
        ShowWindow(g_app.lbl_kpa_badge, SW_SHOW);
    } else {
        ShowWindow(g_app.lbl_kpa_badge, SW_HIDE);
    }
}

/* --- File dialogs --- */
static void choose_file(HWND owner)
{
    OPENFILENAMEA ofn;
    char file[MAX_PATH] = {0};
    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = owner;
    ofn.lpstrFilter = g_lang.dlg_bin_filter;
    ofn.lpstrFile = file;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    if (GetOpenFileNameA(&ofn)) {
        SetWindowTextA(g_app.edit_file, file);
        /* Auto-load and validate */
        {
            char err[256] = {0};
            payload_set_free(&g_app.payloads);
            payload_set_init(&g_app.payloads);
            if (load_payload_file(file, 0, &g_app.payloads, err, sizeof(err))) {
                char summary[160], warn_txt[160], plbl[320];
                validate_payload_set(&g_app.payloads, summary, sizeof(summary),
                                     warn_txt, sizeof(warn_txt));
                if (warn_txt[0])
                    snprintf(plbl, sizeof(plbl), "%s  %s", summary, warn_txt);
                else
                    snprintf(plbl, sizeof(plbl), "%s", summary);
                SetWindowTextA(g_app.payload_label, plbl);
                update_kpa_badge();
                strcpy_s(g_app.loaded_file, sizeof(g_app.loaded_file), file);
                EnableWindow(g_app.btn_export, TRUE);
            } else {
                SetWindowTextA(g_app.payload_label, err);
                update_kpa_badge();
            }
        }
    }
}

static void choose_wav_file(HWND owner)
{
    OPENFILENAMEA ofn;
    char file[MAX_PATH] = {0};
    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = owner;
    ofn.lpstrFilter = g_lang.dlg_audio_filter;
    ofn.lpstrFile = file;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    if (GetOpenFileNameA(&ofn))
        SetWindowTextA(g_app.edit_wav, file);
}

/* --- External process helpers --- */
static int file_exists(const char *path)
{
    DWORD attr = GetFileAttributesA(path);
    return (attr != INVALID_FILE_ATTRIBUTES) && ((attr & FILE_ATTRIBUTE_DIRECTORY) == 0);
}

static int resolve_tool_path(const char *tool_rel, char *out, size_t out_len)
{
    char cwd[MAX_PATH], exe_path[MAX_PATH];
    char *slash;
    /* 1. Try CWD\tools\... */
    if (GetCurrentDirectoryA(MAX_PATH, cwd) > 0) {
        snprintf(out, out_len, "%s\\%s", cwd, tool_rel);
        if (file_exists(out)) return 1;
    }
    if (GetModuleFileNameA(NULL, exe_path, MAX_PATH) == 0) return 0;
    slash = strrchr(exe_path, '\\');
    if (!slash) return 0;
    *slash = '\0';
    /* 2. Try EXE_DIR\tools\... (e.g. bin\tools\) */
    snprintf(out, out_len, "%s\\%s", exe_path, tool_rel);
    if (file_exists(out)) return 1;
    /* 3. Try EXE_DIR\..\tools\... (exe in bin\, tools in project root) */
    slash = strrchr(exe_path, '\\');
    if (slash) {
        *slash = '\0';
        snprintf(out, out_len, "%s\\%s", exe_path, tool_rel);
        if (file_exists(out)) return 1;
    }
    return 0;
}

static int run_process_and_wait(const char *cmdline, DWORD *exit_code)
{
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    char cmd[4096];
    DWORD code = 1;
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si);
    snprintf(cmd, sizeof(cmd), "%s", cmdline);
    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
        return 0;
    WaitForSingleObject(pi.hProcess, INFINITE);
    if (!GetExitCodeProcess(pi.hProcess, &code)) code = 1;
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    if (exit_code) *exit_code = code;
    return 1;
}

/* Run a process without a shell, redirecting its stderr to a file.
 * working_dir sets the child process CWD (NULL = inherit).
 * Uses bInheritHandles=TRUE so the child process can write to the log handle. */
static int run_process_stderr_redirect(const char *cmdline, const char *stderr_path,
                                        const char *working_dir, DWORD *exit_code)
{
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    SECURITY_ATTRIBUTES sa;
    char cmd[4096];
    DWORD code = 1;
    HANDLE hErr = INVALID_HANDLE_VALUE;

    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = TRUE;

    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si);

    if (stderr_path && stderr_path[0]) {
        hErr = CreateFileA(stderr_path, GENERIC_WRITE, FILE_SHARE_READ, &sa,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hErr != INVALID_HANDLE_VALUE) {
            si.hStdError  = hErr;
            si.hStdOutput = hErr;   /* capture stdout in the log too */
            si.hStdInput  = GetStdHandle(STD_INPUT_HANDLE);
            si.dwFlags |= STARTF_USESTDHANDLES;
        }
    }

    snprintf(cmd, sizeof(cmd), "%s", cmdline);
    if (!CreateProcessA(NULL, cmd, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL,
                        (working_dir && working_dir[0]) ? working_dir : NULL, &si, &pi)) {
        if (hErr != INVALID_HANDLE_VALUE) CloseHandle(hErr);
        return 0;
    }

    WaitForSingleObject(pi.hProcess, INFINITE);
    if (!GetExitCodeProcess(pi.hProcess, &code)) code = 1;
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    if (hErr != INVALID_HANDLE_VALUE) CloseHandle(hErr);
    if (exit_code) *exit_code = code;
    return 1;
}


/* Read the last ~480 bytes of a log file into buf (null-terminated).
 * Skips to the first complete line if the file is longer than the buffer. */
static void read_log_tail(const char *path, char *buf, size_t buf_len)
{
    buf[0] = '\0';
    if (buf_len < 2) return;
    FILE *f = fopen(path, "r");
    if (!f) return;
    size_t max = buf_len - 1;
    if (max > 480) max = 480;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    long start = (long)max < sz ? sz - (long)max : 0;
    fseek(f, start, SEEK_SET);
    size_t nr = fread(buf, 1, max, f);
    buf[nr] = '\0';
    fclose(f);
    /* Skip partial first line when we seeked mid-file */
    if (start > 0) {
        char *nl = strchr(buf, '\n');
        if (nl) memmove(buf, nl + 1, strlen(nl + 1) + 1);
    }
}

/* --- Demodulation thread ---
 * Runs dsd-fme.exe and dsdfme_dsp_to_bin.py directly via CreateProcessA,
 * without cmd.exe as an intermediary, to avoid shell metacharacter injection. */
static DWORD WINAPI demod_thread_proc(LPVOID param)
{
    char wav_path[MAX_PATH], err[256] = {0};
    char dsd_path[MAX_PATH];
    char out_bin[MAX_PATH], logfile[MAX_PATH], qname[MAX_PATH], dspfile[MAX_PATH];
    char wav_dir[MAX_PATH];
    char cmdline[4096];
    char drive[_MAX_DRIVE], dir[_MAX_DIR], fname[_MAX_FNAME], ext[_MAX_EXT];
    char ob_drive[_MAX_DRIVE], ob_dir[_MAX_DIR], ob_fname[_MAX_FNAME], ob_ext[_MAX_EXT];
    DWORD proc_exit = 1;
    (void)param;

    GetWindowTextA(g_app.edit_wav, wav_path, MAX_PATH);
    if (wav_path[0] == '\0') {
        SetWindowTextA(g_app.demod_label, g_lang.err_no_audio_selected);
        goto done;
    }
    if (!file_exists(wav_path)) {
        SetWindowTextA(g_app.demod_label, g_lang.err_audio_not_found);
        goto done;
    }
    if (!resolve_tool_path("tools\\dsd-fme.exe", dsd_path, sizeof(dsd_path))) {
        SetWindowTextA(g_app.demod_label, g_lang.err_dsd_missing);
        MessageBoxA(g_app.hwnd,
            "dsd-fme.exe was not found in the tools\\ folder.\n\n"
            "The installation may be incomplete or corrupted.\n"
            "Please reinstall FSP.DMRCrack.",
            APP_TITLE, MB_ICONERROR);
        goto done;
    }

    /* Build output paths */
    _splitpath_s(wav_path, drive, sizeof(drive), dir, sizeof(dir), fname, sizeof(fname), ext, sizeof(ext));
    snprintf(out_bin,  sizeof(out_bin),  "%s%s%s.fromdsdfme.bin", drive, dir, fname);
    snprintf(logfile,  sizeof(logfile),  "%s%s%s.dslog.txt",      drive, dir, fname);
    snprintf(wav_dir,  sizeof(wav_dir),  "%s%s", drive, dir);
    /* Remove trailing backslash so CreateProcess lpCurrentDirectory is valid */
    { size_t wdl = strlen(wav_dir); if (wdl > 1 && wav_dir[wdl-1] == '\\') wav_dir[wdl-1] = '\0'; }

    /* qname is filename-only; dsd-fme writes it relative to its CWD (wav_dir).
     * dsd-fme (Cygwin) may create a DSP/ subdirectory — we search both locations. */
    _splitpath_s(out_bin, ob_drive, sizeof(ob_drive), ob_dir, sizeof(ob_dir),
                 ob_fname, sizeof(ob_fname), ob_ext, sizeof(ob_ext));
    snprintf(qname, sizeof(qname), "%s.dsdsp.txt", ob_fname);

    /* Paths are embedded in a quoted command line; '"' would break quoting. */
    if (strchr(dsd_path, '"') || strchr(wav_path, '"') || strchr(qname,   '"') ||
        strchr(out_bin,  '"') || strchr(logfile,  '"')) {
        SetWindowTextA(g_app.demod_label, g_lang.err_path_has_quotes);
        goto done;
    }

    /* Clean up outputs from previous runs (both possible locations) */
    DeleteFileA(out_bin);
    DeleteFileA(logfile);
    {
        char tmp[MAX_PATH];
        snprintf(tmp, sizeof(tmp), "%s\\DSP\\%s", wav_dir, qname);
        DeleteFileA(tmp);
        snprintf(tmp, sizeof(tmp), "%s\\%s", wav_dir, qname);
        DeleteFileA(tmp);
    }

    /* Pre-flight: check that the Cygwin runtime is bundled next to dsd-fme.exe */
    {
        char dll_path[MAX_PATH];
        char *last_sep = strrchr(dsd_path, '\\');
        if (last_sep) {
            size_t dir_len = (size_t)(last_sep - dsd_path);
            if (dir_len + 1 + 12 < sizeof(dll_path)) {
                memcpy(dll_path, dsd_path, dir_len);
                memcpy(dll_path + dir_len, "\\cygwin1.dll", 13);
                if (!file_exists(dll_path)) {
                    SetWindowTextA(g_app.demod_label, g_lang.err_cygwin_dlls_missing);
                    goto done;
                }
            }
        }
    }

    /* Slot flag from combo */
    char slot_flag[8] = "-V 3";
    {
        int slot_sel = (int)SendMessageA(g_app.combo_slot, CB_GETCURSEL, 0, 0);
        if (slot_sel == 1) strcpy_s(slot_flag, sizeof(slot_flag), "-V 1");
        else if (slot_sel == 2) strcpy_s(slot_flag, sizeof(slot_flag), "-V 2");
        else strcpy_s(slot_flag, sizeof(slot_flag), "-V 3");
    }

    /* Inverted flag */
    char inv_flag[8] = "";
    if (SendMessageA(g_app.chk_inverted, BM_GETCHECK, 0, 0) == BST_CHECKED)
        strcpy_s(inv_flag, sizeof(inv_flag), " -xr");

    /* RTL-SDR mode: build RTL input string */
    char rtl_input[128] = "";
    int use_rtl = 0;
    if (g_app.capture_mode == 1) {
        char freq_txt[32], gain_txt[16], ppm_txt[16], dev_txt[8];
        GetWindowTextA(g_app.edit_freq,   freq_txt, sizeof(freq_txt));
        GetWindowTextA(g_app.edit_gain,   gain_txt, sizeof(gain_txt));
        GetWindowTextA(g_app.edit_ppm,    ppm_txt,  sizeof(ppm_txt));
        GetWindowTextA(g_app.edit_device, dev_txt,  sizeof(dev_txt));
        double freq_mhz = atof(freq_txt);
        long long freq_hz = (long long)(freq_mhz * 1e6);
        snprintf(rtl_input, sizeof(rtl_input), "rtl:%s:%lld:%s:%s",
                 dev_txt, freq_hz, gain_txt, ppm_txt);
        use_rtl = 1;
    }

    /* Step 1/2: run dsd-fme.exe directly (no shell), stderr → log file.
     * -Q takes a relative filename; dsd-fme runs with CWD = wav_dir. */
    SetWindowTextA(g_app.demod_label, g_lang.status_demodulating);
    if (use_rtl)
        snprintf(cmdline, sizeof(cmdline), "\"%s\" -fs -i %s -Q \"%s\" -Z %s%s",
                 dsd_path, rtl_input, qname, slot_flag, inv_flag);
    else
        snprintf(cmdline, sizeof(cmdline), "\"%s\" -fs -i \"%s\" -Q \"%s\" -Z %s%s",
                 dsd_path, wav_path, qname, slot_flag, inv_flag);
    if (!run_process_stderr_redirect(cmdline, logfile, wav_dir, &proc_exit) || proc_exit != 0) {
        /* 0xC0000135 = STATUS_DLL_NOT_FOUND -- Cygwin runtime missing */
        if (proc_exit == 0xC0000135u || proc_exit == 0xC0000139u) {
            SetWindowTextA(g_app.demod_label, g_lang.err_dll_not_found_exit);
        } else {
            char tail[512], detail[1024];
            read_log_tail(logfile, tail, sizeof(tail));
            if (tail[0])
                snprintf(detail, sizeof(detail), "%s (exit %lu)\n\nLog: %s\n\n%s",
                         g_lang.err_dsd_failed, (unsigned long)proc_exit, logfile, tail);
            else
                snprintf(detail, sizeof(detail), "%s (exit %lu)\n\nLog: %s\n\n(empty log)",
                         g_lang.err_dsd_failed, (unsigned long)proc_exit, logfile);
            SetWindowTextA(g_app.demod_label, g_lang.err_dsd_failed);
            MessageBoxA(g_app.hwnd, detail, APP_TITLE, MB_ICONERROR);
        }
        goto done;
    }

    /* Locate the DSP output: dsd-fme may write to wav_dir\DSP\qname, wav_dir\qname,
     * or (on some versions) relative to the dsd-fme.exe directory. */
    {
        char cand[MAX_PATH];
        int found = 0;
        snprintf(cand, sizeof(cand), "%s\\DSP\\%s", wav_dir, qname);
        if (file_exists(cand)) { snprintf(dspfile, sizeof(dspfile), "%s", cand); found = 1; }
        if (!found) {
            snprintf(cand, sizeof(cand), "%s\\%s", wav_dir, qname);
            if (file_exists(cand)) { snprintf(dspfile, sizeof(dspfile), "%s", cand); found = 1; }
        }
        /* Also check the dsd-fme.exe directory in case it writes there */
        if (!found) {
            char *dsd_sep = strrchr(dsd_path, '\\');
            if (dsd_sep) {
                char dsd_dir[MAX_PATH];
                size_t dlen = (size_t)(dsd_sep - dsd_path);
                memcpy(dsd_dir, dsd_path, dlen);
                dsd_dir[dlen] = '\0';
                snprintf(cand, sizeof(cand), "%s\\DSP\\%s", dsd_dir, qname);
                if (file_exists(cand)) { snprintf(dspfile, sizeof(dspfile), "%s", cand); found = 1; }
                if (!found) {
                    snprintf(cand, sizeof(cand), "%s\\%s", dsd_dir, qname);
                    if (file_exists(cand)) { snprintf(dspfile, sizeof(dspfile), "%s", cand); found = 1; }
                }
            }
        }
        if (!found) {
            char tail[512], detail[1024];
            read_log_tail(logfile, tail, sizeof(tail));
            if (tail[0])
                snprintf(detail, sizeof(detail),
                         "%s\n\nLog: %s\n\ndsd-fme output:\n%s",
                         g_lang.err_no_dsp_output, logfile, tail);
            else
                snprintf(detail, sizeof(detail),
                         "%s\n\nLog: %s\n\n(empty log — dsd-fme produced no output)",
                         g_lang.err_no_dsp_output, logfile);
            SetWindowTextA(g_app.demod_label, g_lang.err_no_dsp_output);
            MessageBoxA(g_app.hwnd, detail, APP_TITLE, MB_ICONWARNING);
            goto done;
        }
    }

    /* Step 2/2: convert DSP output to .bin (native C, no Python needed) */
    SetWindowTextA(g_app.demod_label, g_lang.status_converting);
    {
        char conv_err[256] = {0};
        if (!dsp_convert_to_bin(dspfile, out_bin, logfile, conv_err, sizeof(conv_err))) {
            SetWindowTextA(g_app.demod_label,
                conv_err[0] ? conv_err : g_lang.err_dsp_conversion);
            goto done;
        }
    }

    payload_set_free(&g_app.payloads);
    payload_set_init(&g_app.payloads);
    if (!load_payload_file(out_bin, 0, &g_app.payloads, err, sizeof(err))) {
        SetWindowTextA(g_app.demod_label, err[0] ? err : g_lang.err_bin_load);
        goto done;
    }

    strcpy_s(g_app.loaded_wav, sizeof(g_app.loaded_wav), wav_path);
    strcpy_s(g_app.loaded_file, sizeof(g_app.loaded_file), out_bin);
    {
        char msg[320], summary[160], warn_txt[160], plbl[320];
        snprintf(msg, sizeof(msg), "OK: %zu payloads -> %s", g_app.payloads.count, out_bin);
        SetWindowTextA(g_app.demod_label, msg);
        validate_payload_set(&g_app.payloads, summary, sizeof(summary),
                             warn_txt, sizeof(warn_txt));
        if (warn_txt[0])
            snprintf(plbl, sizeof(plbl), "%s  %s", summary, warn_txt);
        else
            snprintf(plbl, sizeof(plbl), "%s", summary);
        SetWindowTextA(g_app.payload_label, plbl);
        update_kpa_badge();
    }
    SetWindowTextA(g_app.edit_file, out_bin);
    EnableWindow(g_app.btn_export, TRUE);
    InterlockedExchange(&g_app.demod_running, 0);
    PostMessageA(g_app.hwnd, WM_APP_DEMOD_DONE, 1, 0);
    return 0;

done:
    InterlockedExchange(&g_app.demod_running, 0);
    PostMessageA(g_app.hwnd, WM_APP_DEMOD_DONE, 0, 0);
    return 1;
}

static void start_demod(HWND hwnd)
{
    if (InterlockedCompareExchange(&g_app.demod_running, 1, 0) != 0) {
        MessageBoxA(hwnd, g_lang.err_demod_already_running, APP_TITLE, MB_ICONINFORMATION);
        return;
    }
    if (g_app.demod_thread) { CloseHandle(g_app.demod_thread); g_app.demod_thread = NULL; }
    g_app.demod_thread = CreateThread(NULL, 0, demod_thread_proc, NULL, 0, NULL);
    if (!g_app.demod_thread) {
        InterlockedExchange(&g_app.demod_running, 0);
        MessageBoxA(hwnd, g_lang.err_demod_thread, APP_TITLE, MB_ICONERROR);
    }
}

static void export_bin_file(HWND owner)
{
    OPENFILENAMEA ofn;
    char file[MAX_PATH] = {0}, err[256] = {0}, msg[320];

    if (g_app.payloads.count == 0) {
        MessageBoxA(owner, g_lang.err_no_payloads_export, APP_TITLE, MB_ICONWARNING);
        return;
    }
    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = owner;
    ofn.lpstrFilter = g_lang.dlg_export_filter;
    ofn.lpstrFile = file;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;
    ofn.lpstrDefExt = "bin";

    if (GetSaveFileNameA(&ofn)) {
        if (payload_save_file(file, &g_app.payloads, err, sizeof(err))) {
            snprintf(msg, sizeof(msg), g_lang.msg_exported, g_app.payloads.count, file);
            MessageBoxA(owner, msg, APP_TITLE, MB_ICONINFORMATION);
            SetWindowTextA(g_app.edit_file, file);
        } else {
            MessageBoxA(owner, err, APP_TITLE, MB_ICONERROR);
        }
    }
}

/* --- History & refresh --- */
static int read_edit_text(HWND edit, char *out, size_t out_len)
{
    return GetWindowTextA(edit, out, (int)out_len) > 0;
}

static void append_kps_sample(double kps)
{
    if (g_app.hist_count < 120)
        g_app.kps_history[g_app.hist_count++] = kps;
    else {
        g_app.kps_history[g_app.hist_pos] = kps;
        g_app.hist_pos = (g_app.hist_pos + 1) % 120;
    }
}

static void append_score_sample(double score)
{
    if (!isfinite(score) || score <= -1e30) score = 0.0;
    if (g_app.score_hist_count < 120)
        g_app.score_history[g_app.score_hist_count++] = score;
    else {
        g_app.score_history[g_app.score_hist_pos] = score;
        g_app.score_hist_pos = (g_app.score_hist_pos + 1) % 120;
    }
}

static void refresh_snapshot_and_ui(void)
{
    bruteforce_get_snapshot(&g_app.engine, &g_app.snapshot);
    append_kps_sample(g_app.snapshot.keys_per_second);
    append_score_sample(g_app.snapshot.best_score);
    InvalidateRect(g_app.hwnd, &g_app.tile_throughput_rect, FALSE);
    InvalidateRect(g_app.hwnd, &g_app.tile_progress_rect, FALSE);
    InvalidateRect(g_app.hwnd, &g_app.tile_candidate_rect, FALSE);
    InvalidateRect(g_app.hwnd, &g_app.status_strip_rect, FALSE);
    if (g_app.snapshot.running)
        SetWindowTextA(g_app.btn_pause, g_app.snapshot.paused ? g_lang.btn_resume : g_lang.btn_pause);
    else
        SetWindowTextA(g_app.btn_pause, g_lang.btn_pause);

    /* Key-found notification: flash taskbar when search completes with a result */
    if (g_app.snapshot.finished && !g_app.notified_completion) {
        g_app.notified_completion = 1;
        if (isfinite(g_app.snapshot.best_score) && g_app.snapshot.best_score > -1e30) {
            FLASHWINFO fwi;
            fwi.cbSize = sizeof(fwi);
            fwi.hwnd = g_app.hwnd;
            fwi.dwFlags = FLASHW_ALL | FLASHW_TIMERNOFG;
            fwi.uCount = 5;
            fwi.dwTimeout = 0;
            FlashWindowEx(&fwi);
            MessageBeep(MB_ICONINFORMATION);
        }
    }

    InvalidateRect(g_app.hwnd, &g_app.graph_rect, FALSE);
    InvalidateRect(g_app.hwnd, &g_app.score_graph_rect, FALSE);
    InvalidateRect(g_app.hwnd, &g_app.progress_rect, FALSE);
}

/* --- Bruteforce control --- */
static int start_bruteforce(HWND hwnd)
{
    char file[MAX_PATH], start_hex[64], end_hex[64], threads_txt[64], samples_txt[64], err[256];
    uint64_t start_key, end_key;
    int threads, samples;
    BruteforceConfig cfg;

    if (!read_edit_text(g_app.edit_file, file, sizeof(file))) {
        MessageBoxA(hwnd, g_lang.err_no_bin_selected, APP_TITLE, MB_ICONWARNING);
        return 0;
    }
    if (!read_edit_text(g_app.edit_start, start_hex, sizeof(start_hex)) || !parse_hex40(start_hex, &start_key)) {
        MessageBoxA(hwnd, g_lang.err_start_key_invalid, APP_TITLE, MB_ICONWARNING);
        return 0;
    }
    if (!read_edit_text(g_app.edit_end, end_hex, sizeof(end_hex)) || !parse_hex40(end_hex, &end_key)) {
        MessageBoxA(hwnd, g_lang.err_end_key_invalid, APP_TITLE, MB_ICONWARNING);
        return 0;
    }
    if (!read_edit_text(g_app.edit_threads, threads_txt, sizeof(threads_txt))) {
        MessageBoxA(hwnd, g_lang.err_threads_empty, APP_TITLE, MB_ICONWARNING);
        return 0;
    }
    { char *endp; long val = strtol(threads_txt, &endp, 10);
      if (endp == threads_txt || *endp || val <= 0 || val > 64) {
          MessageBoxA(hwnd, g_lang.err_threads_range, APP_TITLE, MB_ICONWARNING); return 0;
      }
      threads = (int)val;
    }
    if (!read_edit_text(g_app.edit_samples, samples_txt, sizeof(samples_txt))) {
        MessageBoxA(hwnd, g_lang.err_samples_empty, APP_TITLE, MB_ICONWARNING);
        return 0;
    }
    { char *endp; long val = strtol(samples_txt, &endp, 10);
      if (endp == samples_txt || *endp || val <= 0 || val > 100000) {
          MessageBoxA(hwnd, g_lang.err_samples_range, APP_TITLE, MB_ICONWARNING); return 0;
      }
      samples = (int)val;
    }

    if (g_app.payloads.count == 0 || strcmp(file, g_lang.status_demod_in_memory) != 0) {
        payload_set_free(&g_app.payloads);
        payload_set_init(&g_app.payloads);
        if (!load_payload_file(file, 0, &g_app.payloads, err, sizeof(err))) {
            MessageBoxA(hwnd, err, APP_TITLE, MB_ICONERROR);
            return 0;
        }
        strcpy_s(g_app.loaded_file, sizeof(g_app.loaded_file), file);
    }

    {
        char summary[160], warn_txt[160], plbl[320];
        validate_payload_set(&g_app.payloads, summary, sizeof(summary),
                             warn_txt, sizeof(warn_txt));
        if (warn_txt[0])
            snprintf(plbl, sizeof(plbl), "%s  %s", summary, warn_txt);
        else
            snprintf(plbl, sizeof(plbl), "%s", summary);
        SetWindowTextA(g_app.payload_label, plbl);
    }
    if (g_app.payloads.count < 30) {
        char warn[160];
        snprintf(warn, sizeof(warn), g_lang.warn_low_payloads_n, g_app.payloads.count);
        SetWindowTextA(g_app.payload_label, warn);
    }
    update_kpa_badge();

    cfg.start_key = start_key;
    cfg.end_key = end_key;
    cfg.thread_count = threads;
    cfg.sample_lines = samples;
    {
        char pct_buf[8] = {0};
        read_edit_text(g_app.edit_gpu_pct, pct_buf, sizeof(pct_buf));
        int pct = atoi(pct_buf);
        if (pct < 50 || pct > 95) pct = 80;
        pct = (pct / 5) * 5;
        g_app.gpu_split_pct = pct;
        cfg.gpu_split_pct = pct;
    }
    { size_t ml = 0;
      for (size_t i = 0; i < g_app.payloads.count; ++i)
          if (g_app.payloads.items[i].len > ml) ml = g_app.payloads.items[i].len;
      cfg.sample_bytes = (ml >= 33) ? 33 : 27;
    }

    if (!bruteforce_start(&g_app.engine, &cfg, &g_app.payloads, err, sizeof(err))) {
        MessageBoxA(hwnd, err, APP_TITLE, MB_ICONERROR);
        return 0;
    }

    g_app.last_cfg = cfg;
    g_app.fallback_triggered = 0;
    g_app.fallback_banner_ticks = 0;
    g_app.notified_completion = 0;
    g_app.hist_count = g_app.hist_pos = 0;
    g_app.score_hist_count = g_app.score_hist_pos = 0;
    ZeroMemory(g_app.kps_history, sizeof(g_app.kps_history));
    ZeroMemory(g_app.score_history, sizeof(g_app.score_history));
    refresh_snapshot_and_ui();
    return 1;
}

static void on_pause_resume(void)
{
    bruteforce_get_snapshot(&g_app.engine, &g_app.snapshot);
    if (!g_app.snapshot.running) return;
    if (g_app.snapshot.paused) bruteforce_resume(&g_app.engine);
    else bruteforce_pause(&g_app.engine);
}

static void on_stop(void)
{
    bruteforce_stop(&g_app.engine);
    refresh_snapshot_and_ui();
}

/* --- Owner-drawn button painting --- */
static void draw_button(DRAWITEMSTRUCT *dis)
{
    COLORREF bg_clr, txt_clr;
    HBRUSH br;
    char text[64];
    RECT r = dis->rcItem;

    if (dis->itemState & ODS_DISABLED) {
        bg_clr = RGB(60, 60, 60);
        txt_clr = CLR_DIM;
    } else if (dis->itemState & ODS_SELECTED) {
        bg_clr = CLR_ACCENT_PRESS;
        txt_clr = CLR_BRIGHT;
    } else {
        bg_clr = CLR_ACCENT;
        txt_clr = CLR_BRIGHT;
    }

    /* Special colors for Stop button */
    if (dis->CtlID == ID_BTN_STOP && !(dis->itemState & ODS_DISABLED)) {
        bg_clr = (dis->itemState & ODS_SELECTED) ? RGB(180, 40, 40) : RGB(200, 55, 55);
    }

    /* Rounded button with 4px corner radius */
    {
        HRGN rgn = CreateRoundRectRgn(r.left, r.top, r.right + 1, r.bottom + 1, 8, 8);
        SelectClipRgn(dis->hDC, rgn);
        br = CreateSolidBrush(bg_clr);
        FillRect(dis->hDC, &r, br);
        DeleteObject(br);

        GetWindowTextA(dis->hwndItem, text, sizeof(text));
        SetBkMode(dis->hDC, TRANSPARENT);
        SetTextColor(dis->hDC, txt_clr);
        SelectObject(dis->hDC, g_app.ui_font_bold);
        DrawTextA(dis->hDC, text, -1, &r, DT_CENTER | DT_VCENTER | DT_SINGLELINE);

        SelectClipRgn(dis->hDC, NULL);

        if (dis->itemState & ODS_FOCUS) {
            HPEN pen = CreatePen(PS_SOLID, 1, CLR_BRIGHT);
            HPEN old_p = (HPEN)SelectObject(dis->hDC, pen);
            HBRUSH null_br = (HBRUSH)GetStockObject(NULL_BRUSH);
            HBRUSH old_br = (HBRUSH)SelectObject(dis->hDC, null_br);
            RoundRect(dis->hDC, r.left, r.top, r.right, r.bottom, 8, 8);
            SelectObject(dis->hDC, old_p);
            SelectObject(dis->hDC, old_br);
            DeleteObject(pen);
        }
        DeleteObject(rgn);
    }
}

/* --- Language persistence (dmrcrack.ini next to the exe) --- */
static void get_ini_path(char *out, size_t sz)
{
    GetModuleFileNameA(NULL, out, (DWORD)sz);
    char *last = strrchr(out, '\\');
    if (last) { last[1] = '\0'; strncat_s(out, sz, "dmrcrack.ini", sz - strlen(out) - 1); }
}

static void lang_save(void)
{
    char ini[MAX_PATH];
    get_ini_path(ini, sizeof(ini));
    WritePrivateProfileStringA("Settings", "Language",
        (g_lang_ptr == &g_lang_es) ? "es" : "en", ini);
}

static void lang_load(void)
{
    char ini[MAX_PATH], val[8];
    get_ini_path(ini, sizeof(ini));
    GetPrivateProfileStringA("Settings", "Language", "en", val, sizeof(val), ini);
    g_lang_ptr = (val[0] == 'e' && val[1] == 's') ? &g_lang_es : &g_lang_en;
}

/* --- Apply current language to all controls --- */
static void layout_controls_current(void)
{
    RECT rc;
    GetClientRect(g_app.hwnd, &rc);
    layout_controls(rc.right, rc.bottom);
    InvalidateRect(g_app.hwnd, NULL, TRUE);
}

static void update_capture_mode_visibility(void)
{
    int is_rtl = (g_app.capture_mode == 1);
    /* WAV-only controls */
    ShowWindow(g_app.lbl_audio,       is_rtl ? SW_HIDE : SW_SHOW);
    ShowWindow(g_app.edit_wav,        is_rtl ? SW_HIDE : SW_SHOW);
    ShowWindow(g_app.btn_browse_wav,  is_rtl ? SW_HIDE : SW_SHOW);
    /* RTL-only controls */
    ShowWindow(g_app.lbl_freq,        is_rtl ? SW_SHOW : SW_HIDE);
    ShowWindow(g_app.edit_freq,       is_rtl ? SW_SHOW : SW_HIDE);
    ShowWindow(g_app.lbl_gain,        is_rtl ? SW_SHOW : SW_HIDE);
    ShowWindow(g_app.edit_gain,       is_rtl ? SW_SHOW : SW_HIDE);
    ShowWindow(g_app.lbl_ppm,         is_rtl ? SW_SHOW : SW_HIDE);
    ShowWindow(g_app.edit_ppm,        is_rtl ? SW_SHOW : SW_HIDE);
    ShowWindow(g_app.lbl_device,      is_rtl ? SW_SHOW : SW_HIDE);
    ShowWindow(g_app.edit_device,     is_rtl ? SW_SHOW : SW_HIDE);
    /* Stop-capture button only for RTL */
    ShowWindow(g_app.btn_stop_capture, is_rtl ? SW_SHOW : SW_HIDE);
    /* btn_demod label changes */
    SetWindowTextA(g_app.btn_demod, is_rtl ? g_lang.btn_capture : g_lang.btn_demodulate);
}

static void apply_language(void)
{
    /* Labels */
    SetWindowTextA(g_app.lbl_audio,   g_lang.label_audio);
    SetWindowTextA(g_app.lbl_file,    g_lang.label_file);
    SetWindowTextA(g_app.lbl_start,   g_lang.label_start_key);
    SetWindowTextA(g_app.lbl_end,     g_lang.label_end_key);
    SetWindowTextA(g_app.lbl_threads, g_lang.label_threads);
    SetWindowTextA(g_app.lbl_samples, g_lang.label_samples);
    /* Buttons */
    SetWindowTextA(g_app.btn_demod,    g_lang.btn_demodulate);
    SetWindowTextA(g_app.btn_export,   g_lang.btn_export);
    SetWindowTextA(g_app.btn_help,     g_lang.btn_help);
    SetWindowTextA(g_app.btn_start,    g_lang.btn_start);
    SetWindowTextA(g_app.btn_stop,     g_lang.btn_stop);
    SetWindowTextA(g_app.btn_copy_key, g_lang.btn_copy_key);
    SetWindowTextA(g_app.btn_lang,
        (g_lang_ptr == &g_lang_es) ? "EN" : "ES");
    /* Pause/Resume depends on current state */
    {
        int paused = InterlockedCompareExchange(&g_app.engine.paused, 0, 0);
        SetWindowTextA(g_app.btn_pause, paused ? g_lang.btn_resume : g_lang.btn_pause);
    }
    /* RTL-SDR labels */
    SetWindowTextA(g_app.radio_wav,        g_lang.radio_wav);
    SetWindowTextA(g_app.radio_rtl,        g_lang.radio_rtl);
    if (g_app.lbl_freq)   SetWindowTextA(g_app.lbl_freq,   g_lang.label_freq);
    if (g_app.lbl_gain)   SetWindowTextA(g_app.lbl_gain,   g_lang.label_gain);
    if (g_app.lbl_ppm)    SetWindowTextA(g_app.lbl_ppm,    g_lang.label_ppm);
    if (g_app.lbl_device) SetWindowTextA(g_app.lbl_device, g_lang.label_device);
    if (g_app.lbl_slot)   SetWindowTextA(g_app.lbl_slot,   g_lang.label_slot);
    if (g_app.lbl_inverted_label) SetWindowTextA(g_app.lbl_inverted_label, g_lang.label_inverted);
    if (g_app.btn_stop_capture) SetWindowTextA(g_app.btn_stop_capture, g_lang.btn_stop_capture);
    /* Slot combo: clear and re-add items in current language */
    if (g_app.combo_slot) {
        SendMessageA(g_app.combo_slot, CB_RESETCONTENT, 0, 0);
        SendMessageA(g_app.combo_slot, CB_ADDSTRING, 0, (LPARAM)g_lang.slot_both);
        SendMessageA(g_app.combo_slot, CB_ADDSTRING, 0, (LPARAM)g_lang.slot_1);
        SendMessageA(g_app.combo_slot, CB_ADDSTRING, 0, (LPARAM)g_lang.slot_2);
        SendMessageA(g_app.combo_slot, CB_SETCURSEL, 0, 0);
    }
    if (g_app.chk_inverted) SetWindowTextA(g_app.chk_inverted, g_lang.label_inverted);
    update_capture_mode_visibility();
    /* Section headers and status are redrawn on next tick */
    InvalidateRect(g_app.hwnd, NULL, TRUE);
    /* Close help window so it doesn't show stale language text */
    if (g_app.hwnd_help && IsWindow(g_app.hwnd_help)) {
        DestroyWindow(g_app.hwnd_help);
        g_app.hwnd_help = NULL;
    }
}

/* --- Help dialog --- */
#define HELP_CLASS_NAME "FSPDMRHelpWnd"

static LRESULT CALLBACK help_wnd_proc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
    switch (msg) {
    case WM_CREATE:
    {
        RECT rc;
        GetClientRect(hwnd, &rc);
        HFONT hfont = CreateFontA(
            -14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY, FIXED_PITCH | FF_MODERN, "Consolas");
        if (!hfont)
            hfont = (HFONT)GetStockObject(SYSTEM_FIXED_FONT);

        HWND hedit = CreateWindowExA(0, "EDIT", g_lang.help_content,
            WS_CHILD | WS_VISIBLE | WS_VSCROLL |
            ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL,
            0, 0, rc.right, rc.bottom,
            hwnd, (HMENU)1, GetModuleHandleA(NULL), NULL);
        SendMessageA(hedit, WM_SETFONT, (WPARAM)hfont, FALSE);
        /* EM_SETMARGINS for a bit of padding */
        SendMessageA(hedit, EM_SETMARGINS, EC_LEFTMARGIN | EC_RIGHTMARGIN,
                     MAKELONG(8, 8));
        SetWindowLongPtrA(hwnd, GWLP_USERDATA, (LONG_PTR)hedit);
        /* Store font in window extra bytes via a second slot isn't available,
           so tag it on the edit control */
        SetPropA(hedit, "HelpFont", (HANDLE)hfont);
        return 0;
    }
    case WM_SIZE:
    {
        HWND hedit = (HWND)GetWindowLongPtrA(hwnd, GWLP_USERDATA);
        if (hedit) MoveWindow(hedit, 0, 0, LOWORD(lparam), HIWORD(lparam), TRUE);
        return 0;
    }
    case WM_CTLCOLOREDIT:
    {
        HDC hdc = (HDC)wparam;
        SetTextColor(hdc, CLR_TEXT);
        SetBkColor(hdc, CLR_BG);
        return (LRESULT)g_app.br_bg;
    }
    case WM_ERASEBKGND:
    {
        RECT rc;
        GetClientRect(hwnd, &rc);
        FillRect((HDC)wparam, &rc, g_app.br_bg);
        return 1;
    }
    case WM_CLOSE:
    {
        /* Clean up the font stored on the edit */
        HWND hedit = (HWND)GetWindowLongPtrA(hwnd, GWLP_USERDATA);
        if (hedit) {
            HFONT hf = (HFONT)GetPropA(hedit, "HelpFont");
            if (hf) { DeleteObject(hf); RemovePropA(hedit, "HelpFont"); }
        }
        g_app.hwnd_help = NULL;
        DestroyWindow(hwnd);
        return 0;
    }
    }
    return DefWindowProcA(hwnd, msg, wparam, lparam);
}

static void show_help_dialog(HWND parent)
{
    if (g_app.hwnd_help && IsWindow(g_app.hwnd_help)) {
        SetForegroundWindow(g_app.hwnd_help);
        return;
    }

    RECT pr;
    GetWindowRect(parent, &pr);
    int wx = pr.left + 60;
    int wy = pr.top + 40;

    g_app.hwnd_help = CreateWindowExA(
        0, HELP_CLASS_NAME, g_lang.help_title,
        WS_OVERLAPPEDWINDOW,
        wx, wy, 720, 640,
        parent, NULL, GetModuleHandleA(NULL), NULL);

    if (!g_app.hwnd_help) return;

    /* Apply dark title bar */
    { BOOL dark = TRUE;
      DwmSetWindowAttribute(g_app.hwnd_help, 20, &dark, sizeof(dark)); }

    ShowWindow(g_app.hwnd_help, SW_SHOW);
    UpdateWindow(g_app.hwnd_help);
}

/* --- Window procedure --- */
static LRESULT CALLBACK wnd_proc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
    switch (msg) {
    case WM_CREATE:
    {
        int y;
        lang_load();
        create_theme_brushes();
        g_app.ui_font = create_ui_font(0, 0);
        g_app.ui_font_bold = create_ui_font(1, 0);
        g_app.ui_font_section = create_ui_font(1, -2);

        /* Tile metric font: Consolas 14pt bold */
        g_app.font_tile_metric = CreateFontA(
            -18, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY, FIXED_PITCH | FF_MODERN, "Consolas");
        if (!g_app.font_tile_metric)
            g_app.font_tile_metric = (HFONT)GetStockObject(ANSI_FIXED_FONT);

        /* Tile sub-label font: Segoe UI 8pt */
        g_app.font_tile_label = CreateFontA(
            -11, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY, VARIABLE_PITCH | FF_SWISS, "Segoe UI");
        if (!g_app.font_tile_label)
            g_app.font_tile_label = g_app.ui_font;

        /* Header bold font: Segoe UI 10pt bold */
        g_app.font_header = CreateFontA(
            -14, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY, VARIABLE_PITCH | FF_SWISS, "Segoe UI");
        if (!g_app.font_header)
            g_app.font_header = g_app.ui_font_bold;

        /* Header sub-text font: Segoe UI 8pt regular */
        g_app.font_header_sub = CreateFontA(
            -11, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY, VARIABLE_PITCH | FF_SWISS, "Segoe UI");
        if (!g_app.font_header_sub)
            g_app.font_header_sub = g_app.ui_font;

        /* Enable dark title bar */
        { BOOL dark = TRUE;
          DwmSetWindowAttribute(hwnd, 20, &dark, sizeof(dark)); }

        y = 15;

        /* === CAPTURA section === */
        /* Section header drawn in WM_PAINT */

        y = 40;
        g_app.lbl_audio = CreateWindowA("STATIC", g_lang.label_audio, WS_CHILD | WS_VISIBLE | SS_RIGHT,
            20, y + 2, 70, 20, hwnd, NULL, NULL, NULL);
        g_app.edit_wav = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "",
            WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
            95, y, 540, 24, hwnd, (HMENU)ID_EDIT_WAV, NULL, NULL);
        g_app.btn_browse_wav = CreateWindowA("BUTTON", "...",
            WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
            640, y, 36, 24, hwnd, (HMENU)ID_BTN_BROWSE_WAV, NULL, NULL);
        g_app.btn_demod = CreateWindowA("BUTTON", g_lang.btn_demodulate,
            WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
            685, y, 100, 24, hwnd, (HMENU)ID_BTN_DEMOD, NULL, NULL);
        g_app.btn_export = CreateWindowA("BUTTON", g_lang.btn_export,
            WS_CHILD | WS_VISIBLE | WS_DISABLED | BS_OWNERDRAW,
            730, y, 60, 24, hwnd, (HMENU)ID_BTN_EXPORT, NULL, NULL);
        g_app.btn_help = CreateWindowA("BUTTON", g_lang.btn_help,
            WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
            800, y, 55, 24, hwnd, (HMENU)ID_BTN_HELP, NULL, NULL);
        g_app.btn_lang = CreateWindowA("BUTTON",
            (g_lang_ptr == &g_lang_es) ? "EN" : "ES",
            WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
            900, y, 36, 24, hwnd, (HMENU)ID_BTN_LANG, NULL, NULL);

        y += 28;
        g_app.demod_label = CreateWindowA("STATIC", "",
            WS_CHILD | WS_VISIBLE | SS_LEFT,
            95, y, 690, 16, hwnd, NULL, NULL, NULL);

        /* WAV/RTL radio buttons */
        g_app.radio_wav = CreateWindowA("BUTTON", g_lang.radio_wav,
            WS_CHILD | WS_VISIBLE | BS_AUTORADIOBUTTON | WS_GROUP,
            0, 0, 60, 20, hwnd, (HMENU)ID_RADIO_WAV, NULL, NULL);
        g_app.radio_rtl = CreateWindowA("BUTTON", g_lang.radio_rtl,
            WS_CHILD | WS_VISIBLE | BS_AUTORADIOBUTTON,
            0, 0, 70, 20, hwnd, (HMENU)ID_RADIO_RTL, NULL, NULL);
        SendMessageA(g_app.radio_wav, BM_SETCHECK, BST_CHECKED, 0);

        /* RTL-SDR controls (initially hidden) */
        g_app.lbl_freq   = CreateWindowA("STATIC", g_lang.label_freq, WS_CHILD, 0,0,1,1, hwnd, NULL, NULL, NULL);
        g_app.edit_freq  = CreateWindowA("EDIT",   "851.375",
            WS_CHILD | WS_BORDER | ES_AUTOHSCROLL, 0,0,1,1, hwnd, (HMENU)ID_EDIT_FREQ, NULL, NULL);
        g_app.lbl_gain   = CreateWindowA("STATIC", g_lang.label_gain, WS_CHILD, 0,0,1,1, hwnd, NULL, NULL, NULL);
        g_app.edit_gain  = CreateWindowA("EDIT",   "0",
            WS_CHILD | WS_BORDER | ES_AUTOHSCROLL | ES_NUMBER, 0,0,1,1, hwnd, (HMENU)ID_EDIT_GAIN, NULL, NULL);
        g_app.lbl_ppm    = CreateWindowA("STATIC", g_lang.label_ppm, WS_CHILD, 0,0,1,1, hwnd, NULL, NULL, NULL);
        g_app.edit_ppm   = CreateWindowA("EDIT",   "0",
            WS_CHILD | WS_BORDER | ES_AUTOHSCROLL | ES_NUMBER, 0,0,1,1, hwnd, (HMENU)ID_EDIT_PPM, NULL, NULL);
        g_app.lbl_device = CreateWindowA("STATIC", g_lang.label_device, WS_CHILD, 0,0,1,1, hwnd, NULL, NULL, NULL);
        g_app.edit_device= CreateWindowA("EDIT",   "0",
            WS_CHILD | WS_BORDER | ES_AUTOHSCROLL | ES_NUMBER, 0,0,1,1, hwnd, (HMENU)ID_EDIT_DEVICE, NULL, NULL);

        /* Slot combo (shared WAV/RTL) */
        g_app.combo_slot = CreateWindowA("COMBOBOX", "",
            WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL,
            0,0,1,60, hwnd, (HMENU)ID_COMBO_SLOT, NULL, NULL);
        SendMessageA(g_app.combo_slot, CB_ADDSTRING, 0, (LPARAM)g_lang.slot_both);
        SendMessageA(g_app.combo_slot, CB_ADDSTRING, 0, (LPARAM)g_lang.slot_1);
        SendMessageA(g_app.combo_slot, CB_ADDSTRING, 0, (LPARAM)g_lang.slot_2);
        SendMessageA(g_app.combo_slot, CB_SETCURSEL, 0, 0);

        /* Inverted checkbox (shared) */
        g_app.chk_inverted = CreateWindowA("BUTTON", g_lang.label_inverted,
            WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
            0,0,1,1, hwnd, (HMENU)ID_CHK_INVERTED, NULL, NULL);

        /* Slot / Inverted static labels */
        g_app.lbl_slot = CreateWindowA("STATIC", g_lang.label_slot,
            WS_CHILD | WS_VISIBLE, 0,0,1,1, hwnd, NULL, NULL, NULL);
        g_app.lbl_inverted_label = CreateWindowA("STATIC", g_lang.label_inverted,
            WS_CHILD | WS_VISIBLE, 0,0,1,1, hwnd, NULL, NULL, NULL);

        /* Stop-capture button (RTL only, initially hidden) */
        g_app.btn_stop_capture = CreateWindowA("BUTTON", g_lang.btn_stop_capture,
            WS_CHILD | BS_OWNERDRAW,
            0,0,1,1, hwnd, (HMENU)ID_BTN_STOP_CAPTURE, NULL, NULL);

        /* === BRUTE FORCE section === */
        y = 125;
        g_app.lbl_file = CreateWindowA("STATIC", g_lang.label_file, WS_CHILD | WS_VISIBLE | SS_RIGHT,
            20, y + 2, 70, 20, hwnd, NULL, NULL, NULL);
        g_app.edit_file = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "",
            WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
            95, y, 540, 24, hwnd, (HMENU)ID_EDIT_FILE, NULL, NULL);
        g_app.btn_browse_file = CreateWindowA("BUTTON", "...",
            WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
            640, y, 36, 24, hwnd, (HMENU)ID_BTN_BROWSE, NULL, NULL);
        g_app.payload_label = CreateWindowA("STATIC", "",
            WS_CHILD | WS_VISIBLE | SS_LEFT,
            685, y + 2, 170, 20, hwnd, (HMENU)ID_PAYLOAD_LABEL, NULL, NULL);

        g_app.lbl_kpa_badge = CreateWindowExA(0, "STATIC", "",
            WS_CHILD | SS_LEFT,   /* NOT WS_VISIBLE — starts hidden */
            0, 0, 200, 18, hwnd, (HMENU)0, NULL, NULL);

        y += 34;
        g_app.lbl_start = CreateWindowA("STATIC", g_lang.label_start_key, WS_CHILD | WS_VISIBLE | SS_RIGHT,
            20, y + 2, 70, 20, hwnd, NULL, NULL, NULL);
        g_app.edit_start = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "0000000000",
            WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
            95, y, 130, 24, hwnd, (HMENU)ID_EDIT_START, NULL, NULL);

        g_app.lbl_end = CreateWindowA("STATIC", g_lang.label_end_key, WS_CHILD | WS_VISIBLE | SS_RIGHT,
            230, y + 2, 40, 20, hwnd, NULL, NULL, NULL);
        g_app.edit_end = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "FFFFFFFFFF",
            WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
            275, y, 130, 24, hwnd, (HMENU)ID_EDIT_END, NULL, NULL);

        /* GPU % control */
        g_app.lbl_gpu_pct = CreateWindowA("STATIC", "GPU %:", WS_CHILD | WS_VISIBLE | SS_RIGHT,
            0, 0, 45, 18, hwnd, NULL, NULL, NULL);
        g_app.edit_gpu_pct = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "80",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_NUMBER | ES_CENTER,
            0, 0, 50, 24, hwnd, (HMENU)ID_EDIT_GPU_PCT, NULL, NULL);
        g_app.spin_gpu_split = CreateWindowExA(0, UPDOWN_CLASSA, NULL,
            WS_CHILD | WS_VISIBLE | UDS_SETBUDDYINT | UDS_ALIGNRIGHT | UDS_ARROWKEYS,
            0, 0, 0, 0, hwnd, (HMENU)ID_SPIN_GPU, NULL, NULL);
        SendMessageA(g_app.spin_gpu_split, UDM_SETBUDDY,  (WPARAM)g_app.edit_gpu_pct, 0);
        SendMessageA(g_app.spin_gpu_split, UDM_SETRANGE32, 50, 95);
        SendMessageA(g_app.spin_gpu_split, UDM_SETPOS32,   0, 80);
        g_app.gpu_split_pct = 80;

        { SYSTEM_INFO si; char at[16];
          GetSystemInfo(&si);
          snprintf(at, sizeof(at), "%lu", si.dwNumberOfProcessors);
          g_app.lbl_threads = CreateWindowA("STATIC", g_lang.label_threads, WS_CHILD | WS_VISIBLE | SS_RIGHT,
              420, y + 2, 50, 20, hwnd, NULL, NULL, NULL);
          g_app.edit_threads = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", at,
              WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
              475, y, 50, 24, hwnd, (HMENU)ID_EDIT_THREADS, NULL, NULL);
        }

        g_app.lbl_samples = CreateWindowA("STATIC", g_lang.label_samples, WS_CHILD | WS_VISIBLE | SS_RIGHT,
            540, y + 2, 55, 20, hwnd, NULL, NULL, NULL);
        g_app.edit_samples = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "100",
            WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
            600, y, 50, 24, hwnd, (HMENU)ID_EDIT_SAMPLES, NULL, NULL);

        y += 34;
        g_app.btn_start = CreateWindowA("BUTTON", g_lang.btn_start,
            WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
            95, y, 110, 30, hwnd, (HMENU)ID_BTN_START, NULL, NULL);
        g_app.btn_pause = CreateWindowA("BUTTON", g_lang.btn_pause,
            WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
            215, y, 110, 30, hwnd, (HMENU)ID_BTN_PAUSE, NULL, NULL);
        g_app.btn_stop = CreateWindowA("BUTTON", g_lang.btn_stop,
            WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
            335, y, 110, 30, hwnd, (HMENU)ID_BTN_STOP, NULL, NULL);
        g_app.btn_copy_key = CreateWindowA("BUTTON", g_lang.btn_copy_key,
            WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
            460, y, 70, 30, hwnd, (HMENU)ID_BTN_COPY_KEY, NULL, NULL);

        /* Initial layout */
        { RECT rc; GetClientRect(hwnd, &rc);
          layout_controls(rc.right, rc.bottom); }

        set_children_font(hwnd, g_app.ui_font);
        SetTimer(hwnd, IDT_UI_REFRESH, 200, NULL);
        updater_init();

        /* Startup sanity check: verify the bundled dsd-fme is present.
         * If the installation is incomplete the demod button is disabled
         * and a permanent warning is shown in the demod status label. */
        {
            char dsd_path_check[MAX_PATH];
            if (!resolve_tool_path("tools\\dsd-fme.exe", dsd_path_check, sizeof(dsd_path_check))) {
                EnableWindow(g_app.btn_demod, FALSE);
                SetWindowTextA(g_app.demod_label,
                    "WARNING: dsd-fme.exe not found — reinstall the app");
            }
        }
        return 0;
    }

    case WM_SIZE:
    {
        RECT rc;
        GetClientRect(hwnd, &rc);
        layout_controls(rc.right, rc.bottom);
        InvalidateRect(hwnd, NULL, TRUE);
        return 0;
    }

    case WM_GETMINMAXINFO:
    {
        MINMAXINFO *mmi = (MINMAXINFO *)lparam;
        mmi->ptMinTrackSize.x = 960;
        mmi->ptMinTrackSize.y = 740;
        return 0;
    }

    case WM_ERASEBKGND:
    {
        HDC hdc = (HDC)wparam;
        RECT rc;
        GetClientRect(hwnd, &rc);
        FillRect(hdc, &rc, g_app.br_bg);
        return 1;
    }

    case WM_CTLCOLORSTATIC:
    {
        HDC hdc = (HDC)wparam;
        SetTextColor(hdc, CLR_TEXT);
        SetBkColor(hdc, CLR_BG);
        return (LRESULT)g_app.br_bg;
    }

    case WM_CTLCOLOREDIT:
    {
        HDC hdc = (HDC)wparam;
        SetTextColor(hdc, CLR_BRIGHT);
        SetBkColor(hdc, CLR_INPUT);
        return (LRESULT)g_app.br_input;
    }

    case WM_DRAWITEM:
    {
        DRAWITEMSTRUCT *dis = (DRAWITEMSTRUCT *)lparam;
        if (dis->CtlType == ODT_BUTTON) {
            draw_button(dis);
            return TRUE;
        }
        break;
    }

    case WM_COMMAND:
        switch (LOWORD(wparam)) {
        case ID_RADIO_WAV:
            g_app.capture_mode = 0;
            update_capture_mode_visibility();
            layout_controls_current();
            return 0;
        case ID_RADIO_RTL:
            g_app.capture_mode = 1;
            update_capture_mode_visibility();
            layout_controls_current();
            return 0;
        case ID_BTN_STOP_CAPTURE:
            InterlockedExchange(&g_app.demod_running, 0);
            return 0;
        case ID_BTN_BROWSE:     choose_file(hwnd); return 0;
        case ID_BTN_BROWSE_WAV: choose_wav_file(hwnd); return 0;
        case ID_BTN_DEMOD:      start_demod(hwnd); return 0;
        case ID_BTN_EXPORT:     export_bin_file(hwnd); return 0;
        case ID_BTN_START:      start_bruteforce(hwnd); return 0;
        case ID_BTN_PAUSE:      on_pause_resume(); return 0;
        case ID_BTN_STOP:       on_stop(); return 0;
        case ID_BTN_COPY_KEY:   copy_key_to_clipboard(hwnd); return 0;
        case ID_BTN_HELP:       show_help_dialog(hwnd); return 0;
        case ID_BTN_LANG:
            g_lang_ptr = (g_lang_ptr == &g_lang_es) ? &g_lang_en : &g_lang_es;
            lang_save();
            apply_language();
            return 0;
        }
        break;

    case WM_TIMER:
        if (wparam == IDT_UI_REFRESH) {
            refresh_snapshot_and_ui();

            /* CUDA fallback: if CUDA error while still running, switch to CPU */
            if (!g_app.fallback_triggered
                && g_app.engine.cuda_active
                && g_app.engine.cuda_error[0]
                && g_app.snapshot.running
                && !g_app.snapshot.paused)
            {
                g_app.fallback_triggered = 1;
                g_app.fallback_banner_ticks = 32; /* 8 seconds @ 4 ticks/sec */

                uint64_t keys_done = g_app.snapshot.keys_tested;
                bruteforce_stop(&g_app.engine);

                BruteforceConfig fallback_cfg = g_app.last_cfg;
                if (keys_done < fallback_cfg.end_key - fallback_cfg.start_key)
                    fallback_cfg.start_key += keys_done;
                fallback_cfg.thread_count = 4;
                g_app.engine.cuda_error[0] = '\0';

                char ferr[256] = {0};
                bruteforce_start(&g_app.engine, &fallback_cfg, &g_app.payloads, ferr, sizeof(ferr));
                g_app.hist_count = g_app.hist_pos = 0;
                g_app.score_hist_count = g_app.score_hist_pos = 0;
            }

            /* Countdown banner */
            if (g_app.fallback_banner_ticks > 0) {
                g_app.fallback_banner_ticks--;
                InvalidateRect(g_app.hwnd, &g_app.status_strip_rect, FALSE);
            }
        }
        return 0;

    case WM_APP_DEMOD_DONE:
        return 0;

    case WM_PAINT:
    {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);
        SetBkMode(hdc, TRANSPARENT);

        RECT cli;
        GetClientRect(hwnd, &cli);
        int cw = cli.right;
        draw_header(hdc, cw);

        /* Section headers */
        draw_section_header(hdc, 20,        HEADER_H + 8, cw/2 - 30, g_lang.section_capture);
        draw_section_header(hdc, cw/2 + 10, HEADER_H + 8, cw/2 - 30, g_lang.section_bruteforce);

        /* Metric tiles + status strip */
        draw_all_tiles(hdc);
        draw_status_strip(hdc);

        /* Graphs */
        draw_graph(hdc, &g_app.graph_rect);
        draw_score_graph(hdc, &g_app.score_graph_rect);
        draw_progress(hdc, &g_app.progress_rect);
        EndPaint(hwnd, &ps);
        return 0;
    }

    case WM_NOTIFY:
    {
        NMHDR *hdr = (NMHDR *)lparam;
        if (hdr->idFrom == ID_SPIN_GPU && hdr->code == UDN_DELTAPOS) {
            NMUPDOWN *pud = (NMUPDOWN *)lparam;
            int newval = pud->iPos + pud->iDelta;
            if (newval < 50) newval = 50;
            if (newval > 95) newval = 95;
            newval = (newval / 5) * 5;  /* snap to multiple of 5 */
            g_app.gpu_split_pct = newval;
            /* Push snapped value back so display matches */
            SendMessageA(g_app.spin_gpu_split, UDM_SETPOS32, 0, (LPARAM)newval);
            char buf[8];
            snprintf(buf, sizeof(buf), "%d", newval);
            SetWindowTextA(g_app.edit_gpu_pct, buf);
            /* Return TRUE to prevent UpDown from applying the raw delta */
            SetWindowLongPtrA(hwnd, DWLP_MSGRESULT, TRUE);
            return TRUE;
        }
        break;
    }

    case WM_DESTROY:
        KillTimer(hwnd, IDT_UI_REFRESH);
        if (g_app.hwnd_help && IsWindow(g_app.hwnd_help)) {
            DestroyWindow(g_app.hwnd_help);
            g_app.hwnd_help = NULL;
        }
        if (g_app.ui_font)         { DeleteObject(g_app.ui_font); g_app.ui_font = NULL; }
        if (g_app.ui_font_bold)    { DeleteObject(g_app.ui_font_bold); g_app.ui_font_bold = NULL; }
        if (g_app.ui_font_section) { DeleteObject(g_app.ui_font_section); g_app.ui_font_section = NULL; }
        if (g_app.font_tile_metric) { DeleteObject(g_app.font_tile_metric); g_app.font_tile_metric = NULL; }
        if (g_app.font_tile_label)  { DeleteObject(g_app.font_tile_label);  g_app.font_tile_label  = NULL; }
        if (g_app.font_header)      { DeleteObject(g_app.font_header);      g_app.font_header      = NULL; }
        if (g_app.font_header_sub)  { DeleteObject(g_app.font_header_sub);  g_app.font_header_sub  = NULL; }
        destroy_theme_brushes();
        bruteforce_stop(&g_app.engine);
        bruteforce_engine_destroy(&g_app.engine);
        payload_set_free(&g_app.payloads);
        if (g_app.demod_thread) {
            WaitForSingleObject(g_app.demod_thread, 5000);
            CloseHandle(g_app.demod_thread);
            g_app.demod_thread = NULL;
        }
        updater_cleanup();
        PostQuitMessage(0);
        return 0;
    }

    return DefWindowProcA(hwnd, msg, wparam, lparam);
}

int run_gui(HINSTANCE instance, int cmd_show)
{
    WNDCLASSA wc;
    MSG msg;

    InitCommonControls();

    ZeroMemory(&g_app, sizeof(g_app));
    payload_set_init(&g_app.payloads);
    bruteforce_engine_init(&g_app.engine);

    ZeroMemory(&wc, sizeof(wc));
    wc.lpfnWndProc = wnd_proc;
    wc.hInstance = instance;
    wc.lpszClassName = APP_CLASS_NAME;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = NULL;  /* We handle WM_ERASEBKGND */

    if (!RegisterClassA(&wc)) {
        MessageBoxA(NULL, g_lang.err_wnd_class, APP_TITLE, MB_ICONERROR);
        return 1;
    }

    /* Register help window class */
    ZeroMemory(&wc, sizeof(wc));
    wc.lpfnWndProc = help_wnd_proc;
    wc.hInstance = instance;
    wc.lpszClassName = HELP_CLASS_NAME;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = NULL;
    RegisterClassA(&wc);

    g_app.hwnd = CreateWindowExA(
        0, APP_CLASS_NAME, APP_TITLE,
        WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
        CW_USEDEFAULT, CW_USEDEFAULT, 940, 720,
        NULL, NULL, instance, NULL);

    if (!g_app.hwnd) {
        MessageBoxA(NULL, g_lang.err_wnd_create, APP_TITLE, MB_ICONERROR);
        return 1;
    }

    ShowWindow(g_app.hwnd, cmd_show);
    UpdateWindow(g_app.hwnd);

    while (GetMessageA(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageA(&msg);
    }

    return (int)msg.wParam;
}
