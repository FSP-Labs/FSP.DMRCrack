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

#define IDT_UI_REFRESH  2001
#define WM_APP_DEMOD_DONE       (WM_APP + 1)
#define WM_APP_UPDATE_AVAILABLE (WM_APP + 2)

/* --- Dark theme colors --- */
#define CLR_BG          RGB(30, 30, 30)
#define CLR_PANEL       RGB(37, 37, 38)
#define CLR_INPUT       RGB(51, 51, 51)
#define CLR_INPUT_BORDER RGB(62, 62, 66)
#define CLR_TEXT        RGB(204, 204, 204)
#define CLR_BRIGHT      RGB(255, 255, 255)
#define CLR_DIM         RGB(128, 128, 128)
#define CLR_ACCENT      RGB(0, 120, 215)
#define CLR_ACCENT_HOV  RGB(28, 145, 235)
#define CLR_ACCENT_PRESS RGB(0, 84, 153)
#define CLR_GREEN       RGB(78, 201, 176)
#define CLR_ORANGE      RGB(206, 145, 120)
#define CLR_RED         RGB(244, 71, 71)
#define CLR_GRAPH_BG    RGB(37, 37, 38)
#define CLR_GRAPH_AXIS  RGB(80, 80, 80)
#define CLR_GRAPH_LINE1 RGB(86, 156, 214)
#define CLR_GRAPH_LINE2 RGB(215, 186, 125)
#define CLR_GRAPH_THRESH RGB(78, 201, 176)
#define CLR_PROGRESS_BG RGB(45, 45, 48)
#define CLR_SECTION     RGB(0, 120, 215)

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
    HWND status_text;

    HWND edit_wav;
    HWND btn_browse_wav;
    HWND btn_demod;
    HWND btn_export;
    HWND demod_label;

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

    snprintf(text, sizeof(text),
        "Claves probadas: %llu / %llu (%.2f%%)\r\n"
        "Velocidad: %.2f claves/s\r\n"
        "Tiempo: %s  |  ETA: %s\r\n"
        "Backend: %s\r\n"
        "Mejor candidata: %s\r\n"
        "Mejor score: %s\r\n"
        "Estado: %s",
        (unsigned long long)g_app.snapshot.keys_tested,
        (unsigned long long)g_app.snapshot.total_keys, pct,
        g_app.snapshot.keys_per_second,
        elapsed, eta,
        g_app.engine.cuda_active ? "CUDA GPU" : "CPU",
        best_key_buf,
        (!isfinite(g_app.snapshot.best_score) || g_app.snapshot.best_score <= -1e30) ? "---" :
            (snprintf(score_buf, sizeof(score_buf), "%.4f", g_app.snapshot.best_score), score_buf),
        g_app.snapshot.running ? (g_app.snapshot.paused ? "PAUSADO" : "EJECUTANDO") : "DETENIDO");

    if (g_app.engine.cuda_active && g_app.engine.cuda_device_name[0])
        snprintf(text + strlen(text), sizeof(text) - strlen(text),
                 "\r\nGPU: %s", g_app.engine.cuda_device_name);

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
                 "\r\nError CUDA: %s", g_app.engine.cuda_error);

    SetWindowTextA(g_app.status_text, text);
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
    {
        char lbl[64];
        snprintf(lbl, sizeof(lbl), "Claves/s (historial)");
        TextOutA(hdc, rect->left + 35, rect->top + 6, lbl, (int)strlen(lbl));
    }
    /* Current value top-right */
    if (g_app.hist_count > 0) {
        char val[32];
        double last = g_app.kps_history[(g_app.hist_pos + g_app.hist_count - 1) % 120];
        if (last >= 1e6) snprintf(val, sizeof(val), "%.1f M/s", last / 1e6);
        else if (last >= 1e3) snprintf(val, sizeof(val), "%.1f K/s", last / 1e3);
        else snprintf(val, sizeof(val), "%.0f /s", last);
        SetTextColor(hdc, CLR_BRIGHT);
        TextOutA(hdc, rect->right - 100, rect->top + 6, val, (int)strlen(val));
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
    TextOutA(hdc, rect->left + 35, rect->top + 6, "Mejor score (evolucion)", 23);
    /* Current value */
    if (g_app.score_hist_count > 0) {
        char val[32];
        double last = g_app.score_history[(g_app.score_hist_pos + g_app.score_hist_count - 1) % 120];
        snprintf(val, sizeof(val), "%.1f", last);
        SetTextColor(hdc, CLR_BRIGHT);
        TextOutA(hdc, rect->right - 80, rect->top + 6, val, (int)strlen(val));
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

/* --- File dialogs --- */
static void choose_file(HWND owner)
{
    OPENFILENAMEA ofn;
    char file[MAX_PATH] = {0};
    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = owner;
    ofn.lpstrFilter = "BIN payload (*.bin)\0*.bin\0Todos (*.*)\0*.*\0";
    ofn.lpstrFile = file;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    if (GetOpenFileNameA(&ofn))
        SetWindowTextA(g_app.edit_file, file);
}

static void choose_wav_file(HWND owner)
{
    OPENFILENAMEA ofn;
    char file[MAX_PATH] = {0};
    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = owner;
    ofn.lpstrFilter = "Audio DMR (*.wav;*.mp3;*.flac;*.ogg)\0*.wav;*.mp3;*.flac;*.ogg\0"
                      "WAV (*.wav)\0*.wav\0Todos (*.*)\0*.*\0";
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
    if (GetCurrentDirectoryA(MAX_PATH, cwd) > 0) {
        snprintf(out, out_len, "%s\\%s", cwd, tool_rel);
        if (file_exists(out)) return 1;
    }
    if (GetModuleFileNameA(NULL, exe_path, MAX_PATH) == 0) return 0;
    slash = strrchr(exe_path, '\\');
    if (!slash) return 0;
    *slash = '\0';
    snprintf(out, out_len, "%s\\%s", exe_path, tool_rel);
    return file_exists(out);
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
            si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
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

/* Locate the DSP output file produced by dsd-fme -Q <qname>.
 * base_dir is the working directory dsd-fme ran in (the WAV file's directory).
 * dsd-fme writes to base_dir\DSP\qname or base_dir\qname depending on version. */
static int find_dsp_file(const char *qname, const char *base_dir,
                          char *out_path, size_t out_len)
{
    char candidate[MAX_PATH];
    snprintf(candidate, sizeof(candidate), "%s\\DSP\\%s", base_dir, qname);
    if (file_exists(candidate)) { snprintf(out_path, out_len, "%s", candidate); return 1; }
    snprintf(candidate, sizeof(candidate), "%s\\%s", base_dir, qname);
    if (file_exists(candidate)) { snprintf(out_path, out_len, "%s", candidate); return 1; }
    return 0;
}

/* --- Demodulation thread ---
 * Runs dsd-fme.exe and dsdfme_dsp_to_bin.py directly via CreateProcessA,
 * without cmd.exe as an intermediary, to avoid shell metacharacter injection. */
static DWORD WINAPI demod_thread_proc(LPVOID param)
{
    char wav_path[MAX_PATH], err[256] = {0};
    char dsd_path[MAX_PATH], py_script[MAX_PATH];
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
        goto done;
    }
    if (!resolve_tool_path("tools\\dsdfme_dsp_to_bin.py", py_script, sizeof(py_script))) {
        SetWindowTextA(g_app.demod_label, g_lang.err_py_script_missing);
        goto done;
    }

    /* Build output paths */
    _splitpath_s(wav_path, drive, sizeof(drive), dir, sizeof(dir), fname, sizeof(fname), ext, sizeof(ext));
    snprintf(out_bin,  sizeof(out_bin),  "%s%s%s.fromdsdfme.bin", drive, dir, fname);
    snprintf(logfile,  sizeof(logfile),  "%s%s%s.dslog.txt",      drive, dir, fname);
    snprintf(wav_dir,  sizeof(wav_dir),  "%s%s", drive, dir);
    /* Remove trailing backslash so CreateProcess lpCurrentDirectory is valid */
    { size_t wdl = strlen(wav_dir); if (wdl > 1 && wav_dir[wdl-1] == '\\') wav_dir[wdl-1] = '\0'; }

    /* qname is filename-only; dsd-fme writes it relative to its own CWD (wav_dir) */
    _splitpath_s(out_bin, ob_drive, sizeof(ob_drive), ob_dir, sizeof(ob_dir),
                 ob_fname, sizeof(ob_fname), ob_ext, sizeof(ob_ext));
    snprintf(qname, sizeof(qname), "%s.dsdsp.txt", ob_fname);

    /* Paths are embedded in a quoted command line; '"' would break quoting. */
    if (strchr(dsd_path,  '"') || strchr(wav_path,  '"') || strchr(qname,     '"') ||
        strchr(out_bin,   '"') || strchr(logfile,   '"') || strchr(py_script, '"')) {
        SetWindowTextA(g_app.demod_label, g_lang.err_path_has_quotes);
        goto done;
    }

    /* Clean up outputs from previous runs */
    DeleteFileA(out_bin);
    DeleteFileA(logfile);

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

    /* Step 1/2: run dsd-fme.exe directly (no shell), stderr → log file */
    SetWindowTextA(g_app.demod_label, g_lang.status_demodulating);
    snprintf(cmdline, sizeof(cmdline), "\"%s\" -fs -i \"%s\" -Q \"%s\" -Z",
             dsd_path, wav_path, qname);
    if (!run_process_stderr_redirect(cmdline, logfile, wav_dir, &proc_exit) || proc_exit != 0) {
        /* 0xC0000135 = STATUS_DLL_NOT_FOUND -- Cygwin runtime missing */
        if (proc_exit == 0xC0000135u || proc_exit == 0xC0000139u) {
            SetWindowTextA(g_app.demod_label, g_lang.err_dll_not_found_exit);
        } else {
            SetWindowTextA(g_app.demod_label,
                proc_exit ? g_lang.err_dsd_failed : g_lang.err_dsd_launch);
        }
        goto done;
    }

    /* Locate the DSP output file that dsd-fme wrote */
    if (!find_dsp_file(qname, wav_dir, dspfile, sizeof(dspfile))) {
        SetWindowTextA(g_app.demod_label, g_lang.err_no_dsp_output);
        goto done;
    }

    /* Step 2/2: run dsdfme_dsp_to_bin.py directly via py launcher (no shell) */
    SetWindowTextA(g_app.demod_label, g_lang.status_converting);
    snprintf(cmdline, sizeof(cmdline),
             "py -3 \"%s\" --dsp \"%s\" --out \"%s\" --log \"%s\"",
             py_script, dspfile, out_bin, logfile);
    if (!run_process_and_wait(cmdline, &proc_exit) || proc_exit != 0) {
        SetWindowTextA(g_app.demod_label, g_lang.err_dsp_conversion);
        goto done;
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
        char msg[320];
        snprintf(msg, sizeof(msg), "OK: %zu payloads -> %s", g_app.payloads.count, out_bin);
        SetWindowTextA(g_app.demod_label, msg);
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
    update_status_text();
    if (g_app.snapshot.running)
        SetWindowTextA(g_app.btn_pause, g_app.snapshot.paused ? g_lang.btn_resume : g_lang.btn_pause);
    else
        SetWindowTextA(g_app.btn_pause, g_lang.btn_pause);
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

    if (g_app.payloads.count < 64)
        MessageBoxA(hwnd, g_lang.warn_few_payloads, APP_TITLE, MB_ICONWARNING);

    cfg.start_key = start_key;
    cfg.end_key = end_key;
    cfg.thread_count = threads;
    cfg.sample_lines = samples;
    { size_t ml = 0;
      for (size_t i = 0; i < g_app.payloads.count; ++i)
          if (g_app.payloads.items[i].len > ml) ml = g_app.payloads.items[i].len;
      cfg.sample_bytes = (ml >= 33) ? 33 : 27;
    }

    if (!bruteforce_start(&g_app.engine, &cfg, &g_app.payloads, err, sizeof(err))) {
        MessageBoxA(hwnd, err, APP_TITLE, MB_ICONERROR);
        return 0;
    }

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

    br = CreateSolidBrush(bg_clr);
    FillRect(dis->hDC, &r, br);
    DeleteObject(br);

    GetWindowTextA(dis->hwndItem, text, sizeof(text));
    SetBkMode(dis->hDC, TRANSPARENT);
    SetTextColor(dis->hDC, txt_clr);
    SelectObject(dis->hDC, g_app.ui_font_bold);
    DrawTextA(dis->hDC, text, -1, &r, DT_CENTER | DT_VCENTER | DT_SINGLELINE);

    if (dis->itemState & ODS_FOCUS) {
        HPEN pen = CreatePen(PS_SOLID, 1, CLR_BRIGHT);
        HPEN old = (HPEN)SelectObject(dis->hDC, pen);
        HBRUSH null_br = (HBRUSH)GetStockObject(NULL_BRUSH);
        HBRUSH old_br = (HBRUSH)SelectObject(dis->hDC, null_br);
        Rectangle(dis->hDC, r.left, r.top, r.right, r.bottom);
        SelectObject(dis->hDC, old);
        SelectObject(dis->hDC, old_br);
        DeleteObject(pen);
    }
}

/* --- Window procedure --- */
static LRESULT CALLBACK wnd_proc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
    switch (msg) {
    case WM_CREATE:
    {
        int y;
        create_theme_brushes();
        g_app.ui_font = create_ui_font(0, 0);
        g_app.ui_font_bold = create_ui_font(1, 0);
        g_app.ui_font_section = create_ui_font(1, -2);

        /* Enable dark title bar */
        { BOOL dark = TRUE;
          DwmSetWindowAttribute(hwnd, 20, &dark, sizeof(dark)); }

        y = 15;

        /* === CAPTURA section === */
        /* Section header drawn in WM_PAINT */

        y = 40;
        CreateWindowA("STATIC", g_lang.label_audio, WS_CHILD | WS_VISIBLE | SS_RIGHT,
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
            795, y, 85, 24, hwnd, (HMENU)ID_BTN_EXPORT, NULL, NULL);

        y += 28;
        g_app.demod_label = CreateWindowA("STATIC", "",
            WS_CHILD | WS_VISIBLE | SS_LEFT,
            95, y, 690, 16, hwnd, NULL, NULL, NULL);

        /* === FUERZA BRUTA section === */
        y = 105;

        y = 125;
        CreateWindowA("STATIC", g_lang.label_file, WS_CHILD | WS_VISIBLE | SS_RIGHT,
            20, y + 2, 70, 20, hwnd, NULL, NULL, NULL);
        g_app.edit_file = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "",
            WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
            95, y, 540, 24, hwnd, (HMENU)ID_EDIT_FILE, NULL, NULL);
        CreateWindowA("BUTTON", "...",
            WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
            640, y, 36, 24, hwnd, (HMENU)ID_BTN_BROWSE, NULL, NULL);

        y += 34;
        CreateWindowA("STATIC", g_lang.label_start_key, WS_CHILD | WS_VISIBLE | SS_RIGHT,
            20, y + 2, 70, 20, hwnd, NULL, NULL, NULL);
        g_app.edit_start = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "0000000000",
            WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
            95, y, 130, 24, hwnd, (HMENU)ID_EDIT_START, NULL, NULL);

        CreateWindowA("STATIC", g_lang.label_end_key, WS_CHILD | WS_VISIBLE | SS_RIGHT,
            230, y + 2, 40, 20, hwnd, NULL, NULL, NULL);
        g_app.edit_end = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "FFFFFFFFFF",
            WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
            275, y, 130, 24, hwnd, (HMENU)ID_EDIT_END, NULL, NULL);

        { SYSTEM_INFO si; char at[16];
          GetSystemInfo(&si);
          snprintf(at, sizeof(at), "%lu", si.dwNumberOfProcessors);
          CreateWindowA("STATIC", g_lang.label_threads, WS_CHILD | WS_VISIBLE | SS_RIGHT,
              420, y + 2, 50, 20, hwnd, NULL, NULL, NULL);
          g_app.edit_threads = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", at,
              WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
              475, y, 50, 24, hwnd, (HMENU)ID_EDIT_THREADS, NULL, NULL);
        }

        CreateWindowA("STATIC", g_lang.label_samples, WS_CHILD | WS_VISIBLE | SS_RIGHT,
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

        /* Status text */
        y += 42;
        g_app.status_text = CreateWindowExA(0, "STATIC", g_lang.btn_ready,
            WS_CHILD | WS_VISIBLE | SS_LEFT,
            25, y, 850, 110, hwnd, (HMENU)ID_STATUS_TEXT, NULL, NULL);

        /* Graph rects */
        g_app.graph_rect.left = 20;
        g_app.graph_rect.top = 340;
        g_app.graph_rect.right = 890;
        g_app.graph_rect.bottom = 475;

        g_app.score_graph_rect.left = 20;
        g_app.score_graph_rect.top = 485;
        g_app.score_graph_rect.right = 890;
        g_app.score_graph_rect.bottom = 620;

        g_app.progress_rect.left = 20;
        g_app.progress_rect.top = 635;
        g_app.progress_rect.right = 890;
        g_app.progress_rect.bottom = 660;

        set_children_font(hwnd, g_app.ui_font);
        SetTimer(hwnd, IDT_UI_REFRESH, 200, NULL);
        updater_check_async(hwnd, WM_APP_UPDATE_AVAILABLE);
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
        case ID_BTN_BROWSE:     choose_file(hwnd); return 0;
        case ID_BTN_BROWSE_WAV: choose_wav_file(hwnd); return 0;
        case ID_BTN_DEMOD:      start_demod(hwnd); return 0;
        case ID_BTN_EXPORT:     export_bin_file(hwnd); return 0;
        case ID_BTN_START:      start_bruteforce(hwnd); return 0;
        case ID_BTN_PAUSE:      on_pause_resume(); return 0;
        case ID_BTN_STOP:       on_stop(); return 0;
        }
        break;

    case WM_TIMER:
        if (wparam == IDT_UI_REFRESH) refresh_snapshot_and_ui();
        return 0;

    case WM_APP_DEMOD_DONE:
        return 0;

    case WM_APP_UPDATE_AVAILABLE:
    {
        char *ver = (char *)lparam;
        char msg[256];
        snprintf(msg, sizeof(msg), g_lang.update_available, ver ? ver : "");
        free(ver);
        if (MessageBoxA(hwnd, msg, g_lang.update_title,
                        MB_ICONINFORMATION | MB_YESNO | MB_DEFBUTTON1) == IDYES) {
            ShellExecuteA(NULL, "open",
                "https://github.com/" DMRCRACK_GITHUB_OWNER "/" DMRCRACK_GITHUB_REPO "/releases/latest",
                NULL, NULL, SW_SHOWNORMAL);
        }
        return 0;
    }

    case WM_PAINT:
    {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);
        SetBkMode(hdc, TRANSPARENT);

        /* Section headers */
        draw_section_header(hdc, 20, 15, 860, g_lang.section_capture);
        draw_section_header(hdc, 20, 100, 860, g_lang.section_bruteforce);

        /* Graphs */
        draw_graph(hdc, &g_app.graph_rect);
        draw_score_graph(hdc, &g_app.score_graph_rect);
        draw_progress(hdc, &g_app.progress_rect);
        EndPaint(hwnd, &ps);
        return 0;
    }

    case WM_DESTROY:
        KillTimer(hwnd, IDT_UI_REFRESH);
        if (g_app.ui_font)         { DeleteObject(g_app.ui_font); g_app.ui_font = NULL; }
        if (g_app.ui_font_bold)    { DeleteObject(g_app.ui_font_bold); g_app.ui_font_bold = NULL; }
        if (g_app.ui_font_section) { DeleteObject(g_app.ui_font_section); g_app.ui_font_section = NULL; }
        destroy_theme_brushes();
        bruteforce_stop(&g_app.engine);
        bruteforce_engine_destroy(&g_app.engine);
        payload_set_free(&g_app.payloads);
        if (g_app.demod_thread) {
            WaitForSingleObject(g_app.demod_thread, 5000);
            CloseHandle(g_app.demod_thread);
            g_app.demod_thread = NULL;
        }
        PostQuitMessage(0);
        return 0;
    }

    return DefWindowProcA(hwnd, msg, wparam, lparam);
}

int run_gui(HINSTANCE instance, int cmd_show)
{
    WNDCLASSA wc;
    MSG msg;

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

    g_app.hwnd = CreateWindowExA(
        0, APP_CLASS_NAME, APP_TITLE,
        WS_OVERLAPPEDWINDOW,
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
