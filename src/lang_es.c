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
 * lang_es.c - Tabla de cadenas en espanol
 *
 * Para compilar en espanol, enlazar lang_es.c en lugar de lang_en.c.
 */
#include "../include/lang.h"

const Lang g_lang_es = {
    /* ---- Etiquetas ---- */
    .label_audio      = "WAV:",
    .label_file       = ".bin:",
    .label_start_key  = "Inicio:",
    .label_end_key    = "Fin:",
    .label_threads    = "Hilos:",
    .label_samples    = "Muestras:",
    .label_gpu_pct    = "GPU %:",
    .label_temp_limit = "Max C:",

    /* Titulos de tiles */
    .tile_throughput     = "VELOCIDAD",
    .tile_progress       = "PROGRESO",
    .tile_candidate      = "MEJOR CANDIDATO",
    /* Cuerpo de los tiles */
    .tile_cpu_only            = "Solo CPU",
    .tile_split_fmt           = "GPU  %s  \xb7  CPU  %s",
    .tile_score_fmt           = "Puntuaci\xf3n  %.2f",
    .tile_progress_meta_fmt   = "%s claves   \xb7   ETA  %s   \xb7   transcurrido  %s",
    .tile_gpu_temp_fmt        = "GPU  %d C",
    .tile_gpu_temp_paused_fmt = "GPU  %d C  \xb7  enfriando, en pausa",
    .empty_hint               = "Carga un .bin o captura en vivo, luego pulsa Start",
    .no_candidate_hint        = "Sin clave sobre el umbral",
    .diag_best_fmt            = "mejor visto  %.1f/burst en %d bursts",
    .status_idle              = "En reposo",
    .status_searching         = "Buscando...",
    .graph_waiting            = "esperando datos",
    /* Veredicto de confianza de la clave recuperada */
    .conf_confirmed           = "CONFIRMADA",
    .conf_unverified          = "SIN VERIFICAR - confirma con DSD-FME",
    .conf_no_key              = "Sin clave confirmada",
    .conf_searching           = "Buscando - aun sin clave confirmada",
    .conf_sigma_fmt           = "  %.1f sigma",
    /* Badge KPA */
    .kpa_silence_fmt          = "KPA: %u tramas de silencio",
    /* Barra de estado */
    .status_backend_cuda = "GPU CUDA",
    .status_backend_cpu  = "CPU",
    .msg_cuda_fallback   = "Error CUDA \x97 continuando en CPU",
    /* Validacion de payloads */
    .val_payloads_ok     = "%zu payloads  \xb7  KMI9: %zu/%zu  \xb7  KID=%02X",
    .val_align_warn      = "! Advertencia de alineamiento",
    .warn_low_payloads_n = "! Solo %zu payloads -- baja confianza, riesgo de falso positivo",

    /* ---- Botones ---- */
    .btn_demodulate = "Demodular",
    .btn_export     = "Exportar",
    .btn_start      = "Iniciar",
    .btn_pause      = "Pausar",
    .btn_resume     = "Reanudar",
    .btn_stop       = "Detener",
    .btn_ready      = "Listo",

    /* ---- Estado / errores de demodulacion ---- */
    .status_demodulating       = "Demodulando con DSD-FME... [1/2]",
    .status_converting         = "Convirtiendo DSP a BIN... [2/2]",
    .status_demod_in_memory    = "(demodulado en memoria)",
    .err_demod_already_running = "Ya hay una demodulacion en curso",
    .err_demod_thread          = "Error al crear el hilo de demodulacion",
    .err_no_audio_selected     = "Error: selecciona un archivo de audio primero",
    .err_audio_not_found       = "Error: archivo de audio no encontrado o inaccesible",
    .err_path_has_quotes       = "Error: la ruta contiene caracteres no validos (\")",
    .err_cygwin_dlls_missing   = "Error: faltan DLLs de Cygwin junto a dsd-fme.exe "
                                 "(cygwin1.dll, cyggcc_s-seh-1.dll, ...)",
    .err_dll_not_found_exit    = "Error: DLL no encontrada al lanzar DSD-FME "
                                 "(coloca cygwin1.dll y dependencias junto a dsd-fme.exe)",
    .err_dsd_failed            = "DSD-FME fallo (ver detalles)",
    .err_dsd_launch            = "Error al lanzar DSD-FME",
    .err_no_dsp_output         = "Error: salida DSP no encontrada (ver detalles)",
    .err_dsp_conversion        = "Error: conversion DSP->BIN fallida",
    .err_dsd_missing           = "Error: falta dsd-fme.exe \x97 reinstala la aplicaci\xf3n",
    .err_dsd_missing_detail    = "No se encontr\xf3 dsd-fme.exe en la carpeta tools\\.\n\n"
                                 "La instalaci\xf3n puede estar incompleta o corrupta.\n"
                                 "Reinstala FSP.DMRCrack.",
    .warn_dsd_missing_startup  = "AVISO: dsd-fme.exe no encontrado \x97 reinstala la aplicaci\xf3n",
    .msg_demod_ok_fmt          = "OK: %zu payloads -> %s",
    .err_dsd_detail_fmt        = "%s (salida %lu)\n\nLog: %s\n\n%s",
    .err_no_dsp_detail_fmt     = "%s\n\nLog: %s\n\nSalida de dsd-fme:\n%s",
    .lbl_empty_log             = "(log vac\xedo)",
    .lbl_empty_log_no_output   = "(log vac\xedo \x97 dsd-fme no produjo salida)",
    .err_py_script_missing     = "Error: falta tools\\dsdfme_dsp_to_bin.py",
    .err_bin_load              = "Error al cargar el archivo BIN generado",

    /* ---- Escucha: desencriptar audio recuperado a WAV ---- */
    .btn_listen                 = "Escuchar",
    .status_decrypting          = "Desencriptando audio con DSD-FME...",
    .err_listen_already_running = "Desencriptado ya en curso",
    .err_listen_thread          = "Error al crear el hilo de desencriptado",
    .err_listen_no_source       = "Selecciona el WAV de origen (campo de audio) para reproducir el audio desencriptado",
    .err_listen_no_key          = "Aun no hay clave recuperada - ejecuta una busqueda primero",
    .msg_listen_ok_fmt          = "Audio desencriptado: %s",

    /* ---- Captura en vivo (RTL-SDR, supervisada desatendida) ---- */
    .btn_capture_start          = "Captura en vivo",
    .btn_capture_stop           = "Detener captura",
    .err_capture_no_spec        = "Indica un spec RTL-SDR en el campo Audio, p.ej. rtl:0:451.2M:22",
    .err_capture_launch         = "No se pudo iniciar la captura en vivo (revisa DSD-FME / RTL-SDR)",
    .err_capture_no_device      = "RTL-SDR no abierto: conectado? driver WinUSB (Zadig)? cerrado en SDR#/otra app SDR?",
    .err_capture_died           = "dsd-fme salio antes de tiempo - mira live.log en la carpeta de sesion",
    .cap_sync_ok                = "senal OK",
    .cap_sync_none              = "sin senal",
    .cap_status_fmt             = "Captura en vivo | %s | %zu tramas cifradas | %s",
    .cap_target_fmt             = "Objetivo alcanzado (%zu tramas) - iniciando crackeo",
    .cap_dlg_title              = "Escuchar un canal de radio",
    .cap_intro                  = "Conecta tu receptor SDR y la antena, y escribe la frecuencia que\r\nquieres escuchar. La app captura las llamadas cifradas sola y\r\nempieza a descifrar cuando tiene suficiente. Pulsa Iniciar y espera.",
    .cap_lbl_freq               = "Frecuencia de radio",
    .cap_freq_hint              = "En MHz - por ejemplo  461.8375",
    .cap_adv_show               = "Mas opciones",
    .cap_adv_hide               = "Menos opciones",
    .cap_lbl_dev                = "Numero de dispositivo SDR",
    .cap_hint_dev               = "Deja 0 si tienes un solo SDR",
    .cap_lbl_gain               = "Ganancia de senal",
    .cap_hint_gain              = "0 = automatica (recomendado)",
    .cap_lbl_ppm                = "Correccion de frecuencia",
    .cap_hint_ppm               = "Deja 0 si no estas seguro",
    .cap_btn_ok                 = "Iniciar",
    .cap_btn_cancel             = "Cancelar",

    /* ---- Errores de validacion de fuerza bruta ---- */
    .err_no_bin_selected   = "Selecciona un archivo .bin de payloads primero",
    .err_start_key_invalid = "Clave inicial no valida (hex, 1-10 digitos)",
    .err_end_key_invalid   = "Clave final no valida (hex, 1-10 digitos)",
    .err_threads_empty     = "Numero de hilos no valido",
    .err_threads_range     = "Los hilos deben estar entre 1 y 64",
    .err_samples_empty     = "Numero de muestras no valido",
    .err_samples_range     = "Las muestras deben estar entre 1 y 100000",
    .warn_few_payloads     = "Aviso: pocas lineas de payload (<64).\n"
                             "Considera capturar mas tramas de voz.",

    /* ---- Exportar ---- */
    .err_no_payloads_export = "No hay payloads cargados para exportar.",
    .msg_exported           = "Exportadas %zu lineas a:\n%s",
    .dlg_export_filter      = "Archivo BIN de payloads (*.bin)\0*.bin\0Todos los archivos (*.*)\0*.*\0",

    /* ---- Errores fatales / inicio ---- */
    .err_wnd_class  = "Error al registrar la clase de ventana",
    .err_wnd_create = "Error al crear la ventana principal",

    /* ---- Errores de arranque del motor ---- */
    .err_search_already_active = "Ya hay una b\xfasqueda en curso",
    .err_start_gt_end          = "La clave inicial debe ser <= a la final",
    .err_end_exceeds_40bit     = "La clave final excede 40 bits",
    .err_no_payloads_loaded    = "No hay payloads cargados",
    .err_pause_event_failed    = "No se pudo crear el evento de pausa",
    .err_oom_cpu_threads       = "Sin memoria para los hilos de CPU",
    .err_create_cpu_threads    = "Error al crear los hilos de CPU",
    .err_oom_handles           = "Sin memoria para los handles de hilo",
    .err_create_cuda_thread    = "Error al crear el hilo lanzador CUDA",

    /* ---- Cadenas de formato del panel de estado ---- */
    .fmt_keys_tested    = "Claves probadas: %llu / %llu (%.2f%%)",
    .fmt_speed          = "Velocidad: %.2f claves/s",
    .fmt_time           = "Tiempo: %s  |  ETA: %s",
    .fmt_backend        = "Motor: %s",
    .fmt_best_candidate = "Mejor candidata: %s",
    .fmt_best_score     = "Mejor puntuacion: %s",
    .fmt_status         = "Estado: %s",
    .fmt_cuda_error     = "Error CUDA: %s",
    .warn_gpu_not_found = "No se encontro ninguna GPU compatible con CUDA -- la busqueda se ejecutara solo en CPU.\n\n"
                          "Detalles: %s\n\n"
                          "Para habilitar la aceleracion por GPU:\n"
                          "  1. Confirma que el controlador NVIDIA esta instalado (nvidia-smi debe mostrar tu GPU).\n"
                          "  2. Instala el CUDA Toolkit que corresponda a la version CUDA de tu controlador.\n"
                          "  3. Abre una consola x64 Native Tools para VS, ejecuta build.bat\n"
                          "     y confirma que aparece BUILD SUCCEEDED.\n"
                          "  4. Verifica que tu GPU no este en modo TCC:\n"
                          "     nvidia-smi -q | findstr \"Compute Mode\"  (debe decir Default).",
    .fmt_payloads_loaded = "%zu payloads cargados",

    /* ---- Etiquetas de estado ---- */
    .state_running = "EN CURSO",
    .state_paused  = "PAUSADO",
    .state_stopped = "DETENIDO",

    /* ---- Titulos de graficos ---- */
    .graph_keys_title  = "Claves/s (historial)",
    .graph_score_title = "Mejor puntuacion (evolucion)",

    /* ---- Filtros de dialogo de archivo ---- */
    .dlg_bin_filter   = "Payload o DSP (*.bin;*.dsp;*.txt)\0*.bin;*.dsp;*.txt\0"
                        "Payload BIN (*.bin)\0*.bin\0"
                        "Volcado DSP de DSD-FME (*.dsp;*.txt)\0*.dsp;*.txt\0"
                        "Todos los archivos (*.*)\0*.*\0",
    .dlg_audio_filter = "Audio DMR (*.wav;*.mp3;*.flac;*.ogg)\0*.wav;*.mp3;*.flac;*.ogg\0"
                        "WAV (*.wav)\0*.wav\0Todos los archivos (*.*)\0*.*\0",

    /* ---- Conversion automatica de volcado DSP ---- */
    .dsp_src_prefix   = "DSP \xb7 ",
    .dsp_no_log_note  = "  \xb7  sin log PI (falta MI/ALG)",

    /* ---- Copiar / notificacion ---- */
    .btn_copy_key   = "Copiar",
    .msg_key_found  = "Clave encontrada! %s (puntuacion: %.1f)",
    .msg_key_copied = "Clave copiada al portapapeles",

    /* ---- Dialogo de ayuda ---- */
    .btn_help  = "Ayuda",
    .help_title = "DMRCrack - Guia rapida",
    .help_content =
"PASO 1 - CAPTURAR AUDIO CON SDR#\r\n"
"==================================\r\n"
"\r\n"
"  1. Abre SDR# y conecta tu dispositivo SDR.\r\n"
"  2. Sintoniza la frecuencia del canal DMR.\r\n"
"  3. Selecciona el modo de demodulacion NFM.\r\n"
"  4. Ajusta el ancho de filtro a 12500 Hz.\r\n"
"  5. DESACTIVA 'Filter Audio' (o 'De-emphasis').\r\n"
"     DSD-FME necesita la salida cruda del discriminador\r\n"
"     sin de-enfasis. Si no se desactiva, la decodificacion falla.\r\n"
"  6. Ajusta la frecuencia de muestreo de audio a 48000 Hz.\r\n"
"  7. Abre el plugin Audio Recorder.\r\n"
"     Selecciona modo de grabacion 'Audio' (NO 'Baseband').\r\n"
"     Baseband graba IQ crudo que DSD-FME no puede leer.\r\n"
"  8. Graba al menos 30-60 segundos de voz cifrada.\r\n"
"     Cuanto mas, mejor: se recomiendan 60+ payloads.\r\n"
"  9. Deten la grabacion y anota la ruta del archivo .wav.\r\n"
"\r\n"
"  Otros programas SDR: usa NFM con de-enfasis DESACTIVADO.\r\n"
"    SDR++: De-emphasis = NONE.  GQRX: 'No de-emphasis'.\r\n"
"\r\n"
"\r\n"
"PASO 2 - DEMODULAR\r\n"
"===================\r\n"
"\r\n"
"  1. Pulsa 'Examinar WAV...' y selecciona el archivo .wav.\r\n"
"  2. Pulsa 'Demodular'.\r\n"
"  3. Espera hasta que aparezca 'N payloads cargados'.\r\n"
"  4. (Opcional) Pulsa 'Exportar' para guardar el .bin.\r\n"
"\r\n"
"\r\n"
"PASO 3 - FUERZA BRUTA\r\n"
"======================\r\n"
"\r\n"
"  1. Pon Inicio = 0000000000, Fin = FFFFFFFFFF.\r\n"
"  2. Pulsa 'Iniciar'.\r\n"
"  3. Cuando la Mejor Puntuacion suba (Z > 7), la clave\r\n"
"     ha sido encontrada.\r\n"
"  4. Pulsa 'Copiar' para copiar la clave al portapapeles.\r\n"
"\r\n"
"\r\n"
"NOTAS\r\n"
"=====\r\n"
"\r\n"
"  - GPU NVIDIA recomendada. El modo CPU es mucho mas lento.\r\n"
"  - Minimo 6 payloads necesarios, 60+ recomendados.\r\n"
"  - El WAV debe ser mono, 48000 Hz, 16-bit PCM.\r\n",

};
