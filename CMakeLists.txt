cmake_minimum_required(VERSION 3.18)

# ── Project ────────────────────────────────────────────────────────────────
project(FSP.DMRCrack LANGUAGES C CXX)

# ── Options ────────────────────────────────────────────────────────────────
option(USE_HIP    "Build with AMD ROCm/HIP instead of NVIDIA CUDA" OFF)
option(NO_GUI     "Build headless CLI only (no Win32 GUI)"         OFF)
option(BUILD_TESTS "Build test utilities"                           OFF)

# Force CLI on Linux (no Win32 GUI available)
if(UNIX)
    set(NO_GUI ON CACHE BOOL "Forced ON: no Win32 GUI on Linux" FORCE)
endif()

# ── Compiler flags ─────────────────────────────────────────────────────────
set(COMMON_C_FLAGS
    -O3
    -W
    -Wall
    -D_CRT_SECURE_NO_WARNINGS   # harmless on Linux, needed on MSVC
)

if(WIN32)
    list(APPEND COMMON_C_FLAGS -DWIN32 -D_WINDOWS)
endif()

if(NO_GUI)
    list(APPEND COMMON_C_FLAGS -DNO_GUI)
endif()

if(USE_HIP)
    list(APPEND COMMON_C_FLAGS -DUSE_HIP)
endif()

# ── Source files ───────────────────────────────────────────────────────────
set(SOURCES_COMMON
    src/bruteforce.cu
    src/payload_io.c
    src/rc4.c
    src/lang.c
    src/lang_en.c
    src/lang_es.c
)

if(NO_GUI)
    list(APPEND SOURCES_COMMON src/cli.c)
else()
    list(APPEND SOURCES_COMMON
        src/gui.c
        src/updater.c
        src/main.c
    )
endif()

# ── GPU back-end ───────────────────────────────────────────────────────────
if(USE_HIP)
    # ── AMD ROCm / HIP ─────────────────────────────────────────────────────
    find_package(hip REQUIRED CONFIG
        HINTS /opt/rocm /opt/rocm/hip $ENV{ROCM_PATH})

    # Common RDNA/CDNA targets; add more as needed
    set(GPU_TARGETS "gfx1010;gfx1030;gfx1031;gfx1100;gfx1101;gfx906;gfx908"
        CACHE STRING "AMD GPU targets (gfxNNNN list)")

    set_source_files_properties(src/bruteforce.cu PROPERTIES
        HIP_SOURCE_PROPERTY_FORMAT ON)

    add_executable(dmrcrack ${SOURCES_COMMON})

    target_compile_options(dmrcrack PRIVATE
        $<$<COMPILE_LANGUAGE:HIP>:
            -O3
            --offload-arch=${GPU_TARGETS}
        >
        ${COMMON_C_FLAGS}
    )

    target_link_libraries(dmrcrack PRIVATE hip::host)

else()
    # ── NVIDIA CUDA ─────────────────────────────────────────────────────────
    enable_language(CUDA)
    find_package(CUDAToolkit REQUIRED)

    # Supported SM targets (PTX fallback covers future cards via JIT)
    set(CMAKE_CUDA_ARCHITECTURES "75;86;89" CACHE STRING "CUDA architectures")

    add_executable(dmrcrack ${SOURCES_COMMON})

    set_target_properties(dmrcrack PROPERTIES
        CUDA_SEPARABLE_COMPILATION OFF
        CUDA_RESOLVE_DEVICE_SYMBOLS ON
    )

    target_compile_options(dmrcrack PRIVATE
        $<$<COMPILE_LANGUAGE:CUDA>:
            -O3
            --generate-code arch=compute_75,code=sm_75
            --generate-code arch=compute_86,code=sm_86
            --generate-code arch=compute_89,code=sm_89
            --generate-code arch=compute_100,code=sm_100
            --generate-code arch=compute_89,code=compute_89
            -Xcompiler /W4,/D_CRT_SECURE_NO_WARNINGS
        >
        $<$<AND:$<COMPILE_LANGUAGE:CUDA>,$<BOOL:${WIN32}>>:
            -Xcompiler /DWIN32,/D_WINDOWS
        >
    )

    target_link_libraries(dmrcrack PRIVATE CUDA::cudart_static)
endif()

# ── Include paths ──────────────────────────────────────────────────────────
target_include_directories(dmrcrack PRIVATE include)

# ── Platform link libraries ────────────────────────────────────────────────
if(WIN32 AND NOT NO_GUI)
    target_link_libraries(dmrcrack PRIVATE
        user32 gdi32 comdlg32 kernel32 dwmapi shell32 advapi32
        ${CMAKE_SOURCE_DIR}/vendor/winsparkle/x64/WinSparkle.lib
    )
    target_include_directories(dmrcrack PRIVATE vendor/winsparkle/include)
elseif(WIN32 AND NO_GUI)
    target_link_libraries(dmrcrack PRIVATE
        user32 kernel32 advapi32
    )
elseif(UNIX)
    find_package(Threads REQUIRED)
    target_link_libraries(dmrcrack PRIVATE Threads::Threads m)
endif()

# ── Output directory ──────────────────────────────────────────────────────
set_target_properties(dmrcrack PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin
)

# ── Test tools ────────────────────────────────────────────────────────────
if(BUILD_TESTS)
    add_executable(test_strict_score
        src/test_strict_score.c
        src/bruteforce.c
        src/rc4.c
        src/payload_io.c
    )
    target_include_directories(test_strict_score PRIVATE include)
    if(WIN32)
        target_link_libraries(test_strict_score PRIVATE user32 gdi32 comdlg32 shell32 advapi32)
    else()
        find_package(Threads REQUIRED)
        target_link_libraries(test_strict_score PRIVATE Threads::Threads m)
    endif()
    set_target_properties(test_strict_score PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)
endif()
