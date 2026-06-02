cmake_minimum_required(VERSION 3.21)  # 3.21+ required for first-class HIP language support

# ── Project ────────────────────────────────────────────────────────────────
project(FSP.DMRCrack LANGUAGES C CXX)

# ── Options ────────────────────────────────────────────────────────────────
option(USE_HIP    "Build with AMD ROCm/HIP instead of NVIDIA CUDA" OFF)
option(USE_CUDA   "Build with the NVIDIA CUDA GPU backend"         ON)
option(USE_OPENCL "Build with the portable OpenCL GPU backend (NVIDIA/AMD/Intel)" OFF)
option(NO_GUI     "Build headless CLI only (no Win32 GUI)"         OFF)
option(BUILD_TESTS "Build test utilities"                           OFF)

# The three GPU back-ends are mutually exclusive. Priority when several are
# requested: HIP > OpenCL > CUDA. OpenCL is the vendor-neutral backend used for
# the Debian/Kali package (free build deps, runs on NVIDIA + AMD + Intel);
# CUDA/HIP remain available as build-from-source options for peak performance.
if(USE_HIP)
    set(USE_OPENCL OFF CACHE BOOL "Disabled: HIP backend selected" FORCE)
    set(USE_CUDA   OFF CACHE BOOL "Disabled: HIP backend selected" FORCE)
elseif(USE_OPENCL)
    set(USE_CUDA   OFF CACHE BOOL "Disabled: OpenCL backend selected" FORCE)
endif()

# USE_HIP/USE_CUDA compile the single-source CUDA kernel (src/bruteforce.cu).
# USE_OPENCL compiles src/bruteforce_cl.cpp. Otherwise we build the portable
# multi-threaded CPU-only engine (src/bruteforce.c), which needs no toolkit.
if(USE_HIP OR USE_CUDA)
    set(GPU_BACKEND ON)
else()
    set(GPU_BACKEND OFF)
endif()

# Force CLI on Linux (no Win32 GUI available)
if(UNIX)
    set(NO_GUI ON CACHE BOOL "Forced ON: no Win32 GUI on Linux" FORCE)
endif()

# ── Compiler flags ─────────────────────────────────────────────────────────
# GCC/Clang and MSVC take different flag syntax. The GCC-style flags (-O3, -Wall)
# are what nvcc/hipcc/gcc consume on the Linux build paths; MSVC needs /-style
# equivalents or it misparses -W as "/W<next-arg>".
if(MSVC)
    set(COMMON_C_FLAGS
        /W3
        /D_CRT_SECURE_NO_WARNINGS
    )
else()
    set(COMMON_C_FLAGS
        -O3
        -W
        -Wall
        -D_CRT_SECURE_NO_WARNINGS   # harmless on GCC/Clang
    )
endif()

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
# bruteforce.cu = GPU kernel (CUDA/HIP); bruteforce.c = portable CPU twin.
# They implement the same engine API — exactly one is compiled in.
if(GPU_BACKEND)
    set(BRUTEFORCE_SRC src/bruteforce.cu)
elseif(USE_OPENCL)
    set(BRUTEFORCE_SRC src/bruteforce_cl.cpp)
else()
    set(BRUTEFORCE_SRC src/bruteforce.c)
endif()

# OpenCL backend: embed the kernel source (src/dmrcrack.cl) into a generated
# header so the runtime has no external .cl file dependency. The C++ raw-string
# wrapper handles arbitrary kernel content (must never contain the delimiter).
if(USE_OPENCL)
    set(_cl_embed "${CMAKE_BINARY_DIR}/dmrcrack_cl_embed.h")
    file(READ "${CMAKE_SOURCE_DIR}/src/dmrcrack.cl" _cl_src)
    file(WRITE "${_cl_embed}"
         "/* Auto-generated from src/dmrcrack.cl — do not edit. */\n"
         "static const char *DMRCRACK_CL_SRC = R\"DMRCLSRC(\n${_cl_src}\n)DMRCLSRC\";\n")
endif()

set(SOURCES_COMMON
    ${BRUTEFORCE_SRC}
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
    # First-class HIP language support (CMake 3.21+). The single-source kernel
    # file src/bruteforce.cu is compiled as HIP; gpu_compat.h aliases the cudaXxx
    # symbols to their hipXxx equivalents so the same source builds on both back-ends.
    #
    # GPU targets: RDNA1/2/3 (gfx10xx/gfx11xx) + CDNA (gfx90a) + Vega (gfx906/908).
    # Override at configure time with -DCMAKE_HIP_ARCHITECTURES="gfxXXXX;...".
    # Set before enable_language(HIP) so the compiler probe uses this list.
    if(NOT DEFINED CMAKE_HIP_ARCHITECTURES)
        set(CMAKE_HIP_ARCHITECTURES
            "gfx906;gfx908;gfx90a;gfx1010;gfx1030;gfx1031;gfx1100;gfx1101;gfx1102")
    endif()

    enable_language(HIP)
    find_package(hip REQUIRED)

    # Compile bruteforce.cu as HIP rather than CUDA.
    set_source_files_properties(src/bruteforce.cu PROPERTIES LANGUAGE HIP)

    add_executable(dmrcrack ${SOURCES_COMMON})

    target_compile_options(dmrcrack PRIVATE
        $<$<COMPILE_LANGUAGE:HIP>:-O3>
        ${COMMON_C_FLAGS}
    )

    target_link_libraries(dmrcrack PRIVATE hip::device)

elseif(USE_CUDA)
    # ── NVIDIA CUDA ─────────────────────────────────────────────────────────
    enable_language(CUDA)
    find_package(CUDAToolkit REQUIRED)

    # Disable CMake's automatic arch-flag generation; we supply all -gencode
    # flags explicitly below, gated on the CUDA version.
    set(CMAKE_CUDA_ARCHITECTURES OFF)

    add_executable(dmrcrack ${SOURCES_COMMON})

    set_target_properties(dmrcrack PROPERTIES
        CUDA_SEPARABLE_COMPILATION OFF
        CUDA_RESOLVE_DEVICE_SYMBOLS ON
    )

    # Use -gencode=arch=...,code=... (single token, no space) so CMake does not
    # inadvertently quote the flag as one shell word when generating Makefiles
    # on Linux, which would make nvcc reject it with "single input file" error.

    # sm_75 (Turing) and sm_86 (Ampere) — always included
    target_compile_options(dmrcrack PRIVATE
        $<$<COMPILE_LANGUAGE:CUDA>:-O3>
        $<$<COMPILE_LANGUAGE:CUDA>:-gencode=arch=compute_75,code=sm_75>
        $<$<COMPILE_LANGUAGE:CUDA>:-gencode=arch=compute_86,code=sm_86>
    )

    # sm_89 (Ada Lovelace, RTX 4xxx) — requires CUDA 11.8+
    if(CMAKE_CUDA_COMPILER_VERSION VERSION_GREATER_EQUAL "11.8")
        target_compile_options(dmrcrack PRIVATE
            $<$<COMPILE_LANGUAGE:CUDA>:-gencode=arch=compute_89,code=sm_89>
        )
    endif()

    # sm_100 (Blackwell) — requires CUDA 12.8+
    if(CMAKE_CUDA_COMPILER_VERSION VERSION_GREATER_EQUAL "12.8")
        target_compile_options(dmrcrack PRIVATE
            $<$<COMPILE_LANGUAGE:CUDA>:-gencode=arch=compute_100,code=sm_100>
        )
    endif()

    # PTX fallback: JIT-compile for future GPU generations
    if(CMAKE_CUDA_COMPILER_VERSION VERSION_GREATER_EQUAL "12.8")
        target_compile_options(dmrcrack PRIVATE
            $<$<COMPILE_LANGUAGE:CUDA>:-gencode=arch=compute_100,code=compute_100>)
    elseif(CMAKE_CUDA_COMPILER_VERSION VERSION_GREATER_EQUAL "11.8")
        target_compile_options(dmrcrack PRIVATE
            $<$<COMPILE_LANGUAGE:CUDA>:-gencode=arch=compute_89,code=compute_89>)
    else()
        target_compile_options(dmrcrack PRIVATE
            $<$<COMPILE_LANGUAGE:CUDA>:-gencode=arch=compute_86,code=compute_86>)
    endif()

    # Windows-only MSVC host-compiler flags — gated to avoid breaking gcc on Linux
    target_compile_options(dmrcrack PRIVATE
        $<$<AND:$<COMPILE_LANGUAGE:CUDA>,$<BOOL:${WIN32}>>:-Xcompiler /W4,/D_CRT_SECURE_NO_WARNINGS,/DWIN32,/D_WINDOWS>
    )

    target_link_libraries(dmrcrack PRIVATE CUDA::cudart_static)

elseif(USE_OPENCL)
    # ── Portable OpenCL (NVIDIA / AMD / Intel) ──────────────────────────────
    # Vendor-neutral GPU backend (src/bruteforce_cl.cpp + embedded src/dmrcrack.cl).
    # Build deps are free (opencl-headers + an ICD loader), so this is the
    # configuration used for the Debian/Kali package. Falls back to a portable
    # multi-threaded CPU scorer at runtime when no OpenCL device is present.
    find_package(OpenCL REQUIRED)

    add_executable(dmrcrack ${SOURCES_COMMON})
    target_compile_options(dmrcrack PRIVATE ${COMMON_C_FLAGS})
    target_compile_definitions(dmrcrack PRIVATE USE_OPENCL)
    # The generated embed header lives in the build directory.
    target_include_directories(dmrcrack PRIVATE ${CMAKE_BINARY_DIR})
    target_link_libraries(dmrcrack PRIVATE OpenCL::OpenCL)

else()
    # ── CPU-only (no GPU toolkit) ───────────────────────────────────────────
    # Portable multi-threaded engine compiled from src/bruteforce.c. Builds with
    # a plain C toolchain and no proprietary dependencies — this is the variant
    # shipped in Debian/Kali. GPU users build from source with -DUSE_CUDA=ON.
    add_executable(dmrcrack ${SOURCES_COMMON})
    target_compile_options(dmrcrack PRIVATE ${COMMON_C_FLAGS})
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
        tests/test_strict_score.c
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

# ── Install targets (used by cmake --install and Debian packaging) ─────────
include(GNUInstallDirs)
install(TARGETS dmrcrack
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
if(EXISTS "${CMAKE_SOURCE_DIR}/man/dmrcrack.1")
    install(FILES man/dmrcrack.1
        DESTINATION ${CMAKE_INSTALL_MANDIR}/man1
    )
endif()
if(UNIX AND EXISTS "${CMAKE_SOURCE_DIR}/completions/dmrcrack.bash")
    install(FILES completions/dmrcrack.bash
        DESTINATION ${CMAKE_INSTALL_DATADIR}/bash-completion/completions
        RENAME dmrcrack
    )
endif()
