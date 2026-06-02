# FSP.DMRCrack — portable OpenCL build on a Debian/Kali-compatible base.
#
#   docker build -t fsp-dmrcrack .
#   docker run --rm fsp-dmrcrack --help
#
# To use a GPU you must expose the vendor's OpenCL ICD to the container, e.g.
# NVIDIA:  docker run --rm --gpus all -e NVIDIA_DRIVER_CAPABILITIES=compute,utility \
#                 fsp-dmrcrack --bin /data/capture.bin
# Without a usable ICD the engine falls back to the multi-threaded CPU scorer.

# ── Stage 1: build ──────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
        cmake \
        build-essential \
        opencl-headers \
        ocl-icd-opencl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

RUN cmake -S . -B build \
        -DUSE_OPENCL=ON \
        -DNO_GUI=ON \
        -DCMAKE_BUILD_TYPE=Release \
    && cmake --build build --parallel

# ── Stage 2: runtime ────────────────────────────────────────────────────────
FROM debian:bookworm-slim

# ocl-icd-libopencl1 = the OpenCL ICD loader; vendor ICDs are mounted at runtime.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ocl-icd-libopencl1 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /src/bin/dmrcrack /usr/local/bin/dmrcrack

WORKDIR /data
ENTRYPOINT ["dmrcrack"]
CMD ["--help"]
