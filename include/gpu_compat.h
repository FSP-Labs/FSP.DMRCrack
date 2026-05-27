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

#ifndef GPU_COMPAT_H
#define GPU_COMPAT_H

/*
 * gpu_compat.h — CUDA / HIP compatibility shim
 *
 * When USE_HIP is defined (AMD ROCm build), every cudaXxx symbol is aliased
 * to its hipXxx counterpart.  The GPU kernels and host launch code need no
 * ifdefs — they just include this header instead of <cuda_runtime.h>.
 *
 * On NVIDIA builds (default), this header is a no-op pass-through.
 */

#if defined(USE_HIP)

/* ── HIP backend ─────────────────────────────────────────────────────── */
#include <hip/hip_runtime.h>

/* Error type and success sentinel */
#define cudaError_t             hipError_t
#define cudaSuccess             hipSuccess
#define cudaErrorNotReady       hipErrorNotReady
#define cudaGetErrorString      hipGetErrorString
#define cudaGetLastError        hipGetLastError

/* Device management */
#define cudaDeviceProp          hipDeviceProp_t
#define cudaGetDeviceProperties hipGetDeviceProperties
#define cudaFuncSetAttribute    hipFuncSetAttribute
#define cudaFuncAttributeMaxDynamicSharedMemorySize \
        hipFuncAttributeMaxDynamicSharedMemorySize

/* Memory */
#define cudaMalloc              hipMalloc
#define cudaFree                hipFree
#define cudaMemset              hipMemset
#define cudaMemcpy              hipMemcpy
#define cudaMemcpyToSymbol      hipMemcpyToSymbol
#define cudaMemcpyAsync         hipMemcpyAsync
#define cudaMemsetAsync         hipMemsetAsync
#define cudaMemcpyHostToDevice  hipMemcpyHostToDevice
#define cudaMemcpyDeviceToHost  hipMemcpyDeviceToHost
#define cudaHostAlloc           hipHostMalloc
#define cudaHostAllocDefault    0
#define cudaFreeHost            hipHostFree

/* Streams */
#define cudaStream_t            hipStream_t
#define cudaStreamCreateWithFlags hipStreamCreateWithFlags
#define cudaStreamDestroy       hipStreamDestroy
#define cudaStreamSynchronize   hipStreamSynchronize
#define cudaStreamQuery         hipStreamQuery
#define cudaStreamNonBlocking   hipStreamNonBlocking

/* Events */
#define cudaEvent_t             hipEvent_t
#define cudaEventCreate         hipEventCreate
#define cudaEventRecord         hipEventRecord
#define cudaEventSynchronize    hipEventSynchronize
#define cudaEventElapsedTime    hipEventElapsedTime
#define cudaEventDestroy        hipEventDestroy

/* Intrinsics available in both CUDA and HIP */
/* __popc, __float_as_uint, __uint_as_float, __fsqrt_rn — already provided by HIP */

#else  /* ── CUDA backend (default) ───────────────────────────────────── */

#include <cuda_runtime.h>
#include <device_launch_parameters.h>

/* Nothing to alias — CUDA names are used directly. */

#endif  /* USE_HIP */

#endif  /* GPU_COMPAT_H */
