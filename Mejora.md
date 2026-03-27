# DMRCrack — Plan de Mejora de Velocidad: CPU+GPU Híbrido

## ✅ COMPLETADO: GUI Operator Dashboard (2026-03-27)

Las 10 tareas del plan `docs/plans/2026-03-26-gui-redesign.md` han sido implementadas:

- **Task 1**: `gpu_keys_tested` counter en engine + snapshot
- **Task 2**: Header bar + paleta de colores del Operator Dashboard
- **Task 3**: AppState refactoring + nuevos controles RTL-SDR (radio, freq, gain, ppm, slot, inverted)
- **Task 4**: `validate_payload_set()` en `payload_io.c`
- **Task 5**: Modo RTL-SDR en `demod_thread_proc` (flags `-V`, `-xr`)
- **Task 6**: `layout_controls` para paneles CAPTURE / BRUTE FORCE side-by-side
- **Task 7**: Metric tiles (THROUGHPUT/PROGRESS/CANDIDATE) + status strip pintados en WM_PAINT
- **Task 8**: Gráficos side-by-side con area fill y borde
- **Task 9**: CUDA auto-fallback a CPU, low-payload inline warning
- **Task 10**: Section headers en WM_PAINT, static labels para Slot/Inverted

---

> **Para Claude:** Usar `superpowers:executing-plans` para implementar tarea a tarea.

**Objetivo:** Maximizar throughput de búsqueda de clave RC4-40 en hardware disponible
(RTX 3050 Ti Laptop + CPU quad-core), reduciendo el tiempo de búsqueda exhaustiva
de ~38 horas actuales a ~10-15 horas.

**Arquitectura:**
El GPU maneja el grueso del keyspace con un kernel ILP-2 (2 claves por thread,
encadenamiento independiente de S-boxes). La CPU corre en paralelo sobre un chunk
distinto del keyspace usando hilos nativos ya presentes en el motor. Las herramientas
Python añaden análisis de frames de silencio para futuros ataques de texto conocido.

**Stack:** C + CUDA (NVCC), Win32, Python 3, mbelib pipeline KMI9.

---

## Análisis del estado actual (baseline)

### Benchmark medido (RTX 3050 Ti Laptop, sm_86)

| Payloads | Throughput | Ciclos/clave | Ciclos/paso RC4 |
|----------|-----------|-------------|----------------|
| 6        | 4.71 M/s  | 220         | 0.38           |
| 126      | 0.23 M/s  | 4571        | 4.8            |
| Efectivo (126 + pruning) | **8.1 M/s** | — | — |

- Registros: strict=128 regs, legacy=64 regs (en límite de `__launch_bounds__`)
- Ocupancia: 33% (16 warps / 48 warps posibles por SM)
- Clave correcta (`373374ABE8`) encontrada con score=5083.96 ✅

### ¿Por qué 8.1 M/s y no más?

El S-box de RC4 (256 bytes/thread) vive en L1 cache (128 KB por SM = exactamente el
working set de 512 threads × 256 B). La latencia de L1 es ~32 ciclos. Con 16 warps
activos, el scheduler esconde esta latencia via warp-switching: 0.38 cyc/paso para
claves con poda. El verdadero techo es el **ancho de banda L1** de accesos aleatorios
al S-box (2 loads aleatorios por paso de KSA × 512 threads = 1024 loads/paso).

### ¿Por qué NO más optimizaciones micro?

| Idea | Veredicto | Razón |
|------|-----------|-------|
| Ataque FMS/Mantin | ❌ No aplica | RC4 descarta 256 bytes → biases en pos 256+ son O(1/2²⁴) |
| Bitslicing | ❌ No aplica | KSA tiene j=f(S[i],j_prev) → dependencia de datos, no bit-parallelizable |
| Ataque de textos conocidos (silencio) | ⚠️ Parcial | Útil post-facto, pero no acelera brute-force sin key previa |
| Rainbow tables | ❌ No viable | 2^40 entradas × ~10 bytes = 10 TB, inmanejable |

---

## Ruta de mejora: 4 tareas

```
TAREA 1: GPU ILP-2 kernel             → +50-80% GPU throughput
TAREA 2: Rechazo anticipado burst k=1 → +5% (free)
TAREA 3: CPU workers paralelos        → +4-8 M/s adicionales
TAREA 4: Herramienta silence frames   → base para futuros ataques KP
```

**Resultado esperado total: 14-20 M/s efectivos** (vs 8.1 M/s actual)

---

## TAREA 1: Kernel ILP-2 — 2 claves por thread

### Fundamento teórico

Con 1 clave por thread, el scheduler necesita saltar entre 16 warps para esconder
la latencia de load S[j] (j-dependiente). Con 2 claves por thread interleaved:
- Las cadenas S_a[j_a] y S_b[j_b] son **completamente independientes**
- El compilador puede emitir load S_a[j_a] inmediatamente seguido de load S_b[j_b]
- Mientras espera el resultado de S_a, el pipeline ya tiene S_b en vuelo
- Resultado: 2x ILP dentro del hilo → latencia escondida sin necesitar más warps

La clave es reducir threads/block a 128 para que el S-box doble (512B/thread) siga
cabiendo en L1 (128 × 512B = 64 KB < 128 KB L1).

### Archivos a modificar

- Modificar: `src/bruteforce.cu` — añadir nuevo kernel `bruteforce_kernel_strict_ilp2`
- Modificar: `src/bruteforce.cu` — añadir lógica de selección automática ILP-2 vs original
- Modificar: `src/test_bench.cu` — extender benchmark para medir ILP-2

### Paso 1: Añadir el nuevo kernel ILP-2 en `src/bruteforce.cu`

Insertar DESPUÉS del bloque `#undef BCNT_ADD` / `#undef BCNT_GET` del kernel existente
(~línea 720), ANTES de `bruteforce_kernel`:

```cuda
/* =========================================================================
 * ILP-2 STRICT KERNEL — 2 keys per thread, 128 threads/block
 * Each thread interleaves two independent RC4 chains to hide L1 load latency
 * without relying solely on warp switching.
 * Config: __launch_bounds__(128, 4) → ≤64 regs/thread target
 * ========================================================================= */
__global__ __launch_bounds__(128, 4)
void bruteforce_kernel_strict_ilp2(
    uint64_t start_key,
    uint64_t total_keys,
    int payload_count,
    uint32_t global_mi,
    unsigned long long* __restrict__ dev_keys_tested,
    float* __restrict__ dev_best_score,
    unsigned long long* __restrict__ dev_best_key,
    int* __restrict__ dev_stop_requested)
{
    uint64_t tid     = blockIdx.x * (uint64_t)blockDim.x + threadIdx.x;
    uint64_t stride  = (uint64_t)gridDim.x * blockDim.x;
    /* Each thread processes 2 consecutive keys: base_key and base_key+1 */
    uint64_t stride2 = stride * 2ULL;
    const int enable_prune = (total_keys > (1ULL << 20)) ? 1 : 0;
    int local_keys = 0;

    for (uint64_t i = tid * 2; i < total_keys; i += stride2) {
        if ((i & 0x3FFu) == 0 && dev_stop_requested[0]) return;

        /* --- Key A --- */
        uint64_t key_a = start_key + i;
        unsigned char ka[5];
        key_to_5bytes_dev(key_a, ka);

        /* --- Key B (next key) --- */
        uint64_t key_b = key_a + 1;
        if (key_b >= start_key + total_keys) key_b = key_a; /* last key: duplicate */
        unsigned char kb[5];
        key_to_5bytes_dev(key_b, kb);

        float score_a = 0.0f, score_b = 0.0f;
        int bursts_a = 0, bursts_b = 0;
        int pruned_a = 0, pruned_b = 0;

        /* Packed uint16 bit-freq accumulators — one set per key */
        unsigned int ba[12], bb[12];
        #pragma unroll
        for (int k = 0; k < 12; k++) { ba[k] = 0u; bb[k] = 0u; }

#define BA_ADD(b, bit) ba[(b)>>1] += ((unsigned int)(bit)) << (((b)&1u)<<4)
#define BB_ADD(b, bit) bb[(b)>>1] += ((unsigned int)(bit)) << (((b)&1u)<<4)
#define BA_GET(b) ((float)((ba[(b)>>1] >> (((b)&1u)<<4)) & 0xFFFFu))
#define BB_GET(b) ((float)((bb[(b)>>1] >> (((b)&1u)<<4)) & 0xFFFFu))

        for (int sf_base = 0; sf_base < payload_count; sf_base += 6) {
            /* --- MI for this superframe --- */
            uint32_t mi = global_mi;
            if (sf_base < MAX_CONST_LINES && (d_const_meta_flags[sf_base] & 0x1u))
                mi = d_const_mi[sf_base];

            /* --- KSA for key A and key B in parallel (interleaved) --- */
            unsigned char kmi_a[9], kmi_b[9];
            compose_kmi9_dev(ka, mi, kmi_a);
            compose_kmi9_dev(kb, mi, kmi_b);

            RC4_CTX_DEV rc4_a, rc4_b;
            rc4_ksa9_dev(&rc4_a, kmi_a);   /* KSA-A */
            rc4_ksa9_dev(&rc4_b, kmi_b);   /* KSA-B (independent: compiler pipelines loads) */
            rc4_discard_dev(&rc4_a, 256);
            rc4_discard_dev(&rc4_b, 256);

            for (int burst_pos = 0; burst_pos < 6; ++burst_pos) {
                int p = sf_base + burst_pos;
                if (p >= payload_count) break;
                const unsigned char *cp = d_const_cipher_packs + (p * 21);

                /* --- Decrypt 3 sub-frames for A and B, interleaved --- */
                unsigned char pa0[3], pa1[3], pa2[3];
                unsigned char pb0[3], pb1[3], pb2[3];

                rc4_crypt_first3_skip4_dev(&rc4_a, cp + 0,  pa0);
                rc4_crypt_first3_skip4_dev(&rc4_b, cp + 0,  pb0); /* independent chain */
                rc4_crypt_first3_skip4_dev(&rc4_a, cp + 7,  pa1);
                rc4_crypt_first3_skip4_dev(&rc4_b, cp + 7,  pb1);
                rc4_crypt_first3_skip4_dev(&rc4_a, cp + 14, pa2);
                rc4_crypt_first3_skip4_dev(&rc4_b, cp + 14, pb2);

                /* --- Hamming scores --- */
                int ha01 = __popc((unsigned int)(pa0[0]^pa1[0]))
                         + __popc((unsigned int)(pa0[1]^pa1[1]))
                         + __popc((unsigned int)(pa0[2]^pa1[2]));
                int ha12 = __popc((unsigned int)(pa1[0]^pa2[0]))
                         + __popc((unsigned int)(pa1[1]^pa2[1]))
                         + __popc((unsigned int)(pa1[2]^pa2[2]));
                int hb01 = __popc((unsigned int)(pb0[0]^pb1[0]))
                         + __popc((unsigned int)(pb0[1]^pb1[1]))
                         + __popc((unsigned int)(pb0[2]^pb1[2]));
                int hb12 = __popc((unsigned int)(pb1[0]^pb2[0]))
                         + __popc((unsigned int)(pb1[1]^pb2[1]))
                         + __popc((unsigned int)(pb1[2]^pb2[2]));

                if (!pruned_a) { score_a += (float)(48 - ha01 - ha12); bursts_a++; }
                if (!pruned_b) { score_b += (float)(48 - hb01 - hb12); bursts_b++; }

                /* Bit-freq accumulators */
                if (!pruned_a) {
                    #pragma unroll
                    for (int b=0;b<8;b++) BA_ADD(b,    (pa0[0]>>(7-b))&1);
                    #pragma unroll
                    for (int b=0;b<8;b++) BA_ADD(8+b,  (pa0[1]>>(7-b))&1);
                    #pragma unroll
                    for (int b=0;b<8;b++) BA_ADD(16+b, (pa0[2]>>(7-b))&1);
                }
                if (!pruned_b) {
                    #pragma unroll
                    for (int b=0;b<8;b++) BB_ADD(b,    (pb0[0]>>(7-b))&1);
                    #pragma unroll
                    for (int b=0;b<8;b++) BB_ADD(8+b,  (pb0[1]>>(7-b))&1);
                    #pragma unroll
                    for (int b=0;b<8;b++) BB_ADD(16+b, (pb0[2]>>(7-b))&1);
                }

                /* Per-burst floor — applied to both independently */
                if (enable_prune && bursts_a >= 3 && !pruned_a &&
                    score_a < d_abs_floor[bursts_a]) pruned_a = 1;
                if (enable_prune && bursts_b >= 3 && !pruned_b &&
                    score_b < d_abs_floor[bursts_b]) pruned_b = 1;
                if (pruned_a && pruned_b) break;
            }

            if (pruned_a && pruned_b) break;

            /* Chi²-floor at superframe boundary for both */
            if (enable_prune && bursts_a >= 6 && !pruned_a) {
                float hn = (float)bursts_a * 0.5f;
                float chi2 = 0.0f;
                #pragma unroll
                for (int b=0;b<24;b++) { float d=BA_GET(b)-hn; chi2+=d*d; }
                float floor_v = 6.0f*(float)bursts_a - 3.0f*__fsqrt_rn(48.0f*(float)bursts_a);
                if (chi2 < floor_v) pruned_a = 1;
            }
            if (enable_prune && bursts_b >= 6 && !pruned_b) {
                float hn = (float)bursts_b * 0.5f;
                float chi2 = 0.0f;
                #pragma unroll
                for (int b=0;b<24;b++) { float d=BB_GET(b)-hn; chi2+=d*d; }
                float floor_v = 6.0f*(float)bursts_b - 3.0f*__fsqrt_rn(48.0f*(float)bursts_b);
                if (chi2 < floor_v) pruned_b = 1;
            }
            if (pruned_a && pruned_b) break;
        }

#undef BA_ADD
#undef BB_ADD
#undef BA_GET
#undef BB_GET

        /* Chi² final score boost for non-pruned keys */
        if (!pruned_a && bursts_a > 0) {
            float hn = (float)bursts_a * 0.5f;
            float chi2 = 0.0f;
            for (int b=0;b<12;b++) {
                float d0 = (float)(ba[b] & 0xFFFFu) - hn; chi2 += d0*d0;
                float d1 = (float)(ba[b] >> 16)     - hn; chi2 += d1*d1;
            }
            score_a += chi2 * 0.1f;
        }
        if (!pruned_b && bursts_b > 0) {
            float hn = (float)bursts_b * 0.5f;
            float chi2 = 0.0f;
            for (int b=0;b<12;b++) {
                float d0 = (float)(bb[b] & 0xFFFFu) - hn; chi2 += d0*d0;
                float d1 = (float)(bb[b] >> 16)     - hn; chi2 += d1*d1;
            }
            score_b += chi2 * 0.1f;
        }

        /* Update global best for key A */
        if (!pruned_a) {
            float cur = __ldg(dev_best_score);
            if (score_a > cur) {
                atomicMax((int*)dev_best_score, __float_as_int(score_a));
                if (__int_as_float(atomicMax((int*)dev_best_score,
                                             __float_as_int(score_a))) < score_a)
                    *dev_best_key = key_a;
            }
        }
        /* Update global best for key B */
        if (!pruned_b && key_b != key_a) {
            float cur = __ldg(dev_best_score);
            if (score_b > cur) {
                atomicMax((int*)dev_best_score, __float_as_int(score_b));
                if (__int_as_float(atomicMax((int*)dev_best_score,
                                             __float_as_int(score_b))) < score_b)
                    *dev_best_key = key_b;
            }
        }

        local_keys += (key_b != key_a) ? 2 : 1;
    }

    atomicAdd(dev_keys_tested, (unsigned long long)local_keys);
}
```

### Paso 2: Selección automática del kernel en `cuda_launcher_thread`

En la función `cuda_launcher_thread` (hacia línea 1280), localizar la llamada al kernel
`bruteforce_kernel_strict` y añadir lógica de selección:

```c
/* Selección de kernel: ILP-2 si modo_estricto y GPU Ampere/Ada (sm>=86) */
int use_ilp2 = (mode_policy >= 2) && (cuda_sm >= 86);
int tpb = use_ilp2 ? 128 : 256;
/* Con ILP-2: 2 claves por thread → blocks *= 2 para cubrir el mismo keyspace */
unsigned int blocks = use_ilp2
    ? (unsigned int)((total_keys + (uint64_t)tpb * 2 - 1) / ((uint64_t)tpb * 2))
    : (unsigned int)((total_keys + tpb - 1) / tpb);
blocks = blocks < 1 ? 1 : (blocks > 65535 ? 65535 : blocks);

if (use_ilp2) {
    bruteforce_kernel_strict_ilp2<<<blocks, tpb>>>(
        chunk_start, chunk_size, payload_limit, global_mi,
        d_keys_tested, d_best_score, d_best_key, d_stop);
} else {
    bruteforce_kernel_strict<<<blocks, tpb>>>(
        chunk_start, chunk_size, payload_limit, global_mi,
        d_keys_tested, d_best_score, d_best_key, d_stop);
}
```

Necesitarás obtener `cuda_sm` antes de este bloque:
```c
int cuda_sm = 0;
{
    cudaDeviceProp prop;
    if (cudaGetDeviceProperties(&prop, 0) == cudaSuccess)
        cuda_sm = prop.major * 10 + prop.minor;
}
```

### Paso 3: Benchmark ILP-2 en `src/test_bench.cu`

Añadir sección al final de `run_benchmark()`:

```c
printf("\n------------------------------------------------------------\n");
printf("THROUGHPUT BENCHMARK (ILP-2 kernel, 128 tpb)\n");
printf("------------------------------------------------------------\n");
int payload_counts[] = {6, 12, 30, 60, 126};
for (int pi = 0; pi < 5; pi++) {
    int pc = upload_payloads(ps, payload_counts[pi], abs_floor_host);
    /* warm-up */
    bruteforce_kernel_strict_ilp2<<<40, 128>>>(0, (uint64_t)40*128*1024, pc, mi,
        d_kt, d_bs, d_bk, d_stop);
    cudaDeviceSynchronize();
    /* timed */
    cudaEventRecord(ev0);
    bruteforce_kernel_strict_ilp2<<<40, 128>>>(0, (uint64_t)40*128*1024*4, pc, mi,
        d_kt, d_bs, d_bk, d_stop);
    cudaEventRecord(ev1);
    cudaEventSynchronize(ev1);
    float ms = 0; cudaEventElapsedTime(&ms, ev0, ev1);
    unsigned long long kt = 0;
    cudaMemcpy(&kt, d_kt, sizeof(kt), cudaMemcpyDeviceToHost);
    double kps = (double)kt / (ms / 1000.0);
    double cyc = (ms/1000.0) * 1035e6 / (double)kt;
    printf("  payloads=%3d  blocks=%4d  -> %6.2f M keys/s  (%.0f cyc/key)\n",
           pc, 40, kps/1e6, cyc);
    cudaMemset(d_kt, 0, sizeof(unsigned long long));
}
```

### Paso 4: Compilar y comparar

```bat
build_bench.bat
bin\test_bench.exe --bin test/aaaaa/RC4-40.fromdsdfme.bin --key 373374ABE8 --secs 2
```

**Resultado esperado:**
- ILP-2 con 126 payloads: ≥ 0.35 M/s por sí solo (kernel no tiene pruning)
- Efectivo con pruning dinámico en app: objetivo ≥ 12 M/s

**Commit:**
```bash
git add src/bruteforce.cu src/test_bench.cu
git commit -m "perf: add ILP-2 kernel bruteforce_kernel_strict_ilp2 with 2 keys/thread"
```

---

## TAREA 2: Rechazo anticipado en burst k=1

### Fundamento

Con el floor actual, el rechazo comienza en k=3. A k=1:
- Clave incorrecta: score ≈ 24 (HD aleatorio), σ ≈ 3.46
- Floor propuesto para k=1: `33*1 - 2*3.46 = 26.1`
- P(rechazo correcto) = P(Z < 0.61) ≈ 73%

Esto elimina el 73% de claves tras solo 21 pasos PRGA adicionales (vs las 63 pasos
actuales mínimos). Ahorro esperado: ~6% del tiempo total (el KSA 256+256 sigue siendo
costo fijo).

### Cambio en `cuda_launcher_thread` (host_abs_floor)

```c
/* Habilitar rechazo desde k=1: σ_k = 3.46*sqrt(k) */
host_abs_floor[0] = -FLT_MAX;
for (int k = 1; k <= payload_limit; ++k) {
    float sigma_k = 3.46f * sqrtf((float)k);
    /* Floor = 33k - 2σ (rejects 99.97% wrong at k≥3, 73% at k=1) */
    host_abs_floor[k] = 33.0f * (float)k - 2.0f * sigma_k;
}
```

### Cambio en `bruteforce_kernel_strict` (quitar guarda `>= 3`)

```c
/* ANTES: */
if (enable_prune && processed_bursts >= 3 &&
    total_score < d_abs_floor[processed_bursts]) {
    goto next_key;
}

/* DESPUÉS: */
if (enable_prune && processed_bursts >= 1 &&
    total_score < d_abs_floor[processed_bursts]) {
    goto next_key;
}
```

Aplicar el mismo cambio al kernel ILP-2 (`bursts_a >= 1`, `bursts_b >= 1`).

**IMPORTANTE:** Verificar que la clave correcta no sea rechazada. Test:
```bat
bin\test_bench.exe --bin test/aaaaa/RC4-40.fromdsdfme.bin --key 373374ABE8
```
Debe seguir dando PASS con score ≥ 5000.

**Commit:**
```bash
git add src/bruteforce.cu
git commit -m "perf: enable per-burst floor rejection from k=1 (was k=3)"
```

---

## TAREA 3: Hilos CPU paralelos al GPU (CPU workers) añadir AVX2

### Fundamento

El motor ya tiene CPU workers (`cpu_worker_proc` en `bruteforce.cu` línea ~1824) pero
solo se activan cuando NO hay GPU. La mejora: activar N hilos CPU simultáneamente
con la búsqueda GPU, asignándoles el **final del keyspace** (claves altas), mientras
el GPU trabaja desde el principio (claves bajas).

Con 4 hilos CPU a ~1 M/s cada uno: +4 M/s sobre los 8.1 M/s GPU = ~12 M/s total.

### Cambio en `bruteforce.cu` — `cuda_launcher_thread`

Al inicio de `cuda_launcher_thread`, antes de lanzar el kernel GPU, lanzar también
los workers CPU sobre la **segunda mitad del keyspace**:

```c
/* Número de hilos CPU a usar (deja 2 cores libres para GUI/OS) */
SYSTEM_INFO sysinfo;
GetSystemInfo(&sysinfo);
int n_cpu = (int)sysinfo.dwNumberOfProcessors - 2;
if (n_cpu < 1) n_cpu = 1;
if (n_cpu > 8) n_cpu = 8; /* cap para no saturar */

uint64_t total_range = engine->cfg.end_key - engine->cfg.start_key + 1;
uint64_t gpu_range   = total_range * 3 / 4; /* GPU toma 75% */
uint64_t cpu_range   = total_range - gpu_range;
uint64_t cpu_start   = engine->cfg.start_key + gpu_range;

/* Lanzar hilos CPU sobre [cpu_start, end_key] */
uint64_t cpu_chunk = cpu_range / (uint64_t)n_cpu;
CpuWorkerCtx *cpu_ctxs = (CpuWorkerCtx*)calloc(n_cpu, sizeof(CpuWorkerCtx));
HANDLE *cpu_handles = (HANDLE*)calloc(n_cpu, sizeof(HANDLE));
for (int t = 0; t < n_cpu; t++) {
    cpu_ctxs[t].engine       = engine;
    cpu_ctxs[t].start_key    = cpu_start + (uint64_t)t * cpu_chunk;
    cpu_ctxs[t].end_key      = (t == n_cpu-1)
                                ? engine->cfg.end_key
                                : cpu_ctxs[t].start_key + cpu_chunk - 1;
    cpu_ctxs[t].worker_index = t;
    cpu_handles[t] = (HANDLE)_beginthreadex(NULL, 0, cpu_worker_proc,
                                             &cpu_ctxs[t], 0, NULL);
}

/* Ajustar rango del GPU para que no solape con CPU */
engine->cfg.end_key = engine->cfg.start_key + gpu_range - 1;

/* ... lanzar kernel GPU normalmente ... */

/* Al final, esperar a hilos CPU */
WaitForMultipleObjects(n_cpu, cpu_handles, TRUE, INFINITE);
for (int t = 0; t < n_cpu; t++) CloseHandle(cpu_handles[t]);
free(cpu_handles);
free(cpu_ctxs);
```

### Ajuste a `score_candidate_host` para modo KMI9

Verificar que `score_candidate_host` detecta el modo KMI9 y usa
`score_burst_correct_cpu` (ya implementado en `bruteforce.c`). Si solo usa el path
legacy, añadir la misma lógica de selección que tiene `score_candidate()`.

### Commit
```bash
git add src/bruteforce.cu
git commit -m "perf: launch CPU worker threads in parallel with GPU brute force"
```

---

## TAREA 4: Herramienta de detección de frames de silencio omitir por ahora — no aporta speedup inmediato

### ¿Para qué sirve?

Un frame AMBE de silencio tiene 49 bits conocidos (parámetros = 0 o patrones
específicos de silencio). Si identificamos qué payloads son silencio, podemos:
1. Obtener 7 bytes de texto plano conocido por cada frame
2. XOR con el ciphertext → 7 bytes de keystream conocidos
3. Hacer un test de clave en O(1) comparando 7 bytes: si `rc4(key9, drop)` no
   produce esos 7 bytes, rechazar la clave sin más cómputo

Esto convierte el "silencio" en un filtro casi perfecto (P(falso positivo) = 1/2^56).

### Limitación: chicken-and-egg

Para marcar frames de silencio necesitamos la clave, y para obtener la clave usamos
los frames. Para DATOS DE ENTRENAMIENTO (clave conocida), podemos marcarlos y estudiar
los patrones. Para capturas futuras, se necesita un método estadístico.

### Archivo a crear: `tools/mark_silence_frames.py`

```python
#!/usr/bin/env python3
"""
mark_silence_frames.py — Identifica frames AMBE de silencio en un .bin file.

Dado el archivo de payloads y la clave correcta, descifra cada frame,
aplica el pipeline KMI9, y comprueba si el plaintext AMBE corresponde a
silencio (primeros 24 bits = C0+C1 con hamming distance < 4 respecto a
todos los vecinos).

Uso:
    python tools/mark_silence_frames.py --bin test/aaaaa/RC4-40.fromdsdfme.bin
                                        --key 373374ABE8
                                        --out test/aaaaa/silence_frames.json
"""

import argparse
import json
import sys

# Pipeline KMI9 de referencia (reutiliza verify_decrypt.py si está disponible)
# ... implementación completa en el archivo ...

def lfsr32_step(mi: int) -> int:
    bit = ((mi >> 31) ^ (mi >> 3) ^ (mi >> 1)) & 1
    return ((mi << 1) | bit) & 0xFFFFFFFF

def ksa9(key5: bytes, mi: int) -> list:
    key9 = list(key5) + [(mi >> (24 - 8*i)) & 0xFF for i in range(4)]
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key9[i % 9]) & 0xFF
        S[i], S[j] = S[j], S[i]
    return S

def prga_bytes(S: list, n: int) -> bytes:
    S = S[:]
    i = j = 0
    out = []
    for _ in range(n):
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        out.append(S[(S[i] + S[j]) & 0xFF])
    return bytes(out)

# Tabla de de-interleave (rW/rX/rY/rZ) — ver CLAUDE.md
# SF0: dibits 0-35; SF1: 36-53,78-95; SF2: 96-131
def deinterleave_sf(payload_33: bytes, sf: int) -> list:
    """Extrae los 49 bits AMBE para un sub-frame dado."""
    # ... implementación según layout de CLAUDE.md ...
    pass

def is_silence_frame(ambe_bits_49: list, threshold: int = 5) -> bool:
    """Comprueba si los 49 bits AMBE corresponden a silencio/unvoiced.

    Heurística: b0 (voiced/unvoiced) = 0 y suma de bits < threshold.
    """
    if ambe_bits_49[0] != 0:  # b0 = voiced → no silencio puro
        return False
    return sum(ambe_bits_49[:12]) < threshold  # C0 mostly zero

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--bin', required=True)
    ap.add_argument('--key', required=True)
    ap.add_argument('--out', default='silence_frames.json')
    args = ap.parse_args()

    key5 = bytes.fromhex(args.key)
    assert len(key5) == 5, "Key must be 5 bytes (10 hex chars)"

    with open(args.bin) as f:
        lines = [l.strip() for l in f if l.strip()]

    results = []
    for idx, line in enumerate(lines):
        parts = line.split(';')
        payload = bytes.fromhex(parts[0])
        meta = {k: v for p in parts[1:] for k, v in [p.split('=')]}
        mi = int(meta.get('MI', '0'), 16)

        S = ksa9(key5, mi)
        burst_pos = idx % 6
        drop = 256 + burst_pos * 21

        ks = prga_bytes(S, drop + 21)
        ks_burst = ks[drop:]

        for sf in range(3):
            ambe_bits = deinterleave_sf(payload, sf)
            if ambe_bits and is_silence_frame(ambe_bits):
                results.append({
                    'line_idx': idx,
                    'sf': sf,
                    'drop': drop + sf * 7,
                    'cipher_7': payload.hex(),  # raw para lookup
                    'keystream_7': ks_burst[sf*7:(sf+1)*7].hex()
                })
                print(f"Frame {idx} SF{sf}: SILENCE  (mi={mi:08X})")

    with open(args.out, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"\n{len(results)} silence sub-frames → {args.out}")

if __name__ == '__main__':
    main()
```

**Ejecutar con datos de prueba:**
```bat
python tools/mark_silence_frames.py --bin test/aaaaa/RC4-40.fromdsdfme.bin ^
       --key 373374ABE8 --out test/aaaaa/silence_frames.json
```

**Commit:**
```bash
git add tools/mark_silence_frames.py
git commit -m "feat: add silence frame detector for known-plaintext analysis"
```

---

## Resumen de resultados esperados

| Mejora | Speedup estimado | Tiempo 40-bit (laptop) |
|--------|-----------------|----------------------|
| Baseline actual | 1× | ~38 horas |
| + ILP-2 kernel | +50-80% | ~21-25 horas |
| + Rechazo k=1 | +5-6% | ~20-24 horas |
| + CPU workers (4 cores) | +4-8 M/s absolutos | ~15-18 horas |
| **Total combinado** | **~2-2.5×** | **~15-20 horas** |

> **Nota realista:** Go2Key en servidor de 32 cores AVX512 ≈ 150 M/s → ~2 horas.
> En RTX 3050 Ti laptop el techo físico es ~20 M/s. La diferencia es hardware puro:
> 32 cores × AVX-512 × RC4-optimizado vs GPU con S-box en L1.
> Para igualar Go2Key necesitarías RTX 4090 (128 SMs × 2.5× clock = ~65 M/s GPU)
> más CPU workers → ~75 M/s → ~4 horas.

---

## Orden de implementación recomendado

1. **Tarea 1** (ILP-2) — mayor impacto, validar con test_bench antes de integrar
2. **Tarea 2** (rechazo k=1) — cambio de 1 línea, verificar no-regresión con --key
3. **Tarea 3** (CPU workers) — cuidado con la sincronización de `engine->best_key`
4. **Tarea 4** (silence tool) — útil para análisis, no bloquea las anteriores
