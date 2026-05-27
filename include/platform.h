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

#ifndef PLATFORM_H
#define PLATFORM_H

/*
 * platform.h — thin Win32/POSIX abstraction layer
 *
 * Wraps threading, atomics, synchronization, and timing so that
 * bruteforce.cu / bruteforce.c compile and run on both Windows and Linux
 * without ifdefs scattered everywhere.
 *
 * Rule: include this header instead of <windows.h> in engine code.
 * GUI code (gui.c) still includes <windows.h> directly and is Windows-only.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* ── Types ────────────────────────────────────────────────────────────── */

#if defined(_WIN32)

/* ── Windows implementation ───────────────────────────────────────────── */
#include <windows.h>
#include <process.h>

typedef HANDLE          plat_thread_t;
typedef HANDLE          plat_event_t;
typedef CRITICAL_SECTION plat_mutex_t;
typedef volatile LONG   plat_atomic32_t;
typedef volatile LONG64 plat_atomic64_t;
typedef DWORD           plat_ticks_t;

/* ── Thread ───────────────────────────────────────────────────────────── */

/* Thread function type: unsigned __stdcall fn(void *) on Windows */
typedef unsigned (__stdcall *plat_thread_fn_t)(void *);

#define PLAT_THREAD_RETURN_T  unsigned
#define PLAT_THREAD_CALL      __stdcall
#define PLAT_THREAD_RETURN    return 0u

static inline int plat_thread_create(plat_thread_t *out, plat_thread_fn_t fn, void *arg)
{
    uintptr_t h = _beginthreadex(NULL, 0, fn, arg, 0, NULL);
    if (h == 0) return -1;
    *out = (HANDLE)h;
    return 0;
}

static inline void plat_thread_join(plat_thread_t t)
{
    WaitForSingleObject(t, INFINITE);
}

static inline void plat_thread_close(plat_thread_t t)
{
    CloseHandle(t);
}

static inline void plat_threads_join(plat_thread_t *handles, int count)
{
    if (count > 0 && handles != NULL)
        WaitForMultipleObjects((DWORD)count, handles, TRUE, INFINITE);
}

static inline void plat_thread_set_affinity(int worker_index)
{
    if (worker_index < 64)
        SetThreadAffinityMask(GetCurrentThread(), 1ULL << (unsigned)worker_index);
}

static inline void plat_thread_set_ideal_processor(int idx)
{
    SetThreadIdealProcessor(GetCurrentThread(), (DWORD)idx);
}

/* ── Mutex ────────────────────────────────────────────────────────────── */

static inline void plat_mutex_init(plat_mutex_t *m)    { InitializeCriticalSection(m); }
static inline void plat_mutex_destroy(plat_mutex_t *m) { DeleteCriticalSection(m); }
static inline void plat_mutex_lock(plat_mutex_t *m)    { EnterCriticalSection(m); }
static inline void plat_mutex_unlock(plat_mutex_t *m)  { LeaveCriticalSection(m); }

/* ── Event (manual-reset) ─────────────────────────────────────────────── */

/* signaled=1 means threads waiting on plat_event_wait() are released immediately */
static inline plat_event_t plat_event_create(int signaled)
{
    return CreateEventA(NULL, TRUE, signaled ? TRUE : FALSE, NULL);
}
static inline void plat_event_destroy(plat_event_t *e) { CloseHandle(*e); *e = NULL; }
static inline void plat_event_set(plat_event_t *e)     { SetEvent(*e); }
static inline void plat_event_reset(plat_event_t *e)   { ResetEvent(*e); }
static inline void plat_event_wait(plat_event_t *e)    { WaitForSingleObject(*e, INFINITE); }

/* ── 32-bit atomics ───────────────────────────────────────────────────── */

static inline long plat_atomic32_load(plat_atomic32_t *a)
{
    return InterlockedCompareExchange(a, 0, 0);
}
static inline void plat_atomic32_store(plat_atomic32_t *a, long val)
{
    InterlockedExchange(a, val);
}
static inline long plat_atomic32_inc(plat_atomic32_t *a)
{
    return InterlockedIncrement(a);
}

/* ── 64-bit atomics ───────────────────────────────────────────────────── */

static inline int64_t plat_atomic64_load(plat_atomic64_t *a)
{
    return InterlockedCompareExchange64(a, 0, 0);
}
static inline void plat_atomic64_store(plat_atomic64_t *a, int64_t val)
{
    InterlockedExchange64(a, val);
}
static inline void plat_atomic64_add(plat_atomic64_t *a, int64_t delta)
{
    InterlockedAdd64(a, delta);
}

/* ── Timing ───────────────────────────────────────────────────────────── */

/* Returns milliseconds since some arbitrary epoch (monotonic) */
static inline uint64_t plat_ticks_ms(void)
{
    return (uint64_t)GetTickCount64();
}

/* High-resolution timer for throughput measurement */
typedef struct { LARGE_INTEGER val; } plat_hrtimer_t;
typedef struct { LARGE_INTEGER val; } plat_hrfreq_t;

static inline void plat_hrfreq_init(plat_hrfreq_t *f)
{
    QueryPerformanceFrequency(&f->val);
}
static inline void plat_hrtimer_now(plat_hrtimer_t *t)
{
    QueryPerformanceCounter(&t->val);
}
static inline double plat_hrtimer_elapsed_s(const plat_hrtimer_t *start,
                                             const plat_hrtimer_t *end,
                                             const plat_hrfreq_t  *freq)
{
    return (double)(end->val.QuadPart - start->val.QuadPart)
         / (double)freq->val.QuadPart;
}

/* ── CPU count ────────────────────────────────────────────────────────── */

static inline int plat_cpu_count(void)
{
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    return (int)si.dwNumberOfProcessors;
}

/* ── Directory creation (best-effort, no error checking) ──────────────── */

static inline void plat_mkdir(const char *path) { CreateDirectoryA(path, NULL); }

/* ── File deletion ────────────────────────────────────────────────────── */

static inline void plat_delete_file(const char *path) { DeleteFileA(path); }

#else  /* ── POSIX (Linux, macOS) ────────────────────────────────────── */

/* Required for cpu_set_t, CPU_ZERO/SET, pthread_setaffinity_np on Linux */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <pthread.h>
#include <stdatomic.h>
#include <time.h>
#include <unistd.h>
#include <sched.h>
#include <stdio.h>

typedef pthread_t        plat_thread_t;
typedef pthread_mutex_t  plat_mutex_t;
typedef _Atomic int32_t  plat_atomic32_t;
typedef _Atomic int64_t  plat_atomic64_t;

/* POSIX doesn't have manual-reset events natively; we build one from a
 * mutex + condvar + boolean flag.  The struct is small enough to embed. */
typedef struct {
    pthread_mutex_t  mu;
    pthread_cond_t   cv;
    int              signaled;
} plat_event_t;

/* ── Thread ───────────────────────────────────────────────────────────── */

/* Thread function type: void *fn(void *) on POSIX */
typedef void *(*plat_thread_fn_t)(void *);

#define PLAT_THREAD_RETURN_T  void *
#define PLAT_THREAD_CALL
#define PLAT_THREAD_RETURN    return NULL

static inline int plat_thread_create(plat_thread_t *out, plat_thread_fn_t fn, void *arg)
{
    return pthread_create(out, NULL, fn, arg);
}

static inline void plat_thread_join(plat_thread_t t)
{
    pthread_join(t, NULL);
}

static inline void plat_thread_close(plat_thread_t t)
{
    (void)t;  /* pthread_t resources are released by plat_thread_join; nothing more to close */
}

static inline void plat_threads_join(plat_thread_t *handles, int count)
{
    for (int i = 0; i < count; ++i)
        pthread_join(handles[i], NULL);
}

static inline void plat_thread_set_affinity(int worker_index)
{
#if defined(__linux__)
    cpu_set_t cs;
    CPU_ZERO(&cs);
    CPU_SET(worker_index % (int)sysconf(_SC_NPROCESSORS_CONF), &cs);
    pthread_setaffinity_np(pthread_self(), sizeof(cs), &cs);
#else
    (void)worker_index;
#endif
}

static inline void plat_thread_set_ideal_processor(int idx) { (void)idx; }

/* ── Mutex ────────────────────────────────────────────────────────────── */

static inline void plat_mutex_init(plat_mutex_t *m)    { pthread_mutex_init(m, NULL); }
static inline void plat_mutex_destroy(plat_mutex_t *m) { pthread_mutex_destroy(m); }
static inline void plat_mutex_lock(plat_mutex_t *m)    { pthread_mutex_lock(m); }
static inline void plat_mutex_unlock(plat_mutex_t *m)  { pthread_mutex_unlock(m); }

/* ── Manual-reset event ───────────────────────────────────────────────── */

static inline plat_event_t plat_event_create(int signaled)
{
    plat_event_t e;
    pthread_mutex_init(&e.mu, NULL);
    pthread_cond_init(&e.cv, NULL);
    e.signaled = signaled ? 1 : 0;
    return e;
}
static inline void plat_event_destroy(plat_event_t *e)
{
    pthread_mutex_destroy(&e->mu);
    pthread_cond_destroy(&e->cv);
}
static inline void plat_event_set(plat_event_t *e)
{
    pthread_mutex_lock(&e->mu);
    e->signaled = 1;
    pthread_cond_broadcast(&e->cv);
    pthread_mutex_unlock(&e->mu);
}
static inline void plat_event_reset(plat_event_t *e)
{
    pthread_mutex_lock(&e->mu);
    e->signaled = 0;
    pthread_mutex_unlock(&e->mu);
}
static inline void plat_event_wait(plat_event_t *e)
{
    pthread_mutex_lock(&e->mu);
    while (!e->signaled)
        pthread_cond_wait(&e->cv, &e->mu);
    pthread_mutex_unlock(&e->mu);
}

/* ── 32-bit atomics ───────────────────────────────────────────────────── */

static inline int32_t plat_atomic32_load(plat_atomic32_t *a)
{
    return atomic_load_explicit(a, memory_order_acquire);
}
static inline void plat_atomic32_store(plat_atomic32_t *a, int32_t val)
{
    atomic_store_explicit(a, val, memory_order_release);
}
static inline int32_t plat_atomic32_inc(plat_atomic32_t *a)
{
    return atomic_fetch_add_explicit(a, 1, memory_order_acq_rel) + 1;
}

/* ── 64-bit atomics ───────────────────────────────────────────────────── */

static inline int64_t plat_atomic64_load(plat_atomic64_t *a)
{
    return atomic_load_explicit(a, memory_order_acquire);
}
static inline void plat_atomic64_store(plat_atomic64_t *a, int64_t val)
{
    atomic_store_explicit(a, val, memory_order_release);
}
static inline void plat_atomic64_add(plat_atomic64_t *a, int64_t delta)
{
    atomic_fetch_add_explicit(a, delta, memory_order_acq_rel);
}

/* ── Timing ───────────────────────────────────────────────────────────── */

static inline uint64_t plat_ticks_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)(ts.tv_nsec / 1000000);
}

typedef struct { struct timespec val; } plat_hrtimer_t;
typedef struct { int dummy; }           plat_hrfreq_t;   /* no freq concept on POSIX */

static inline void plat_hrfreq_init(plat_hrfreq_t *f)  { (void)f; }
static inline void plat_hrtimer_now(plat_hrtimer_t *t) { clock_gettime(CLOCK_MONOTONIC, &t->val); }
static inline double plat_hrtimer_elapsed_s(const plat_hrtimer_t *start,
                                             const plat_hrtimer_t *end,
                                             const plat_hrfreq_t  *freq)
{
    (void)freq;
    double ds = (double)(end->val.tv_sec  - start->val.tv_sec);
    double dn = (double)(end->val.tv_nsec - start->val.tv_nsec) * 1e-9;
    return ds + dn;
}

/* ── CPU count ────────────────────────────────────────────────────────── */

static inline int plat_cpu_count(void)
{
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    return (n > 0) ? (int)n : 1;
}

/* ── Directory creation (best-effort, no error checking) ──────────────── */

#include <sys/stat.h>
static inline void plat_mkdir(const char *path) { mkdir(path, 0755); }

/* ── File deletion ────────────────────────────────────────────────────── */
#include <stdio.h>
static inline void plat_delete_file(const char *path) { remove(path); }

#endif  /* _WIN32 */

#endif  /* PLATFORM_H */
