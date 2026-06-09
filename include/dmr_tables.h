#ifndef DMR_TABLES_H
#define DMR_TABLES_H

/*
 * DMR voice-burst de-interleave tables -- single source of truth.
 *
 * These constants map the 132-dibit (33-byte) DMR voice payload into the
 * mbelib ambe_fr[4][24] layout, per sub-frame. They are load-bearing: a
 * transcription error silently corrupts only the backend that carries the
 * wrong copy, and the test harness only exercises the CPU path.
 *
 * To avoid that divergence trap the values live here once, as initializer-list
 * macros. Each translation unit still declares its own storage with the right
 * qualifier (host `static const`, or CUDA `__device__ __constant__`) and
 * initializes it from these macros, e.g.:
 *
 *     static const int rW_cpu[36]                = DMR_RW_INIT;
 *     __device__ __constant__ int dmr_rW_dev[36] = DMR_RW_INIT;
 *
 * rW/rY select the ambe_fr row, rX/rZ the column; each of the 36 interleave
 * steps writes the two bits of one dibit. sf_dibit_idx maps interleave step ->
 * dibit index in the payload:
 *   SF0: dibits 0-35
 *   SF1: dibits 36-53 then 78-95 (split by the sync slot at 54-77)
 *   SF2: dibits 96-131
 */

#define DMR_RW_INIT { \
    0, 1, 0, 1, 0, 1, \
    0, 1, 0, 1, 0, 1, \
    0, 1, 0, 1, 0, 1, \
    0, 1, 0, 1, 0, 2, \
    0, 2, 0, 2, 0, 2, \
    0, 2, 0, 2, 0, 2  \
}

#define DMR_RX_INIT { \
    23, 10, 22, 9, 21, 8, \
    20, 7, 19, 6, 18, 5, \
    17, 4, 16, 3, 15, 2, \
    14, 1, 13, 0, 12, 10, \
    11, 9, 10, 8, 9, 7, \
    8, 6, 7, 5, 6, 4 \
}

#define DMR_RY_INIT { \
    0, 2, 0, 2, 0, 2, \
    0, 2, 0, 3, 0, 3, \
    1, 3, 1, 3, 1, 3, \
    1, 3, 1, 3, 1, 3, \
    1, 3, 1, 3, 1, 3, \
    1, 3, 1, 3, 1, 3  \
}

#define DMR_RZ_INIT { \
    5, 3, 4, 2, 3, 1, \
    2, 0, 1, 13, 0, 12, \
    22, 11, 21, 10, 20, 9, \
    19, 8, 18, 7, 17, 6, \
    16, 5, 15, 4, 14, 3, \
    13, 2, 12, 1, 11, 0 \
}

#define DMR_SF_DIBIT_IDX_INIT { \
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, \
      12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, \
      24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35 }, \
    { 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, \
      48, 49, 50, 51, 52, 53, 78, 79, 80, 81, 82, 83, \
      84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95 }, \
    { 96, 97, 98, 99,100,101,102,103,104,105,106,107, \
     108,109,110,111,112,113,114,115,116,117,118,119, \
     120,121,122,123,124,125,126,127,128,129,130,131 } \
}

#endif /* DMR_TABLES_H */
