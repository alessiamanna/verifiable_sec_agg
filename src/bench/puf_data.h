#ifndef PUF_DATA_H
#define PUF_DATA_H

/*
 * Benchmark-specific PUF data header.
 * Replaces the static const arrays from cr_gen.py with runtime-initialized
 * arrays filled by init_puf_chains_bench(). This allows scaling to large
 * client counts (up to MAX_NUM_CLIENTS) without a multi-MB generated header.
 *
 * Shadowed via CMake include path ordering: src/bench comes before src.
 */

#include "common.h"

#ifndef CHAIN_LEN
#define CHAIN_LEN 400
#endif

#ifndef PUF_SIZE_BYTE
#define PUF_SIZE_BYTE 16
#endif

/* Runtime-initialized PUF chains */
extern UInt128 PUF_CHAIN_TA[MAX_NUM_CLIENTS][CHAIN_LEN];
extern UInt128 PUF_CHAIN_SRV[CHAIN_LEN];

/**
 * Fill PUF chains with deterministic pseudo-random data.
 * Must be called once before any protocol function.
 */
void init_puf_chains_bench(uint32_t seed);

#endif /* PUF_DATA_H */
