#include "puf_data.h"

/*
 * Runtime PUF chain storage. With MAX_NUM_CLIENTS=500 and CHAIN_LEN=400,
 * PUF_CHAIN_TA occupies 500 * 400 * 16 = 3.2 MB in BSS.
 */
UInt128 PUF_CHAIN_TA[MAX_NUM_CLIENTS][CHAIN_LEN];
UInt128 PUF_CHAIN_SRV[CHAIN_LEN];

void init_puf_chains_bench(uint32_t seed) {
    uint32_t s = seed;
    auto next = [&s]() -> uint32_t {
        s = s * 1664525u + 1013904223u;   /* Numerical Recipes LCG */
        return s;
    };

    for (int c = 0; c < MAX_NUM_CLIENTS; c++) {
        for (int l = 0; l < CHAIN_LEN; l++) {
            PUF_CHAIN_TA[c][l] = UInt128{next(), next(), next(), next()};
        }
    }
    for (int l = 0; l < CHAIN_LEN; l++) {
        PUF_CHAIN_SRV[l] = UInt128{next(), next(), next(), next()};
    }
}
