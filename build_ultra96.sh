#!/usr/bin/env bash
set -e

echo "======================================================="
echo "  HeVerSa Benchmark - Ultra96-V2 Linux Build Script"
echo "======================================================="

mkdir -p build

if [ -f "src/sss/randombytes/randombytes.h" ]; then
    cp -f "src/sss/randombytes/randombytes.h" "src/sss/randombytes.h"
fi
if [ -f "src/sss/randombytes/randombytes.c" ]; then
    cp -f "src/sss/randombytes/randombytes.c" "src/sss/randombytes.c"
fi

echo "[1/2] Compiling C cryptographic dependencies (SSS, TweetNaCl, RandomBytes)..."
gcc -O2 -Isrc/sss -c src/sss/sss.c -o build/sss.o
gcc -O2 -Isrc/sss -c src/sss/hazmat.c -o build/hazmat.o
gcc -O2 -c src/sss/tweetnacl.c -o build/tweetnacl.o
gcc -O2 -c src/sss/randombytes.c -o build/randombytes.o

echo "[2/2] Compiling HeVerSa Single-Node Benchmark (MAX_NUM_CLIENTS=1000)..."
g++ -std=c++17 -O2 -DDEBUG=0 -DBENCHMARK_RUNTIME_PUF=1 -DMAX_NUM_CLIENTS=1000 \
    -Isrc/bench -Isrc -Isrc/sss \
    src/benchmark.cpp \
    src/sim_gen.cpp \
    src/bench/puf_data_bench.cpp \
    src/heversa_api.cpp \
    src/heversa_sim.cpp \
    src/node.cpp \
    src/server.cpp \
    src/ta.cpp \
    src/common_share.cpp \
    src/puf_manager.cpp \
    src/crypto_utils.cpp \
    build/sss.o build/hazmat.o build/tweetnacl.o build/randombytes.o \
    -lcrypto -lpthread \
    -o build/benchmark

echo "Build succeeded: ./build/benchmark"
