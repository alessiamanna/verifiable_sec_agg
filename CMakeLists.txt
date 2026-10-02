cmake_minimum_required(VERSION 3.14)
project(HeVersaProtocol)

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)
option(BUILD_PYTHON_MODULE "Build the pybind11 Python extension module" ON)

# set fallbacks default values
set(MAX_NUM_CLIENTS 10 CACHE STRING "Maximum number of clients")
set(BENCH_MAX_NUM_CLIENTS 1000 CACHE STRING "Maximum number of clients for the benchmark target")

set(PROTOCOL_SOURCES
    src/heversa_api.cpp
    src/heversa_sim.cpp
    src/node.cpp
    src/server.cpp
    src/ta.cpp
    src/common_share.cpp
    src/puf_manager.cpp
    src/crypto_utils.cpp
    src/sss/sss.c
    src/sss/hazmat.c
    src/sss/tweetnacl.c
    src/sss/randombytes.c
)

if(BUILD_PYTHON_MODULE AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/extern/pybind11/CMakeLists.txt")
    add_subdirectory(extern/pybind11)
    pybind11_add_module(heversa src/wrapper.cpp ${PROTOCOL_SOURCES})
    target_link_libraries(heversa PRIVATE pybind11::module OpenSSL::Crypto)
    target_include_directories(heversa PRIVATE ${OPENSSL_INCLUDE_DIR} src src/sss)
    target_compile_definitions(heversa PRIVATE DEBUG=1 UPDATE_LEN=${UPDATE_LEN} MAX_NUM_CLIENTS=${MAX_NUM_CLIENTS})
    target_compile_features(heversa PRIVATE cxx_std_17)
endif()

add_executable(protocol_sim src/main_ta.cpp ${PROTOCOL_SOURCES})
target_link_libraries(protocol_sim PRIVATE OpenSSL::Crypto)
target_include_directories(protocol_sim PRIVATE ${OPENSSL_INCLUDE_DIR} src src/sss)
target_compile_definitions(protocol_sim PRIVATE DEBUG=1 UPDATE_LEN=${UPDATE_LEN} MAX_NUM_CLIENTS=${MAX_NUM_CLIENTS})
target_compile_features(protocol_sim PRIVATE cxx_std_17)

add_executable(benchmark
    src/benchmark.cpp
    src/sim_gen.cpp
    src/bench/puf_data_bench.cpp
    ${PROTOCOL_SOURCES}
)
target_link_libraries(benchmark PRIVATE OpenSSL::Crypto Threads::Threads)
target_include_directories(benchmark PRIVATE src/bench ${OPENSSL_INCLUDE_DIR} src src/sss)
target_compile_definitions(benchmark PRIVATE
    DEBUG=0
    BENCHMARK_RUNTIME_PUF=1
    MAX_NUM_CLIENTS=${BENCH_MAX_NUM_CLIENTS}
)
target_compile_features(benchmark PRIVATE cxx_std_17)
if(MSVC)
    target_compile_options(benchmark PRIVATE /O2)
else()
    target_compile_options(benchmark PRIVATE -O2)
endif()
