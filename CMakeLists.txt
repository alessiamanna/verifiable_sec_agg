cmake_minimum_required(VERSION 3.20)
project(protocol_test LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(OpenSSL REQUIRED)

find_library(GMP_LIB NAMES gmp REQUIRED)

set(SSS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/sss")
set(RANDOMBYTES_DIR "${SSS_DIR}/randombytes")

add_executable(protocol_simulation
    src/main_ta.cpp 
    src/node.cpp 
    src/server.cpp 
    src/ta.cpp
    src/common_share.cpp
    src/crypto_utils.cpp
    src/puf_manager.cpp
)

find_path(GMP_INCLUDE_DIR NAMES gmp.h PATHS /usr/include /usr/local/include)
find_library(GMP_LIB NAMES gmp PATHS /usr/lib64 /usr/lib /usr/local/lib)

if(NOT GMP_LIB)
    message(FATAL_ERROR "GMP library not found! Please run: sudo zypper install gmp-devel")
endif()

target_include_directories(protocol_simulation PRIVATE ${GMP_INCLUDE_DIR})
target_link_libraries(protocol_simulation PRIVATE 
    "${SSS_DIR}/sss.o"
    "${SSS_DIR}/hazmat.o"
    "${SSS_DIR}/tweetnacl.o"
    "${SSS_DIR}/randombytes/librandombytes.a"
    OpenSSL::Crypto
    ${GMP_LIB}
)

# Add compiler flags
target_compile_options(protocol_simulation PRIVATE -g -Wall)