cmake_minimum_required(VERSION 3.20)
project(protocol_test LANGUAGES C)

set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

find_package(OpenSSL REQUIRED)

find_library(GMP_LIB NAMES gmp REQUIRED)

set(SSS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/sss")
set(RANDOMBYTES_DIR "${SSS_DIR}/randombytes")

add_executable(protocol 
    src/main_ta.c 
    src/node.c 
    src/server.c 
    src/ta.c 
    src/common_share.c
    src/crypto_utils.c
    src/puf_manager.c
)

find_path(GMP_INCLUDE_DIR NAMES gmp.h PATHS /usr/include /usr/local/include)
find_library(GMP_LIB NAMES gmp PATHS /usr/lib64 /usr/lib /usr/local/lib)

if(NOT GMP_LIB)
    message(FATAL_ERROR "GMP library not found! Please run: sudo zypper install gmp-devel")
endif()

target_include_directories(protocol PRIVATE ${GMP_INCLUDE_DIR})
target_link_libraries(protocol PRIVATE 
    "${SSS_DIR}/sss.o"
    "${SSS_DIR}/hazmat.o"
    "${SSS_DIR}/tweetnacl.o"
    "${SSS_DIR}/randombytes/librandombytes.a"
    OpenSSL::Crypto
    ${GMP_LIB}
)

# Add compiler flags
target_compile_options(protocol PRIVATE -g -Wall)