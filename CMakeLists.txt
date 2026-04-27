cmake_minimum_required(VERSION 3.14)
project(HeVersaProtocol)


find_package(OpenSSL REQUIRED)


add_subdirectory(extern/pybind11)

set(PROTOCOL_SOURCES
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


pybind11_add_module(heversa
src/wrapper.cpp
${PROTOCOL_SOURCES}
)

target_link_libraries(heversa PRIVATE
pybind11::module
OpenSSL::Crypto
)

target_include_directories(heversa PRIVATE
${OPENSSL_INCLUDE_DIR}
src
src/sss
)

target_compile_definitions(heversa PRIVATE DEBUG=1)
target_compile_features(heversa PRIVATE cxx_std_11)



add_executable(protocol_sim
src/main_ta.cpp
${PROTOCOL_SOURCES}
)

target_link_libraries(protocol_sim PRIVATE
OpenSSL::Crypto
)

target_include_directories(protocol_sim PRIVATE
${OPENSSL_INCLUDE_DIR}
src
src/sss
)

target_compile_definitions(protocol_sim PRIVATE DEBUG=1)
target_compile_features(protocol_sim PRIVATE cxx_std_11)
