set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)


cmake_minimum_required(VERSION 4.1.2)
project(protocol_test LANGUAGES C)

add_executable(protocol src/dev_protocol.c src/prot_test.c)


target_include_directories(protocol PRIVATE src)