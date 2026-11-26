cmake_minimum_required(VERSION 3.20)
project(bionic_shim C ASM)
set(CMAKE_C_STANDARD 11)
add_library(bionic_shim SHARED
    bionic_pthread.c
    bionic_posix.c
    bionic_android.c
    bionic_tlsdesc.c
    bionic_tlsdesc.S
    bionic_varargs.S
    bionic_varargs.c
    bionic_libc.c
    bionic_jmp.S)
target_include_directories(bionic_shim PRIVATE .)
set_target_properties(bionic_shim PROPERTIES
    OUTPUT_NAME bionic_shim
    BUILD_WITH_INSTALL_RPATH TRUE
    INSTALL_RPATH "@loader_path")
set(CMAKE_SHARED_LIBRARY_PREFIX "lib")
