cmake_minimum_required(VERSION 3.13)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -m32 -fpie")
set(CMAKE_ASM_FLAGS "${CMAKE_ASM_FLAGS} -m32 -fpie")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -pie")
set(COMPILER_PROFILING_FLAGS -g -fcoverage-mapping)
set(LINKER_PROFILING_FLAGS -fprofile-instr-generate)
set(ROPF_IR_FLAGS -O0 -S -emit-llvm -fno-omit-frame-pointer -mno-omit-leaf-frame-pointer -m32)
set(ROPF_ASM_FLAGS -march=x86 --disable-fp-elim -debug-only=${debug-only})

project(ropfuscator-binutils C ASM)

find_library(BFD bfd)
find_library(DL dl)

#if(NOT BFD)
#    message(FATAL_ERROR "libbfd not found.")
#endif()

#if(NOT DL)
#    message(FATAL_ERROR "libdl not found.")
#endif()

option(ROPF_PROFILE "Enable profiling in ropfuscated program." OFF)
option(ROPF_LIBNAIVE_ENABLE "Link ropfuscated binary with libnaive" OFF)

if (ROPF_PROFILE)
    # check if the compiler is clang since
    # we are using clang-specific profiling flags
    if (NOT CMAKE_C_COMPILER_ID MATCHES "Clang" OR NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        message(FATAL_ERROR "You must use clang in order to enable profiling.")
    endif ()
endif ()

add_subdirectory("binutils" EXCLUDE_FROM_ALL)
add_subdirectory("examples" EXCLUDE_FROM_ALL)
add_subdirectory("lib" EXCLUDE_FROM_ALL)
