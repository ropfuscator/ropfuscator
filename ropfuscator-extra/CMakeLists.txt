cmake_minimum_required(VERSION 3.13)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -m32 -fpie")
set(CMAKE_ASM_FLAGS "${CMAKE_ASM_FLAGS} -m32 -fpie")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -pie")
set(COMPILER_PROFILING_FLAGS -g -fcoverage-mapping)
set(LINKER_PROFILING_FLAGS -fprofile-instr-generate)
set(ROPF_IR_FLAGS -O0 -S -emit-llvm -fno-omit-frame-pointer -mno-omit-leaf-frame-pointer -m32)
set(ROPF_ASM_FLAGS -march=x86 --disable-fp-elim -debug-only=xchg_chains,ropchains,processed_instr,liveness_analysis --use-custom-lib /home/user/crash/libc-2.29.so)

project(ropfuscator-extra ASM)

find_library(BFD bfd)
find_library(DL dl)

option(ROPF_PROFILE "Enable profiling in ropfuscated program." OFF)
option(ROPF_LIBNAIVE "Link ropfuscated binary with libnaive" OFF)
option(ROPF_OPAQUEP "Enable opaque predicates to protect the ROP chains." OFF)

add_subdirectory("binutils" EXCLUDE_FROM_ALL)
add_subdirectory("examples" EXCLUDE_FROM_ALL)
add_subdirectory("lib" EXCLUDE_FROM_ALL)
