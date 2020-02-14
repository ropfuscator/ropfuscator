cmake_minimum_required(VERSION 3.13)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -m32 -fpie")
set(CMAKE_ASM_FLAGS "${CMAKE_ASM_FLAGS} -m32 -fpie")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -pie")
set(COMPILER_PROFILING_FLAGS -fcoverage-mapping)
set(LINKER_PROFILING_FLAGS -fprofile-instr-generate)
set(ROPF_IR_FLAGS -O0 -m32 -c -emit-llvm) # -fno-omit-frame-pointer -mno-omit-leaf-frame-pointer
set(ROPF_ASM_FLAGS -march=x86) # --disable-fp-elim --use-custom-lib /path/to/your/libc.so

if (ROPF_OPAQUEP)
    set(ROPF_ASM_FLAGS ${ROPF_ASM_FLAGS} -fopaque-predicates)
endif ()

if (CMAKE_BUILD_TYPE MATCHES DEBUG)
    set(ROPF_ASM_FLAGS ${ROPF_ASM_FLAGS} -debug-only=xchg_chains,ropchains,processed_instr,liveness_analysis)
endif ()

project(ropfuscator-extra ASM)

option(ROPF_PROFILE "Enable profiling in ropfuscated program." OFF)
option(ROPF_LIBNAIVE "Link ropfuscated binary with libnaive" OFF)
option(ROPF_OPAQUEP "Enable opaque predicates to protect the ROP chains." OFF)

# TODO: how to check for clang target?
# if (NOT $<TARGET_FILE:clang>)
#     message(FATAL_ERROR "Cannot find clang in LLVM's source tree. Please download clang sources and extract them in ${LLVM_SOURCE_DIR}/tools")
# endif ()

add_subdirectory("binutils" EXCLUDE_FROM_ALL)
add_subdirectory("examples" EXCLUDE_FROM_ALL)
add_subdirectory("lib" EXCLUDE_FROM_ALL)
add_subdirectory("testcase" EXCLUDE_FROM_ALL)
add_subdirectory("evaluation" EXCLUDE_FROM_ALL)
