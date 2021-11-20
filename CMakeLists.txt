cmake_minimum_required(VERSION 3.0)
project(ropfuscator-extra CXX C)

set(CMAKE_C_FLAGS "-m32 -fpie")
set(CMAKE_ASM_FLAGS "-m32 -fpie")
set(CMAKE_EXE_LINKER_FLAGS "-m32 -pie -Wl,-rpath,${CMAKE_BINARY_DIR}/lib")
set(COMPILER_PROFILING_FLAGS -fcoverage-mapping)
set(LINKER_PROFILING_FLAGS -fprofile-instr-generate)
set(ROPF_IR_FLAGS -O0 -m32 -c -emit-llvm)
set(ROPF_ASM_FLAGS -march=x86)

# prefer 32-bit library locations
set(CMAKE_LIBRARY_PATH
    "${CMAKE_LIBRARY_PATH};/usr/lib/i386-linux-gnu;/usr/lib32"
    CACHE PATH "")

if(CMAKE_BUILD_TYPE MATCHES DEBUG)
  set(ROPF_ASM_FLAGS
      ${ROPF_ASM_FLAGS}
      -debug-only=xchg_chains,ropchains,processed_instr,liveness_analysis)
endif()
