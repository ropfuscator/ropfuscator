cmake_minimum_required(VERSION 3.0)
project(ropfuscator-extra ASM)

include("cmake/ropfuscator-utils.cmake")

option(ROPF_PROFILE "Enable profiling in ropfuscated program." OFF)
option(USE_LIBC "Extract gadgets from libc instead of ropfuscator's librop."
       OFF)

set(CMAKE_C_FLAGS "-m32 -fpie")
set(CMAKE_ASM_FLAGS "-m32 -fpie")
set(CMAKE_EXE_LINKER_FLAGS "-m32 -pie -Wl,-rpath,${CMAKE_BINARY_DIR}/lib")
set(COMPILER_PROFILING_FLAGS -fcoverage-mapping)
set(LINKER_PROFILING_FLAGS -fprofile-instr-generate)
set(ROPF_IR_FLAGS -O0 -m32 -c -emit-llvm)
set(ROPF_ASM_FLAGS -march=x86)
set(ROPF_OBFUSCATIONS_CONFIG_DIR ${CMAKE_CURRENT_SOURCE_DIR}/configs)

# prefer 32-bit library locations
set(CMAKE_LIBRARY_PATH
    "${CMAKE_LIBRARY_PATH};/usr/lib/i386-linux-gnu;/usr/lib32"
    CACHE PATH "")

# we should use librop
if(NOT USE_LIBC)
  set(ROPF_ASM_FLAGS ${ROPF_ASM_FLAGS} --ropfuscator-library=$<TARGET_FILE:rop>)
endif()

if(CMAKE_BUILD_TYPE MATCHES DEBUG)
  set(ROPF_ASM_FLAGS
      ${ROPF_ASM_FLAGS}
      -debug-only=xchg_chains,ropchains,processed_instr,liveness_analysis)
endif()

add_subdirectory("librop")
add_subdirectory("binutils" EXCLUDE_FROM_ALL)
add_subdirectory("evaluation" EXCLUDE_FROM_ALL)
add_subdirectory("examples" EXCLUDE_FROM_ALL)
add_subdirectory("testcase" EXCLUDE_FROM_ALL)
add_subdirectory("thirdparty/chocolate-doom" EXCLUDE_FROM_ALL)
