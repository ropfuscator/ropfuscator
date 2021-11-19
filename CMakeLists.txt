cmake_minimum_required(VERSION 3.0)
project(ropfuscator-extra ASM)

include("cmake/ropfuscator-utils.cmake")

option(ROPF_PROFILE "Enable profiling in ropfuscated program." OFF)
option(
  USE_LIBROP
  "Extract gadgets from ropfuscator's librop. If enabled with other libraries, ROPfuscator will produce multiple binaries."
  ON)
option(
  USE_LIBC
  "Extract gadgets from libc. If enabled with other libraries, ROPfuscator will produce multiple binaries."
  OFF)
option(
  ROPFUSCATOR_LIB
  "Shared library path to extract gadgets from. If enabled with other libraries, ROPfuscator will produce multiple binaries."
)

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

# ropfuscator configuration files
set(ROPF_OBFUSCATIONS_CONFIG_DIR ${CMAKE_CURRENT_SOURCE_DIR}/configs)
file(GLOB ROPF_CONFIGURATION_FILES ${ROPF_OBFUSCATIONS_CONFIG_DIR}/*.toml)

# ropfuscator libraries

set(ROPFUSCATOR_LIBRARIES)

if(NOT USE_LIBC
   AND NOT USE_LIBROP
   AND NOT ROPFUSCATOR_LIB)
  message(FATAL_ERROR "No library specified!")
endif()

if(USE_LIBC)
  find_library(LIBC NAMES c)

  if(LIBC)
    list(APPEND ROPFUSCATOR_LIBRARIES ${LIBC})
  else()
    message("libc not found.")
  endif()
endif()

if(USE_LIBROP)
  list(APPEND ROPFUSCATOR_LIBRARIES $<TARGET_FILE:rop>)
endif()

if(ROPFUSCATOR_LIB)
  list(APPEND ROPFUSCATOR_LIBRARIES ${ROPFUSCATOR_LIB})
endif()

if(NOT ROPFUSCATOR_LIBRARIES)
  message(
    FATAL_ERROR
      "Could not find the libraries to extract gadgets from. Terminating.")
endif()

if(CMAKE_BUILD_TYPE MATCHES DEBUG)
  set(ROPF_ASM_FLAGS
      ${ROPF_ASM_FLAGS}
      -debug-only=xchg_chains,ropchains,processed_instr,liveness_analysis)
endif()

add_subdirectory("librop")
add_subdirectory("tests" EXCLUDE_FROM_ALL)
