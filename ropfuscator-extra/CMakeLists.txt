cmake_minimum_required (VERSION 3.13)

set(CMAKE_C_COMPILER clang)
set(CMAKE_CXX_COMPILER clang)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

project (ropfuscator-binutils C ASM)

if(NOT CMAKE_BUILD_TYPE)
    set(default_build_type "Debug")
endif(NOT CMAKE_BUILD_TYPE)

find_path(ROPF_LLC_DIR llc 
    NO_DEFAULT_PATH 
    PATHS ${PROJECT_SOURCE_DIR}/../../../../
    PATH_SUFFIXES bin build build/bin)

if (NOT ROPF_LLC_DIR)
    message(FATAL_ERROR "Could not find ropfuscator's llc.")
endif()

set(ROPF_LLC ${ROPF_LLC_DIR}/llc)

option(ROPF_PROFILE "Enable profiling in ropfuscated program." OFF)
option(ROPF_LIBNAIVE_ENABLE "Link ropfuscated binary with libnaive" OFF)

message("Using ropfuscator llc found at ${ROPF_LLC}")

add_subdirectory("binutils" EXCLUDE_FROM_ALL)
add_subdirectory("examples")
add_subdirectory("lib")