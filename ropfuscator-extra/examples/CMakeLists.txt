cmake_minimum_required (VERSION 3.13)
set(CMAKE_C_COMPILER clang)
set(CMAKE_CXX_COMPILER clang)
project (ropfuscator-examples C ASM)

find_path(ROPF_LLC_DIR llc 
    NO_DEFAULT_PATH 
    PATHS ${PROJECT_SOURCE_DIR}/../../../../../
    PATH_SUFFIXES bin build build/bin
)
set(ROPF_LLC ${ROPF_LLC_DIR}/llc)

if (NOT ROPF_LLC)
    message(FATAL_ERROR "Could not find ropfuscator's llc.")
endif()

if(NOT CMAKE_BUILD_TYPE)
    set(default_build_type "Debug")
endif(NOT CMAKE_BUILD_TYPE)

message("Using ropfuscator llc found at ${ROPF_LLC}")

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

add_subdirectory("lib")
add_subdirectory("src")
