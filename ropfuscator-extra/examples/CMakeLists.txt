cmake_minimum_required (VERSION 3.13)
set(CMAKE_C_COMPILER clang)
set(CMAKE_CXX_COMPILER clang)

project (ropfuscator-examples C ASM)

if(NOT CMAKE_BUILD_TYPE)
    set(default_build_type "Debug")
endif(NOT CMAKE_BUILD_TYPE)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

add_subdirectory("lib")
add_subdirectory("src")