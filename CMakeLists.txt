cmake_minimum_required (VERSION 2.5)
set(CMAKE_C_COMPILER clang)
set(CMAKE_CXX_COMPILER clang)

project (ropfuscator C ASM)

if(NOT CMAKE_BUILD_TYPE)
    set(default_build_type "Debug")
endif(NOT CMAKE_BUILD_TYPE)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/bin)

add_subdirectory("examples")
add_subdirectory("lib")