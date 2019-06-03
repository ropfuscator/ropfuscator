set(CMAKE_BUILD_TYPE Debug)

# compilers
set(CMAKE_C_COMPILER clang)
set(CMAKE_CXX_COMPILER clang++)

# llvm flags
set(LLVM_TARGETS_TO_BUILD X86)
set(BUILD_SHARED_LIBS ON)