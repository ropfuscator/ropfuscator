cmake_minimum_required(VERSION 3.0)
project(ropfuscator-extra ASM)

set(CMAKE_C_FLAGS "-m32 -fpie")
set(CMAKE_ASM_FLAGS "-m32 -fpie -masm=intel")
set(CMAKE_EXE_LINKER_FLAGS "-m32 -pie")
set(COMPILER_PROFILING_FLAGS -fcoverage-mapping)
set(LINKER_PROFILING_FLAGS -fprofile-instr-generate)
set(ROPF_IR_FLAGS -O0 -m32 -c -emit-llvm) # -fno-omit-frame-pointer
                                          # -mno-omit-leaf-frame-pointer
set(ROPF_ASM_FLAGS -march=x86) # --disable-fp-elim --use-custom-lib
                               # /path/to/your/libc.so

if(CMAKE_BUILD_TYPE MATCHES DEBUG)
  set(ROPF_ASM_FLAGS
      ${ROPF_ASM_FLAGS}
      -debug-only=xchg_chains,ropchains,processed_instr,liveness_analysis)
endif()

option(ROPF_PROFILE "Enable profiling in ropfuscated program." OFF)

add_subdirectory("librop")
add_subdirectory("binutils" EXCLUDE_FROM_ALL)
add_subdirectory("evaluation" EXCLUDE_FROM_ALL)
add_subdirectory("examples" EXCLUDE_FROM_ALL)
add_subdirectory("testcase" EXCLUDE_FROM_ALL)
