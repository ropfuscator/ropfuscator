cmake_minimum_required(VERSION 3.0)
project(ropfuscator-extra CXX C)

if(CMAKE_BUILD_TYPE MATCHES DEBUG)
  set(ROPF_ASM_FLAGS
    ${ROPF_ASM_FLAGS}
    -debug-only=xchg_chains,ropchains,processed_instr,liveness_analysis)
endif()
