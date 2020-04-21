set(CMAKE_CXX_STANDARD 17)

set(ROPFUSCATOR_SOURCES
  X86ROPfuscator.cpp
  Ropfuscator/ROPfuscatorCore.cpp
  Ropfuscator/ROPEngine.cpp
  Ropfuscator/BinAutopsy.cpp
  Ropfuscator/XchgGraph.cpp
  Ropfuscator/LivenessAnalysis.cpp
  Ropfuscator/OpaqueConstruct.cpp
  Ropfuscator/Debug.cpp
  Ropfuscator/ROPfuscatorConfig.cpp
  )

set(sources ${sources} ${ROPFUSCATOR_SOURCES})

add_llvm_target(X86CodeGen ${sources})

if (CURRENT_LLVM_TARGET)
  target_link_libraries(${CURRENT_LLVM_TARGET} LINK_PRIVATE LLVMObject)
  target_link_libraries(${CURRENT_LLVM_TARGET} LINK_PRIVATE LLVMX86Disassembler)
endif ()

# libfmt
include_directories(ropfuscator-extra/include/fmt/include)
# tinytoml
include_directories(ropfuscator-extra/include/tinytoml/include)

add_subdirectory(ropfuscator-extra)
