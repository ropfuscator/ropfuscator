set(CMAKE_CXX_STANDARD 17)

set(ROPF_DIR ropfuscator)
set(ROPF_SRCDIR ${ROPF_DIR}/src)

set(ROPF_SOURCES
  ${ROPF_SRCDIR}/BinAutopsy.cpp
  ${ROPF_SRCDIR}/Debug.cpp
  ${ROPF_SRCDIR}/InstrStegano.cpp
  ${ROPF_SRCDIR}/LivenessAnalysis.cpp
  ${ROPF_SRCDIR}/MathUtil.cpp
  ${ROPF_SRCDIR}/OpaqueConstruct.cpp
  ${ROPF_SRCDIR}/ROPEngine.cpp
  ${ROPF_SRCDIR}/ROPfuscatorConfig.cpp
  ${ROPF_SRCDIR}/ROPfuscatorCore.cpp
  ${ROPF_SRCDIR}/X86ROPfuscatorPass.cpp
  ${ROPF_SRCDIR}/XchgGraph.cpp
  )

set(sources ${sources} ${ROPF_SOURCES})

add_llvm_target(X86CodeGen ${sources})

if (CURRENT_LLVM_TARGET)
  target_link_libraries(${CURRENT_LLVM_TARGET} LINK_PRIVATE LLVMObject)
  target_link_libraries(${CURRENT_LLVM_TARGET} LINK_PRIVATE LLVMX86Disassembler)
endif ()

# libfmt
include_directories(${ROPF_DIR}/thirdparty/fmt/include)
# tinytoml
include_directories(${ROPF_DIR}/thirdparty/tinytoml/include)

add_subdirectory(${ROPF_DIR})

# librop
add_subdirectory(${ROPF_DIR}/librop)