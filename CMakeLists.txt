set(LLVM_TARGET_DEFINITIONS X86.td)

tablegen(LLVM X86GenAsmMatcher.inc -gen-asm-matcher)
tablegen(LLVM X86GenAsmWriter.inc -gen-asm-writer)
tablegen(LLVM X86GenAsmWriter1.inc -gen-asm-writer -asmwriternum=1)
tablegen(LLVM X86GenCallingConv.inc -gen-callingconv)
tablegen(LLVM X86GenDAGISel.inc -gen-dag-isel)
tablegen(LLVM X86GenDisassemblerTables.inc -gen-disassembler)
tablegen(LLVM X86GenEVEX2VEXTables.inc -gen-x86-EVEX2VEX-tables)
tablegen(LLVM X86GenFastISel.inc -gen-fast-isel)
tablegen(LLVM X86GenGlobalISel.inc -gen-global-isel)
tablegen(LLVM X86GenInstrInfo.inc -gen-instr-info)
tablegen(LLVM X86GenRegisterBank.inc -gen-register-bank)
tablegen(LLVM X86GenRegisterInfo.inc -gen-register-info)
tablegen(LLVM X86GenSubtargetInfo.inc -gen-subtarget)

if (X86_GEN_FOLD_TABLES)
    tablegen(LLVM X86GenFoldTables.inc -gen-x86-fold-tables)
endif ()

add_public_tablegen_target(X86CommonTableGen)

set(ROPFUSCATOR_SOURCES
        X86ROPfuscator.cpp
        RopfuscatorBinAutopsy.cpp
        RopfuscatorXchgGraph.cpp
        RopfuscatorCapstoneLLVMAdpt.cpp
        RopfuscatorLivenessAnalysis.cpp
        X86ROPUtils.cpp
        )

set(sources
        ShadowCallStack.cpp
        X86AsmPrinter.cpp
        X86CallFrameOptimization.cpp
        X86CallingConv.cpp
        X86CallLowering.cpp
        X86CmovConversion.cpp
        X86DomainReassignment.cpp
        X86ExpandPseudo.cpp
        X86FastISel.cpp
        X86FixupBWInsts.cpp
        X86FixupLEAs.cpp
        X86AvoidStoreForwardingBlocks.cpp
        X86FixupSetCC.cpp
        X86FlagsCopyLowering.cpp
        X86FloatingPoint.cpp
        X86FrameLowering.cpp
        X86InstructionSelector.cpp
        X86ISelDAGToDAG.cpp
        X86ISelLowering.cpp
        X86IndirectBranchTracking.cpp
        X86InterleavedAccess.cpp
        X86InstrFMA3Info.cpp
        X86InstrFoldTables.cpp
        X86InstrInfo.cpp
        X86EvexToVex.cpp
        X86LegalizerInfo.cpp
        X86MCInstLower.cpp
        X86MachineFunctionInfo.cpp
        X86MacroFusion.cpp
        X86OptimizeLEAs.cpp
        X86PadShortFunction.cpp
        X86RegisterBankInfo.cpp
        X86RegisterInfo.cpp
        X86RetpolineThunks.cpp
        X86SelectionDAGInfo.cpp
        X86ShuffleDecodeConstantPool.cpp
        X86SpeculativeLoadHardening.cpp
        X86Subtarget.cpp
        X86TargetMachine.cpp
        X86TargetObjectFile.cpp
        X86TargetTransformInfo.cpp
        X86VZeroUpper.cpp
        X86WinAllocaExpander.cpp
        X86WinEHState.cpp
        ${ROPFUSCATOR_SOURCES}
        )

add_llvm_target(X86CodeGen ${sources})

add_subdirectory(AsmParser)
add_subdirectory(Disassembler)
add_subdirectory(InstPrinter)
add_subdirectory(MCTargetDesc)
add_subdirectory(TargetInfo)
add_subdirectory(Utils)

# Adding capstone
find_package(capstone QUIET)
find_package(fmt QUIET)
find_library(BFD bfd)

if (NOT capstone_FOUND OR NOT fmt_FOUND)
    find_package(PkgConfig REQUIRED)
    if (PKG_CONFIG_FOUND)
        pkg_search_module(capstone capstone)
        pkg_search_module(fmt fmt)
    endif ()
endif ()

if (NOT capstone_FOUND)
    message(FATAL_ERROR "Unable to find capstone. Please install pkg-config and capstone development files")
endif ()

if (NOT fmt_FOUND)
    message(FATAL_ERROR "Unable to find capstone. Please install pkg-config and fmtlib development files")
endif ()

target_link_libraries(${CURRENT_LLVM_TARGET} LINK_PRIVATE capstone fmt ${BFD})