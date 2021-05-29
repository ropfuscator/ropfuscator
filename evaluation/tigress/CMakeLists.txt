add_custom_target(ropfuscator-tigress-samples)

file(GLOB vanilla "${CMAKE_CURRENT_SOURCE_DIR}/vanilla-*.c")

set(ROPF_ASM_FLAGS_STDBIN ${ROPF_ASM_FLAGS} -fno-ropfuscator)
set(ROPF_IR_FLAGS_STDBIN ${ROPF_IR_FLAGS})

set(ROPF_ASM_FLAGS_ROPFBIN ${ROPF_ASM_FLAGS})
set(ROPF_IR_FLAGS_ROPFBIN ${ROPF_IR_FLAGS})

foreach(filename ${vanilla})
  get_filename_component(sample ${filename} NAME_WE)
  set(ropfuscated_sample "${sample}-ropfuscated")

  add_executable(${sample} ${sample}.s)
  add_executable(${ropfuscated_sample} ${ropfuscated_sample}.s)
  add_dependencies(ropfuscator-tigress-samples ${sample} ${ropfuscated_sample})

  # ############################################################################
  # options handling
  # ############################################################################

  if(ROPF_PROFILE)
    # standard binaries
    set(ROPF_IR_FLAGS_STDBIN ${ROPF_IR_FLAGS} ${COMPILER_PROFILING_FLAGS}
                             -fprofile-instr-generate=${sample}.profdata)
    target_link_options(${sample} PRIVATE ${LINKER_PROFILING_FLAGS})

    # ropfuscated binaries
    set(ROPF_IR_FLAGS_ROPFBIN
        ${ROPF_IR_FLAGS} ${COMPILER_PROFILING_FLAGS}
        -fprofile-instr-generate=${ropfuscated_sample}.profdata)
    target_link_options(${ropfuscated_sample} PRIVATE ${LINKER_PROFILING_FLAGS})
  endif()

  # ############################################################################
  # standard binaries
  # ############################################################################

  add_custom_command(
    OUTPUT ${sample}.s
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/${sample}.c
    COMMAND $<TARGET_FILE:clang> ARGS ${ROPF_IR_FLAGS_STDBIN}
            ${CMAKE_CURRENT_SOURCE_DIR}/${sample}.c -o ${sample}.bc
    COMMAND $<TARGET_FILE:llc> ARGS ${ROPF_ASM_FLAGS_STDBIN} ${sample}.bc -o
            ${sample}.s)

  # ############################################################################
  # ROPfuscated binaries
  # ############################################################################

  if(USE_LIBC)
    target_link_libraries(${ropfuscated_sample} c)
  else()
    target_link_libraries(${ropfuscated_sample} rop)
  endif()

  add_custom_command(
    OUTPUT ${ropfuscated_sample}.s
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/${sample}.c
    COMMAND $<TARGET_FILE:clang> ARGS ${ROPF_IR_FLAGS_ROPFBIN}
            ${CMAKE_CURRENT_SOURCE_DIR}/${sample}.c -o ${ropfuscated_sample}.bc
    COMMAND $<TARGET_FILE:llc> ARGS ${ROPF_ASM_FLAGS_ROPFBIN}
            ${ropfuscated_sample}.bc -o ${ropfuscated_sample}.s)
endforeach()
