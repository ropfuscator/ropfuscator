add_custom_target(ropfuscator-examples)

file(GLOB files "${CMAKE_CURRENT_SOURCE_DIR}/*.c")

set(ROPF_ASM_FLAGS_STDBIN ${ROPF_ASM_FLAGS})
set(ROPF_IR_FLAGS_STDBIN ${ROPF_IR_FLAGS})

set(ROPF_ASM_FLAGS_ROPFBIN ${ROPF_ASM_FLAGS})
set(ROPF_IR_FLAGS_ROPFBIN ${ROPF_IR_FLAGS})

foreach(filename ${files})
  get_filename_component(exec_name ${filename} NAME_WE)
  set(ropfuscated_exec_name "${exec_name}-ropfuscated")

  add_executable(${exec_name} ${exec_name}.s)
  add_executable(${ropfuscated_exec_name} ${ropfuscated_exec_name}.s)

  # ############################################################################
  # options handling
  # ############################################################################

  if(ROPF_PROFILE)
    # standard binaries
    set(ROPF_IR_FLAGS_STDBIN ${ROPF_IR_FLAGS} ${COMPILER_PROFILING_FLAGS}
                             -fprofile-instr-generate=${exec_name}.profdata)
    target_link_options(${exec_name} PRIVATE ${LINKER_PROFILING_FLAGS})

    # ropfuscated binaries
    set(ROPF_IR_FLAGS_ROPFBIN
        ${ROPF_IR_FLAGS} ${COMPILER_PROFILING_FLAGS}
        -fprofile-instr-generate=${ropfuscated_exec_name}.profdata)
    target_link_options(${ropfuscated_exec_name} PRIVATE
                        ${LINKER_PROFILING_FLAGS})
  endif()

  # ############################################################################
  # standard binaries
  # ############################################################################

  add_dependencies(ropfuscator-examples ${exec_name})

  generate_clean_asm(
    SOURCE
    ${CMAKE_CURRENT_SOURCE_DIR}/${exec_name}.c
    OUTNAME
    ${exec_name}
    IRFLAGS
    ${ROPF_IR_FLAGS_STDBIN}
    ASMFLAGS
    ${ROPF_ASM_FLAGS_STDBIN})

  # ############################################################################
  # ROPfuscated binaries
  # ############################################################################

  add_dependencies(ropfuscator-examples ${ropfuscated_exec_name})

  if(USE_LIBC)
    target_link_libraries(${ropfuscated_exec_name} c)
  else()
    target_link_libraries(${ropfuscated_exec_name} rop)
  endif()

  generate_ropfuscated_asm(
    SOURCE
    ${CMAKE_CURRENT_SOURCE_DIR}/${exec_name}.c
    OUTNAME
    ${ropfuscated_exec_name}
    IRFLAGS
    ${ROPF_IR_FLAGS_ROPFBIN}
    ASMFLAGS
    ${ROPF_ASM_FLAGS_ROPFBIN})

  # generate_ropfuscated_asm( ${CMAKE_CURRENT_SOURCE_DIR}/${exec_name}.c
  # ${ropfuscated_exec_name}
  # "${ROPF_IR_FLAGS_ROPFBIN}" "${ROPF_ASM_FLAGS_ROPFBIN}")
endforeach()
