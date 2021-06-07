add_custom_target(ropfuscator-examples)

file(GLOB files "${CMAKE_CURRENT_SOURCE_DIR}/*.c")

foreach(filename ${files})
  get_filename_component(exec_name ${filename} NAME_WE)

  # ############################################################################
  # standard binaries
  # ############################################################################

  add_executable(${exec_name} ${exec_name}.s)
  add_dependencies(ropfuscator-examples ${exec_name})

  generate_clean_asm(SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/${exec_name}.c OUTNAME
                     ${exec_name})

  # ############################################################################
  # ROPfuscated binaries
  # ############################################################################

  foreach(config ${ROPF_CONFIGURATION_FILES})
    get_filename_component(config_name ${config} NAME_WE)
    set(ropfuscated_exec_name "${exec_name}-ropfuscated-${config_name}")

    add_executable(${ropfuscated_exec_name} ${ropfuscated_exec_name}.s)
    add_dependencies(ropfuscator-examples ${ropfuscated_exec_name})

    # ##########################################################################
    # options handling
    # ##########################################################################

    if(ROPF_PROFILE)
      target_link_options(${exec_name} PRIVATE ${LINKER_PROFILING_FLAGS})
      target_link_options(${ropfuscated_exec_name} PRIVATE
                          ${LINKER_PROFILING_FLAGS})
    endif()

    if(NOT USE_LIBC)
      target_link_libraries(${ropfuscated_exec_name} rop)
    endif()

    generate_ropfuscated_asm(
      SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/${exec_name}.c OUTNAME
      ${ropfuscated_exec_name} OBF_CONFIG ${config})
  endforeach()
endforeach()
