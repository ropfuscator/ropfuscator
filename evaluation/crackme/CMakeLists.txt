add_custom_target(ropfuscator-evaluation-crackme)

file(GLOB files "${CMAKE_CURRENT_SOURCE_DIR}/src_*/*.c")
file(GLOB configfiles "${CMAKE_CURRENT_SOURCE_DIR}/ropf/*.conf")

set(ROPF_ASM_FLAGS_ROPFBIN ${ROPF_ASM_FLAGS})
set(ROPF_IR_FLAGS_ROPFBIN ${ROPF_IR_FLAGS} -O2 -mno-sse)

foreach(filename ${files})
  get_filename_component(src_dir ${filename} DIRECTORY)
  get_filename_component(exec_name ${filename} NAME_WE)

  add_custom_command(
    OUTPUT ${exec_name}.bc
    DEPENDS ${src_dir}/${exec_name}.c clang
    COMMAND ${CMAKE_C_COMPILER} ARGS ${ROPF_IR_FLAGS_ROPFBIN}
            ${src_dir}/${exec_name}.c -o ${exec_name}.bc)

  foreach(configfile ${configfiles})
    get_filename_component(config ${configfile} NAME_WE)
    set(ropfuscated_exec_name "eval.${exec_name}.${config}")

    add_executable(${ropfuscated_exec_name} ${ropfuscated_exec_name}.s)

    if(ROPF_PROFILE)
      target_link_options(${ropfuscated_exec_name} PRIVATE
                          ${LINKER_PROFILING_FLAGS})
    endif()

    add_dependencies(ropfuscator-evaluation-crackme ${ropfuscated_exec_name})

    if(NOT USE_LIBC)
      target_link_libraries(${ropfuscated_exec_name} rop)
    endif()

    add_custom_command(
      OUTPUT ${ropfuscated_exec_name}.s
      DEPENDS ${exec_name}.bc llc ${configfile}
      COMMAND $<TARGET_FILE:llc> ARGS ${ROPF_ASM_FLAGS_ROPFBIN} ${exec_name}.bc
              -o ${ropfuscated_exec_name}.s -ropfuscator-config ${configfile})
  endforeach()
endforeach()
