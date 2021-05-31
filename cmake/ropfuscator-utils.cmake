macro(generate_ropfuscated_asm)
  set(oneValueArgs SOURCE OUTNAME)
  set(multiValueArgs IRFLAGS ASMFLAGS)

  cmake_parse_arguments(ARG "${options}" "${oneValueArgs}" "${multiValueArgs}"
                        ${ARGN})

  if(ROPF_PROFILE)
    set(ROPF_IR_FLAGS ${ROPF_IR_FLAGS} ${COMPILER_PROFILING_FLAGS}
                      -fprofile-instr-generate=${ARG_OUTNAME}.profdata)
  endif()

  get_filename_component(filename ${ARG_SOURCE} NAME_WE)

  # constructing the includes directives
  get_directory_property(CURRENT_DIR_INCLUDES DIRECTORY . INCLUDE_DIRECTORIES)
  foreach(dir ${CURRENT_DIR_INCLUDES})
    string(APPEND INCLUDES_DIRECTIVE "-I${dir} ")
  endforeach()

  add_custom_command(
    OUTPUT ${ARG_OUTNAME}.s
    DEPENDS ${ARG_SOURCE}
    COMMAND $<TARGET_FILE:clang> ARGS ${INCLUDES_DIRECTIVE} ${ROPF_IR_FLAGS}
            ${ARG_IRFLAGS} ${ARG_SOURCE} -o ${ARG_OUTNAME}.bc
    COMMAND $<TARGET_FILE:llc> ARGS ${ROPF_ASM_FLAGS} ${ARG_ASMFLAGS}
            ${ARG_OUTNAME}.bc -o ${ARG_OUTNAME}.s)
endmacro()

macro(generate_clean_asm)
  set(oneValueArgs SOURCE OUTNAME)
  set(multiValueArgs IRFLAGS ASMFLAGS)

  cmake_parse_arguments(ARG "${options}" "${oneValueArgs}" "${multiValueArgs}"
                        ${ARGN})

  if(ROPF_PROFILE)
    set(ROPF_IR_FLAGS ${ROPF_IR_FLAGS} ${COMPILER_PROFILING_FLAGS}
                      -fprofile-instr-generate=${ARG_OUTNAME}.profdata)
  endif()

  get_filename_component(filename ${ARG_SOURCE} NAME_WE)

  # constructing the includes directives
  get_directory_property(CURRENT_DIR_INCLUDES DIRECTORY . INCLUDE_DIRECTORIES)
  foreach(dir ${CURRENT_DIR_INCLUDES})
    string(APPEND INCLUDES_DIRECTIVE "-I${dir} ")
  endforeach()

  add_custom_command(
    OUTPUT ${ARG_OUTNAME}.s
    DEPENDS ${ARG_SOURCE}
    COMMAND $<TARGET_FILE:clang> ARGS ${INCLUDES_DIRECTIVE} ${ROPF_IR_FLAGS}
            ${ARG_IRFLAGS} ${ARG_SOURCE} -o ${ARG_OUTNAME}.bc
    COMMAND $<TARGET_FILE:llc> ARGS -fno-ropfuscator ${ROPF_ASM_FLAGS}
            ${ARG_ASMFLAGS} ${ARG_OUTNAME}.bc -o ${ARG_OUTNAME}.s)
endmacro()
