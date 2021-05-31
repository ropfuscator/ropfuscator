macro(generate_ropfuscated_asm)
  #
  # macro argument parsing
  #

  set(oneValueArgs SOURCE OUTNAME OBF_CONFIG)
  set(multiValueArgs IRFLAGS ASMFLAGS)

  cmake_parse_arguments(ARG "${options}" "${oneValueArgs}" "${multiValueArgs}"
                        ${ARGN})

  #
  # getting includes directories set for current directory
  #

  get_directory_property(CURRENT_DIR_INCLUDES DIRECTORY . INCLUDE_DIRECTORIES)

  foreach(dir ${CURRENT_DIR_INCLUDES})
    string(APPEND INCLUDES_DIRECTIVE "-I${dir} ")
  endforeach()

  #
  # macro variables
  #

  set(CLANG_FLAGS ${ROPF_IR_FLAGS} ${INCLUDES_DIRECTIVE} ${ARG_IRFLAGS}
                  ${ARG_SOURCE})
  set(LLC_FLAGS ${ROPF_ASM_FLAGS} ${ARG_ASMFLAGS} ${ARG_OUTNAME}.bc)
  set(DEPENDENCIES ${ARG_SOURCE})

  #
  # options handling
  #

  if(ROPF_PROFILE)
    list(APPEND CLANG_FLAGS ${COMPILER_PROFILING_FLAGS}
         -fprofile-instr-generate=${ARG_OUTNAME}.profdata)
  endif()

  if(ARG_OBF_CONFIG)
    list(APPEND LLC_FLAGS -ropfuscator-config=${configfile})
    list(APPEND DEPENDENCIES ${ARG_OBF_CONFIG})
  endif()

  add_custom_command(
    OUTPUT ${ARG_OUTNAME}.s
    DEPENDS ${DEPENDENCIES}
    COMMAND $<TARGET_FILE:clang> ARGS ${CLANG_FLAGS} -o ${ARG_OUTNAME}.bc
    COMMAND $<TARGET_FILE:llc> ARGS ${LLC_FLAGS} -o ${ARG_OUTNAME}.s)
endmacro()

macro(generate_clean_asm)
  #
  # macro argument parsing
  #

  set(oneValueArgs SOURCE OUTNAME)
  set(multiValueArgs IRFLAGS ASMFLAGS)

  cmake_parse_arguments(ARG "${options}" "${oneValueArgs}" "${multiValueArgs}"
                        ${ARGN})

  # add no-ropfuscator flag to user defined flags
  list(APPEND ARG_ASMFLAGS -fno-ropfuscator)

  generate_ropfuscated_asm(
    SOURCE
    ${ARG_SOURCE}
    OUTNAME
    ${ARG_OUTNAME}
    ASMFLAGS
    ${ARG_ASMFLAGS}
    IRFLAGS
    ${ARG_IRFLAGS})
endmacro()
