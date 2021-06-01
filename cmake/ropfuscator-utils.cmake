macro(generate_ropfuscated_asm)
  #
  # macro argument parsing
  #

  set(oneValueArgs SOURCE OUTNAME OBF_CONFIG)
  set(multiValueArgs IRFLAGS ASMFLAGS)

  cmake_parse_arguments(ARG "${options}" "${oneValueArgs}" "${multiValueArgs}"
                        ${ARGN})

  if(NOT ARG_SOURCE)
    message(FATAL_ERROR "Source file not specified!")
  endif()

  if(NOT ARG_OUTNAME)
    message(FATAL_ERROR "Output name not specified!")
  endif()

  #
  # getting includes directories set for current directory
  #

  get_directory_property(CURRENT_DIR_INCLUDES DIRECTORY . INCLUDE_DIRECTORIES)

  # since this is a macro and it's going to be inlined wherever this is going to
  # be called, we might clobber the argument list by recursively add the include
  # directory when the macro is called in a loop. To avoid this, we are setting
  # a temporary "flag" variable to avoid this behaviour.
  if(NOT CURRENT_DIR_INCLUDES_FLAG)
    foreach(dir ${CURRENT_DIR_INCLUDES})
      list(APPEND INCLUDES_DIRECTIVE "-I${dir}")
    endforeach()

    set(CURRENT_DIR_INCLUDES_FLAG True)
  endif()
  
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
  # message("YO")
    list(APPEND CLANG_FLAGS ${COMPILER_PROFILING_FLAGS}
         -fprofile-instr-generate=${ARG_OUTNAME}.profdata)
         message(${CLANG_FLAGS})
  endif()

  if(ARG_OBF_CONFIG)
    list(APPEND LLC_FLAGS -ropfuscator-config=${ARG_OBF_CONFIG})
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

  if(NOT ARG_SOURCE)
    message(FATAL_ERROR "Source file not specified!")
  endif()

  if(NOT ARG_OUTNAME)
    message(FATAL_ERROR "Output name not specified!")
  endif()

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
