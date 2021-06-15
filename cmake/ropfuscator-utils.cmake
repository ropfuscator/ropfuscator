macro(generate_ropfuscated_asm)
  #
  # macro argument parsing
  #

  set(oneValueArgs SOURCE OUTNAME OBF_CONFIG GADGET_LIB)
  set(multiValueArgs IRFLAGS ASMFLAGS)

  cmake_parse_arguments(ARG "${options}" "${oneValueArgs}" "${multiValueArgs}"
                        ${ARGN})

  if(NOT ARG_SOURCE)
    message(FATAL_ERROR "Source file not specified!")
  endif()

  if(NOT ARG_OUTNAME)
    message(FATAL_ERROR "Output name not specified!")
  endif()

  if(NOT ARG_GADGET_LIB)
    message(FATAL_ERROR "Gadget library not specified!")
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
  # getting compile definitions for current directory
  #

  get_property(
    SOURCE_DEFINITIONS
    DIRECTORY .
    PROPERTY COMPILE_DEFINITIONS)

  # since this is a macro and it's going to be inlined wherever this is going to
  # be called, we might clobber the argument list by recursively add the include
  # directory when the macro is called in a loop. To avoid this, we are setting
  # a temporary "flag" variable to avoid this behaviour.
  if(NOT SOURCE_DEFINITIONS_FLAG)
    foreach(def ${SOURCE_DEFINITIONS})
      # escape the quotes!
      list(APPEND ROPF_COMPILE_DEFS "'-D${def}'")
    endforeach()

    set(SOURCE_DEFINITIONS_FLAG True)
  endif()

  #
  # macro variables
  #

  set(CLANG_FLAGS ${ROPF_IR_FLAGS} ${INCLUDES_DIRECTIVE} ${ARG_IRFLAGS}
                  ${ROPF_COMPILE_DEFS} ${ARG_SOURCE})
  set(LLC_FLAGS -ropfuscator-library=${ARG_GADGET_LIB} ${ROPF_ASM_FLAGS}
                ${ARG_ASMFLAGS} ${ARG_OUTNAME}.bc)
  set(DEPENDENCIES clang llc ${ARG_SOURCE})

  #
  # options handling
  #

  if(ROPF_PROFILE)
    list(APPEND CLANG_FLAGS ${COMPILER_PROFILING_FLAGS}
         -fprofile-instr-generate=${ARG_OUTNAME}.profdata)
  endif()

  if(ARG_OBF_CONFIG)
    list(APPEND LLC_FLAGS -ropfuscator-config=${ARG_OBF_CONFIG})
    list(APPEND DEPENDENCIES ${ARG_OBF_CONFIG})
  endif()

  if(ARG_GADGET_LIB STREQUAL $<TARGET_FILE:rop>)
    list(APPEND DEPENDENCIES rop)
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
    ${ARG_IRFLAGS}
    GADGET_LIB
    " ")
endmacro()
