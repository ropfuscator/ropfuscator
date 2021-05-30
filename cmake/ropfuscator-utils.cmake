macro(generate_ropfuscated_asm)
  set(oneValueArgs SOURCE OUTNAME)
  set(multiValueArgs HEADERS IRFLAGS ASMFLAGS)

  cmake_parse_arguments(ARG "${options}" "${oneValueArgs}" "${multiValueArgs}"
                        ${ARGN})

  get_filename_component(filename ${ARG_SOURCE} NAME_WE)

  add_custom_command(
    OUTPUT ${ARG_OUTNAME}.s
    DEPENDS ${ARG_SOURCE}
    COMMAND $<TARGET_FILE:clang> ARGS ${ARG_IRFLAGS} ${ARG_SOURCE}
            ${ARG_HEADERS} -o ${ARG_OUTNAME}.bc
    COMMAND $<TARGET_FILE:llc> ARGS ${ARG_ASMFLAGS} ${ARG_OUTNAME}.bc -o
            ${ARG_OUTNAME}.s)
endmacro()

macro(generate_clean_asm)
  set(oneValueArgs SOURCE OUTNAME)
  set(multiValueArgs HEADERS IRFLAGS ASMFLAGS)

  cmake_parse_arguments(ARG "${options}" "${oneValueArgs}" "${multiValueArgs}"
                        ${ARGN})

  get_filename_component(filename ${ARG_SOURCE} NAME_WE)

  add_custom_command(
    OUTPUT ${ARG_OUTNAME}.s
    DEPENDS ${ARG_SOURCE}
    COMMAND $<TARGET_FILE:clang> ARGS ${ARG_IRFLAGS} ${ARG_SOURCE}
            ${ARG_HEADERS} -o ${ARG_OUTNAME}.bc
    COMMAND $<TARGET_FILE:llc> ARGS -fno-ropfuscator ${ARG_ASMFLAGS}
            ${ARG_OUTNAME}.bc -o ${ARG_OUTNAME}.s)
endmacro()
