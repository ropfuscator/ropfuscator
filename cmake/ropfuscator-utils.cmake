macro(generate_ropfuscated_asm source_file out_name ir_flags asm_flags)
  get_filename_component(filename ${source_file} NAME_WE)

  add_custom_command(
    OUTPUT ${out_name}.s
    DEPENDS ${input_source}
    COMMAND $<TARGET_FILE:clang> ARGS ${ir_flags} ${source_file} -o
            ${out_name}.bc
    COMMAND $<TARGET_FILE:llc> ARGS ${asm_flags} ${out_name}.bc -o
            ${out_name}.s)
endmacro()

macro(generate_clean_asm source_file out_name ir_flags asm_flags)
  get_filename_component(filename ${source_file} NAME_WE)

  add_custom_command(
    OUTPUT ${out_name}.s
    DEPENDS ${input_source}
    COMMAND $<TARGET_FILE:clang> ARGS ${ir_flags} ${source_file} -o
            ${out_name}.bc
    COMMAND $<TARGET_FILE:llc> ARGS -fno-ropfuscator ${asm_flags}
            ${out_name}.bc -o ${out_name}.s)
endmacro()
