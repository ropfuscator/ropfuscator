add_custom_target(ropfuscator-tigress-samples)

file(GLOB vanilla "${CMAKE_CURRENT_SOURCE_DIR}/vanilla-*.c")

foreach(filename ${vanilla})
  get_filename_component(sample ${filename} NAME_WE)
  set(ropfuscated_sample "${sample}-ropfuscated")

  add_executable(${sample} ${sample}.s)
  add_dependencies(ropfuscator-tigress-samples ${sample})

  generate_clean_asm(SOURCE ${filename} OUTNAME ${sample})

  foreach(library ${ROPFUSCATOR_LIBRARIES})
    get_filename_component(libname ${library} NAME_WE)

    # ugly but needed because the generator expressions are not expanded at
    # this stage
    if(library STREQUAL $<TARGET_FILE:rop>)
      set(libname "librop")
    endif()

    set(final_name "${ropfuscated_sample}-${libname}")

    add_executable(${final_name} ${final_name}.s)
    add_dependencies(ropfuscator-tigress-samples ${final_name})

    target_link_libraries(${final_name} ${library})

    generate_ropfuscated_asm(SOURCE ${filename} OUTNAME ${final_name}
                             GADGET_LIB ${library})
  endforeach()

endforeach()
