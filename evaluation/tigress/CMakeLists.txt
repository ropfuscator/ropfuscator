add_custom_target(ropfuscator-tigress-samples)

file(GLOB vanilla "${CMAKE_CURRENT_SOURCE_DIR}/vanilla-*.c")

foreach(filename ${vanilla})
  get_filename_component(sample ${filename} NAME_WE)
  set(ropfuscated_sample "${sample}-ropfuscated")

  add_executable(${sample} ${sample}.s)
  add_executable(${ropfuscated_sample} ${ropfuscated_sample}.s)
  add_dependencies(ropfuscator-tigress-samples ${sample} ${ropfuscated_sample})

  if(NOT USE_LIBC)
    target_link_libraries(${ropfuscated_sample} rop)
  endif()

  generate_clean_asm(SOURCE ${filename} OUTNAME ${sample})
  generate_ropfuscated_asm(SOURCE ${filename} OUTNAME ${ropfuscated_sample})
endforeach()
