add_custom_target(ropfuscator-tigress-samples)

file(GLOB vanilla "${CMAKE_CURRENT_SOURCE_DIR}/vanilla-*.c")

foreach(filename ${vanilla})
  get_filename_component(sample ${filename} NAME_WE)

  add_executable(${sample} ${filename})
  add_dependencies(ropfuscator-tigress-samples ${sample})
endforeach()
