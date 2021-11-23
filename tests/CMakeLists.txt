project(ROPfuscator-tests C ASM)
cmake_minimum_required(VERSION 3.0)

include(utils/cmake/ropfuscator-utils.cmake)

if(NOT ROPFUSCATOR_CONFIGS_DIR)
  message(FATAL_ERROR "ROPfuscator's config files directory not specified. Please set ROPFUSCATOR_CONFIGS_DIR accordingly.")
endif()

enable_testing()

file(GLOB sources "${CMAKE_CURRENT_SOURCE_DIR}/src/*.c")
file(GLOB ROPF_CONFIGURATION_FILES "${ROPFUSCATOR_CONFIGS_DIR}/*.toml")

message("${ROPFUSCATOR_CONFIGS_DIR}")
message("${ROPF_CONFIGURATION_FILES}")
# making CMake aware of the targets so we can configure them later
foreach(source ${sources})
  get_filename_component(testcase ${source} NAME_WE)

  # vanilla testcase
  add_executable(${testcase} ${source})
  target_compile_options(${testcase} PRIVATE -mllvm -fno-ropfuscator)

  # obfuscated testcase
  foreach(config ${ROPF_CONFIGURATION_FILES})
    foreach(library ${ROPFUSCATOR_LIBRARIES})
      get_filename_component(config_name ${config} NAME_WE)
      get_filename_component(libname ${library} NAME_WE)

      set(obfuscated_testcase
          "${testcase}-ropfuscated-${config_name}-${libname}")

        add_obfuscated_executable(TARGET ${obfuscated_testcase} SOURCES ${source} CONFIG ${config} LIBRARY ${library})
    endforeach()
  endforeach()
endforeach()

# ====================
# add target specific compile flags here
# ====================
target_compile_options(testcase001 PUBLIC -O2)
target_compile_options(testcase002 PUBLIC -O0)
target_compile_options(testcase003 PUBLIC -O2)
target_compile_options(testcase004 PUBLIC -O0)
target_compile_options(testcase008 PUBLIC -O0)
target_compile_options(testcase009 PUBLIC -O0)
target_compile_options(testcase010 PUBLIC -O0)
target_compile_options(testcase011 PUBLIC -O0)
# ====================

foreach(source ${sources})
  get_filename_component(testcase ${source} NAME_WE)
  get_target_property(TARGET_CFLAGS ${testcase} COMPILE_OPTIONS)
  
  add_test(NAME test-${testcase}-plain-build
           COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target
                   ${testcase})
  add_test(NAME test-${testcase}-plain-exec COMMAND $<TARGET_FILE:${testcase}>)

  # obfuscated testcases (per config)
  foreach(config ${ROPF_CONFIGURATION_FILES})
    foreach(library ${ROPFUSCATOR_LIBRARIES})
      get_filename_component(config_name ${config} NAME_WE)
      get_filename_component(libname ${library} NAME_WE)

      set(obfuscated_testcase
            "${testcase}-ropfuscated-${config_name}-${libname}")

      add_test(NAME test-${obfuscated_testcase}-build
               COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target
                       ${obfuscated_testcase})

      add_test(NAME test-${obfuscated_testcase}-exec
               COMMAND $<TARGET_FILE:${obfuscated_testcase}>)

      add_test(
        NAME test-${obfuscated_testcase}-result-compare
        COMMAND
          ${CMAKE_COMMAND} -DPLAIN_BIN=${testcase}
          -DROPF_BIN=${obfuscated_testcase} -P
          ${CMAKE_CURRENT_SOURCE_DIR}/run-and-compare-results.cmake)

      set_tests_properties(
        test-${testcase}-plain-exec test-${obfuscated_testcase}-result-compare
        PROPERTIES DEPENDS test-${testcase}-plain-build)

      set_tests_properties(
        test-${obfuscated_testcase}-exec
        test-${obfuscated_testcase}-result-compare
        PROPERTIES DEPENDS test-${obfuscated_testcase}-build)
    endforeach()
  endforeach()
endforeach()
