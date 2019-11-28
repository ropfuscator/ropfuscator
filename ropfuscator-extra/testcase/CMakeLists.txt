cmake_minimum_required(VERSION 3.0)

enable_testing()

# ====================
# add test here
# ====================
set(testcases
    testcase001
    testcase002
    testcase003
    testcase-example1
    testcase-example2
    testcase-example3
    testcase-example4
)
# ====================

foreach(testcase ${testcases})
    add_executable(${testcase}-ropfuscated ${testcase}-ropfuscated.s)
    add_executable(${testcase} ${testcase}.s)
endforeach()

# ====================
# add target specific compile flags here
# ====================
target_compile_options(testcase001       PUBLIC -O2)
target_compile_options(testcase002       PUBLIC -O0)
target_compile_options(testcase003       PUBLIC -O2)
target_compile_options(testcase-example1 PUBLIC -O0)
target_compile_options(testcase-example2 PUBLIC -O0)
target_compile_options(testcase-example3 PUBLIC -O0)
target_compile_options(testcase-example4 PUBLIC -O0)
# ====================

set(ROPF_ASM_FLAGS_STDBIN ${ROPF_ASM_FLAGS} -fno-ropfuscator)
set(ROPF_ASM_FLAGS_ROPFBIN ${ROPF_ASM_FLAGS})

foreach(testcase ${testcases})
    set(exec_name ${testcase})
    set(ropfuscated_exec_name "${exec_name}-ropfuscated")
    get_target_property(target_cflags ${exec_name} COMPILE_OPTIONS)

    # build commands
    add_custom_command(
        OUTPUT  ${exec_name}.bc
        DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/src/${exec_name}.c clang
        COMMAND $<TARGET_FILE:clang>  ARGS ${ROPF_IR_FLAGS} ${CMAKE_CURRENT_SOURCE_DIR}/src/${exec_name}.c ${target_cflags} -o ${exec_name}.bc
    )
    add_custom_command(
        OUTPUT  ${exec_name}.s
        DEPENDS ${exec_name}.bc llc
        COMMAND $<TARGET_FILE:llc>    ARGS ${ROPF_ASM_FLAGS_STDBIN} ${exec_name}.bc -o ${exec_name}.s
    )
    add_custom_command(
        OUTPUT  ${ropfuscated_exec_name}.s
        DEPENDS ${exec_name}.bc llc
        COMMAND $<TARGET_FILE:llc>    ARGS ${ROPF_ASM_FLAGS_ROPFBIN} ${exec_name}.bc -o ${ropfuscated_exec_name}.s
    )

    # tests
    add_test(
        NAME    test-${exec_name}-plain-build
        COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target ${exec_name}
    )
    add_test(
        NAME    test-${exec_name}-ropfuscated-build
        COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target ${ropfuscated_exec_name}
    )
    add_test(
        NAME    test-${exec_name}-plain-exec
        COMMAND $<TARGET_FILE:${exec_name}>
    )
    add_test(
        NAME    test-${exec_name}-ropfuscated-exec
        COMMAND $<TARGET_FILE:${ropfuscated_exec_name}>
    )
    add_test(
        NAME    test-${exec_name}-ropfuscated-result-compare
        COMMAND ${CMAKE_COMMAND} -DPLAIN_BIN=${exec_name} -DROPF_BIN=${ropfuscated_exec_name} -P ${CMAKE_CURRENT_SOURCE_DIR}/run-and-compare-results.cmake
    )
    set_tests_properties(
        test-${exec_name}-plain-exec
        test-${exec_name}-ropfuscated-result-compare
        PROPERTIES DEPENDS test-${exec_name}-plain-build
    )
    set_tests_properties(
        test-${exec_name}-ropfuscated-exec
        test-${exec_name}-ropfuscated-result-compare
        PROPERTIES DEPENDS test-${exec_name}-ropfuscated-build
    )
endforeach()

