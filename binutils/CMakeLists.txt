add_custom_target(ropfuscator-binutils)

file(GLOB files "${CMAKE_CURRENT_SOURCE_DIR}/*.bc")

set(ROPF_ASM_FLAGS_ROPFBIN ${ROPF_ASM_FLAGS})
set(ROPF_IR_FLAGS_ROPFBIN ${ROPF_IR_FLAGS})

foreach (filename ${files})
    get_filename_component(exec_name ${filename} NAME_WE)
    set(ropfuscated_exec_name "${exec_name}-ropfuscated")

    add_executable(${ropfuscated_exec_name} ${ropfuscated_exec_name}.s)
    add_executable(${exec_name} ${exec_name}.s)
    add_dependencies(ropfuscator-binutils ${ropfuscated_exec_name})

    target_link_libraries(${exec_name} dl)
    target_link_libraries(${ropfuscated_exec_name} dl)

    #######################
    # options handling
    #######################
    if (ROPF_PROFILE)
        set(ROPF_IR_FLAGS_ROPFBIN ${ROPF_IR_FLAGS} ${COMPILER_PROFILING_FLAGS} -fprofile-instr-generate=${ropfuscated_exec_name}.profdata)
        target_link_options(${ropfuscated_exec_name} PRIVATE ${LINKER_PROFILING_FLAGS})
    endif ()

    add_custom_command(
            OUTPUT
            ${ropfuscated_exec_name}.s
            DEPENDS
            ${CMAKE_CURRENT_SOURCE_DIR}/${exec_name}.bc llc
            COMMAND
            $<TARGET_FILE:llc>
            ARGS
            ${ROPF_ASM_FLAGS_ROPFBIN} ${CMAKE_CURRENT_SOURCE_DIR}/${exec_name}.bc -o ${ropfuscated_exec_name}.s
    )

    add_custom_command(
            OUTPUT
            ${exec_name}.s
            DEPENDS
            ${CMAKE_CURRENT_SOURCE_DIR}/${exec_name}.bc llc
            COMMAND
            $<TARGET_FILE:llc>
            ARGS
            -fno-ropfuscator ${CMAKE_CURRENT_SOURCE_DIR}/${exec_name}.bc -o ${exec_name}.s
    )

    add_custom_target(
            ${ropfuscated_exec_name}-instrstat
            DEPENDS
            ${CMAKE_CURRENT_SOURCE_DIR}/${exec_name}.bc llc
            COMMAND
            $<TARGET_FILE:llc>
            ${ROPF_ASM_FLAGS_ROPFBIN} ${CMAKE_CURRENT_SOURCE_DIR}/${exec_name}.bc -o ${ropfuscated_exec_name}-instrstat.s -ropfuscator-config ${CMAKE_CURRENT_SOURCE_DIR}/../evaluation/instrstat.conf
    )
endforeach ()
