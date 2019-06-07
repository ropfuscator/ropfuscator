add_custom_target(ropfuscator-binutils)

file(GLOB files "${CMAKE_CURRENT_SOURCE_DIR}/*.bc")

set(ROPF_ASM_FLAGS_ROPFBIN ${ROPF_ASM_FLAGS})
set(ROPF_IR_FLAGS_ROPFBIN ${ROPF_IR_FLAGS})

if (ROPF_OPAQUEP)
    set(ROPF_ASM_FLAGS_ROPFBIN ${ROPF_ASM_FLAGS_ROPFBIN} -fopaquepredicates)
endif ()

foreach (filename ${files})
    get_filename_component(exec_name ${filename} NAME_WE)
    set(ropfuscated_exec_name "${exec_name}-ropfuscated")

    add_executable(${ropfuscated_exec_name} ${ropfuscated_exec_name}.s)
    add_dependencies(ropfuscator-binutils ${ropfuscated_exec_name})

    #######################
    # options handling
    #######################
    if (ROPF_PROFILE)
        set(ROPF_IR_FLAGS_ROPFBIN ${ROPF_IR_FLAGS} ${COMPILER_PROFILING_FLAGS} -fprofile-instr-generate=${ropfuscated_exec_name}.profdata)
        target_link_options(${ropfuscated_exec_name} PRIVATE ${LINKER_PROFILING_FLAGS})
    endif ()

    if (ROPF_LIBNAIVE)
        target_link_libraries(${ropfuscated_exec_name} naive)
    endif ()

    if (ROPF_OPAQUEP)
        target_link_libraries(${ropfuscated_exec_name} opaquepredicate)
    endif ()

    add_custom_command(
            OUTPUT
            ${ropfuscated_exec_name}.s
            DEPENDS
            ${CMAKE_CURRENT_SOURCE_DIR}/${exec_name}.bc llc
            COMMAND
            clang
            ARGS
            ${ROPF_IR_FLAGS_ROPFBIN} ${CMAKE_CURRENT_SOURCE_DIR}/${exec_name}.bc -o ${ropfuscated_exec_name}.o
            COMMAND
            $<TARGET_FILE:llc>
            ARGS
            ${ROPF_ASM_FLAGS_ROPFBIN} ${ropfuscated_exec_name}.ll -o ${ropfuscated_exec_name}.s
    )
endforeach ()
