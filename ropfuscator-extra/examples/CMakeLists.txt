file(GLOB files "${CMAKE_CURRENT_SOURCE_DIR}/*.c")

add_custom_target(ropfuscator-examples)

foreach (filename ${files})
    get_filename_component(exec_name ${filename} NAME_WE)
    set(ropfuscated_exec_name "${exec_name}-ropfuscated")

    #######################
    # standard binaries
    #######################

    add_executable(${exec_name} ${exec_name}.c)
    add_dependencies(ropfuscator-examples ${exec_name})

    if (ROPF_PROFILE)
        target_link_options(${exec_name} PRIVATE ${LINKER_PROFILING_FLAGS})
        target_compile_options(${exec_name} PRIVATE
                ${COMPILER_PROFILING_FLAGS}
                -fprofile-instr-generate=${exec_name}.profdata)
    endif ()

    #######################
    # ROPFfuscated binaries
    #######################

    add_executable(${ropfuscated_exec_name} ${ropfuscated_exec_name}.s)
    add_dependencies(ropfuscator-examples ${ropfuscated_exec_name})

    target_link_libraries(${ropfuscated_exec_name} c opaquepredicate)

    if (ROPF_LIBNAIVE_ENABLE)
        target_link_libraries(${ropfuscated_exec_name} naive)
    endif ()

    if (ROPF_PROFILE)
        target_link_options(${ropfuscated_exec_name} PRIVATE ${LINKER_PROFILING_FLAGS})
        add_custom_command(
                OUTPUT
                ${ropfuscated_exec_name}.s
                DEPENDS
                ${CMAKE_CURRENT_SOURCE_DIR}/${exec_name}.c
                COMMAND
                clang
                ARGS
                ${ROPF_IR_FLAGS} ${COMPILER_PROFILING_FLAGS} -fprofile-instr-generate=${ropfuscated_exec_name}.profdata ${CMAKE_CURRENT_SOURCE_DIR}/${exec_name}.c -o ${ropfuscated_exec_name}.o
                COMMAND
                $<TARGET_FILE:llc>
                ARGS
                -march=x86 ${ropfuscated_exec_name}.o -o ${ropfuscated_exec_name}.s
        )
    else ()
        add_custom_command(
                OUTPUT
                ${ropfuscated_exec_name}.s
                DEPENDS
                ${CMAKE_CURRENT_SOURCE_DIR}/${exec_name}.c
                COMMAND
                clang
                ARGS
                ${ROPF_IR_FLAGS} ${CMAKE_CURRENT_SOURCE_DIR}/${exec_name}.c -o ${ropfuscated_exec_name}.o
                COMMAND
                $<TARGET_FILE:llc>
                ARGS
                ${ROPF_ASM_FLAGS} ${ropfuscated_exec_name}.o -o ${ropfuscated_exec_name}.s
        )
    endif ()
endforeach ()

