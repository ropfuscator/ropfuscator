add_custom_target(ropfuscator-evaluation-performance)

file(GLOB files "${CMAKE_CURRENT_SOURCE_DIR}/../../binutils/*.bc")
file(GLOB configfiles "${CMAKE_CURRENT_SOURCE_DIR}/ropf/*.conf")

set(ROPF_ASM_FLAGS_ROPFBIN ${ROPF_ASM_FLAGS})
set(ROPF_IR_FLAGS_ROPFBIN ${ROPF_IR_FLAGS})

foreach (bcfile ${files})
    get_filename_component(exec_name ${bcfile} NAME_WE)

    foreach (configfile ${configfiles})
        get_filename_component(config ${configfile} NAME_WE)
        set(ropfuscated_exec_name "eval.${exec_name}.${config}")

        add_executable(${ropfuscated_exec_name} ${ropfuscated_exec_name}.o)
	set_target_properties(${ropfuscated_exec_name} PROPERTIES LINKER_LANGUAGE C)
        target_link_libraries(${ropfuscated_exec_name} dl)

        add_dependencies(ropfuscator-evaluation-performance ${ropfuscated_exec_name})

        add_custom_command(
            OUTPUT
            ${ropfuscated_exec_name}.s
            DEPENDS
            ${bcfile} llc ${configfile}
            COMMAND
            $<TARGET_FILE:llc>
            ARGS
            ${ROPF_ASM_FLAGS_ROPFBIN} ${bcfile} -o ${ropfuscated_exec_name}.s -ropfuscator-config ${configfile}
        )

        # workaround to avoid huge memory usage in clang assembler (we should use gcc (as) instead)
        add_custom_command(
            OUTPUT
            ${ropfuscated_exec_name}.o
            DEPENDS
            ${ropfuscated_exec_name}.s
            COMMAND
            gcc
            ARGS
            -m32 -c ${ropfuscated_exec_name}.s -o ${ropfuscated_exec_name}.o
        )
    endforeach ()
endforeach ()
