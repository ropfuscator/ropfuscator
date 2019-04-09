set(COMPILER_PROFILING_FLAGS -g -fcoverage-mapping)
set(LINKER_PROFILING_FLAGS -fprofile-instr-generate)
set(ROPF_IR_FLAGS -O0 -S -emit-llvm -fno-omit-frame-pointer -mno-omit-leaf-frame-pointer)
set(ROPF_ASM_FLAGS -march=x86 --disable-fp-elim)

file(GLOB files "${CMAKE_CURRENT_SOURCE_DIR}/*.c")

foreach(filename ${files})
    get_filename_component(exec_name ${filename} NAME_WE)
    set(ropfuscated_exec_name "${exec_name}-ropfuscated")

    #######################
    # standard binaries
    #######################

    add_executable(${exec_name} ${exec_name}.c)
    if(ROPF_PROFILE)
        target_link_options(${exec_name} PRIVATE ${LINKER_PROFILING_FLAGS})
        target_compile_options(${exec_name} PRIVATE 
            ${COMPILER_PROFILING_FLAGS} 
            -fprofile-instr-generate=${exec_name}.profdata)    
    endif()

    #######################
    # ROPFfuscated binaries
    #######################

    add_executable(${ropfuscated_exec_name} ${ropfuscated_exec_name}.s)
    target_link_libraries(${ropfuscated_exec_name} c opaquepredicate)

    if(ROPF_LIBNAIVE_ENABLE)
        target_link_libraries(${ropfuscated_exec_name} naive)
    endif()

    if(ROPF_PROFILE)
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
                ${ROPF_LLC}
            ARGS
                -march=x86 ${ropfuscated_exec_name}.o -o ${ropfuscated_exec_name}.s 
        )
    else()
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
		        ${ROPF_LLC}
	        ARGS
		        ${ROPF_ASM_FLAGS} ${ropfuscated_exec_name}.o -o ${ropfuscated_exec_name}.s
        )
    endif()
endforeach()

