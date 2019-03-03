set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -m32")
set(CMAKE_ASM_FLAGS "${CMAKE_ASM_FLAGS} -m32")

file(GLOB files "${CMAKE_CURRENT_SOURCE_DIR}/*.c")

foreach(filename ${files})
    get_filename_component(exec_name ${filename} NAME_WE)
    set(ropfuscated_exec_name "${exec_name}-ropfuscated")

    add_executable(${exec_name} ${exec_name}.c)

    #######################
    # ROPFfuscated binaries
    #######################
    
    add_executable(${ropfuscated_exec_name} ${ropfuscated_exec_name}.s)
    target_link_libraries(${ropfuscated_exec_name} c opaquepredicate)
    
    add_custom_command(
        OUTPUT 
            ${ropfuscated_exec_name}.s
        DEPENDS
            ${CMAKE_CURRENT_SOURCE_DIR}/${exec_name}.c
        COMMAND
            clang
        ARGS 
            -O0 -S -emit-llvm ${CMAKE_CURRENT_SOURCE_DIR}/${exec_name}.c -o ${ropfuscated_exec_name}.o
        COMMAND
            ropf-llc
        ARGS
            -march=x86 ${ropfuscated_exec_name}.o -o ${ropfuscated_exec_name}.s
    )


    #target_link_options(${exec_name} PRIVATE -rpath . )
endforeach()

