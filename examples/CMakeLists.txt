set(CMAKE_ASM_COMPILER "gcc")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -m32")
set(CMAKE_ASM_FLAGS "${CMAKE_ASM_FLAGS} -m32")

file(GLOB files "${CMAKE_CURRENT_SOURCE_DIR}/*.c")

foreach(filename ${files})
    get_filename_component(exec_name ${filename} NAME_WE)

    add_executable(${exec_name} ${exec_name}.s)
    target_link_libraries(${exec_name} opaquepredicate)
    target_link_libraries(${exec_name} c)

  
    add_custom_command(
        OUTPUT 
            ${exec_name}.s
        DEPENDS
            ${CMAKE_CURRENT_SOURCE_DIR}/${exec_name}.c
        COMMAND
            clang
        ARGS 
            -O0 -S -emit-llvm ${CMAKE_CURRENT_SOURCE_DIR}/${exec_name}.c -o ${exec_name}.o
        COMMAND
            ropf-llc
        ARGS
            -march=x86 ${exec_name}.o -o ${exec_name}.s
    )

    #target_link_options(${exec_name} PRIVATE -rpath . )
endforeach()

