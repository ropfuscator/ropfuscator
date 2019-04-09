add_custom_target(binutils)

set(COMPILER_PROFILING_FLAGS -g -fcoverage-mapping)
set(LINKER_PROFILING_FLAGS -fprofile-instr-generate)
set(ROPF_IR_FLAGS -O0 -S -emit-llvm -fno-omit-frame-pointer -mno-omit-leaf-frame-pointer)
set(ROPF_ASM_FLAGS -march=x86 --disable-fp-elim)

find_library(BFD bfd)
find_library(DL dl)

if(NOT BFD)
    message(FATAL_ERROR "libbfd not found.")
endif()

if(NOT DL)
    message(FATAL_ERROR "libdl not found.")
endif()

file(GLOB files "${CMAKE_CURRENT_SOURCE_DIR}/*.bc")

foreach(filename ${files})
    get_filename_component(exec_name ${filename} NAME_WE)
    set(ropfuscated_exec_name "${exec_name}-ropfuscated")

    add_executable(${ropfuscated_exec_name} ${ropfuscated_exec_name}.s)
    target_link_libraries(${ropfuscated_exec_name} c opaquepredicate bfd dl)

    add_dependencies(binutils ${ropfuscated_exec_name})
    
    if(ROPF_LIBNAIVE_ENABLE)
        target_link_libraries(${ropfuscated_exec_name} naive)
    endif()

    if(ROPF_PROFILE)
        target_link_options(${ropfuscated_exec_name} PRIVATE ${LINKER_PROFILING_FLAGS})
        add_custom_command(
            OUTPUT 
                ${ropfuscated_exec_name}.s
            DEPENDS
                ${CMAKE_CURRENT_SOURCE_DIR}/${exec_name}.bc
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
                ${CMAKE_CURRENT_SOURCE_DIR}/${exec_name}.bc
            COMMAND
                clang
            ARGS 
                ${ROPF_IR_FLAGS} ${CMAKE_CURRENT_SOURCE_DIR}/${exec_name}.bc -o ${ropfuscated_exec_name}.o
            COMMAND
                ${ROPF_LLC}
            ARGS
                ${ROPF_ASM_FLAGS} ${ropfuscated_exec_name}.o -o ${ropfuscated_exec_name}.s
        )
    endif()
endforeach()

