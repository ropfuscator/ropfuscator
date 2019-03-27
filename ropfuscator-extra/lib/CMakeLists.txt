set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -m32 -fno-pic -fomit-frame-pointer")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -no-pic")
set(COMPILER_PROFILING_FLAGS -g -fprofile-instr-generate -fcoverage-mapping)
set(LINKER_PROFILING_FLAGS -fprofile-instr-generate)

add_library(opaquepredicate STATIC op.c)

if(ROPF_LIBNAIVE_ENABLE)
    add_library(naive SHARED libnaive.c)
endif()

if(ROPF_PROFILE)
    target_compile_options(opaquepredicate PRIVATE ${COMPILER_PROFILING_FLAGS})
    target_link_options(opaquepredicate PRIVATE ${LINKER_PROFILING_FLAGS})

    if(ROPF_LIBNAIVE_ENABLE)
        target_compile_options(naive PRIVATE ${COMPILER_PROFILING_FLAGS}) 
        target_link_options(naive PRIVATE ${LINKER_PROFILING_FLAGS})
    endif()
endif()
