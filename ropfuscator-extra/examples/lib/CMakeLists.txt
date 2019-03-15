if(ROPF_LIBNAIVE_ENABLE)
    add_library(naive SHARED libnaive.c)
    target_link_options(
        naive PRIVATE
        -m32 -fno-pie)
    target_compile_options(
        naive PRIVATE
        -m32 -fno-pie)

    if(ROPF_PROFILE)
        target_link_options(
            naive PRIVATE
            -fprofile-instr-generate)
        target_compile_options(
            naive PRIVATE
            -g -fprofile-instr-generate -fcoverage-mapping)
    endif()
endif()

add_library(opaquepredicate STATIC op.c)

target_compile_options(
    opaquepredicate PRIVATE
    -m32 -fomit-frame-pointer -fno-pie -g -fprofile-instr-generate -fcoverage-mapping)

if(ROPF_PROFILE)
    target_compile_options(
        opaquepredicate PRIVATE
        -g -fprofile-instr-generate -fcoverage-mapping)
endif()
