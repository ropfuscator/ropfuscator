add_library(naive SHARED libnaive.c)
add_library(opaquepredicate STATIC op.c)

target_compile_options(
    naive PRIVATE
    -m32 -fno-pie -g -fprofile-instr-generate -fcoverage-mapping
)

target_link_options(
    naive PRIVATE
    -m32 -fno-pie -fprofile-instr-generate
)

target_compile_options(
    opaquepredicate PRIVATE
    -m32 -fomit-frame-pointer -fno-pie -g -fprofile-instr-generate -fcoverage-mapping
)
