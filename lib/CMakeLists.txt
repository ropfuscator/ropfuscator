add_library(naive SHARED libnaive.c)
add_library(opaquepredicate STATIC op.c)

target_compile_options(
    naive PRIVATE
    -m32 -fno-pie
)

target_link_options(
    naive PRIVATE
    -m32 -fno-pie
)

target_compile_options(
    opaquepredicate PRIVATE
    -m32 -lc -fomit-frame-pointer -fno-pie 
)
