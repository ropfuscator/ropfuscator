add_library(rop SHARED librop.c)

target_compile_options(rop PRIVATE "-fasm-blocks")