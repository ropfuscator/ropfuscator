add_library(rop SHARED librop.asm)

add_custom_command(
    OUTPUT
    librop.asm
    DEPENDS
    genasm.py
    COMMAND
    python
    ARGS
    ${CMAKE_CURRENT_SOURCE_DIR}/genasm.py
)