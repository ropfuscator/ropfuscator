add_library(rop SHARED librop.asm)

# TODO: CMake does not recognize the library as a 32bit object
# hence we have to force the -m32 flag
target_compile_options(rop PRIVATE "-masm=intel" "-m32")

add_custom_command(
  OUTPUT librop.asm
  DEPENDS genasm.py
  COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/genasm.py)
