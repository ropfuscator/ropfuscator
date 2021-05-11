add_library(rop SHARED librop.s)

add_custom_command(
  OUTPUT librop.s
  DEPENDS genasm.py
  COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/genasm.py)
