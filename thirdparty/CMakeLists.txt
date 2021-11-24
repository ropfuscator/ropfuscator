file(GLOB BUF ${CMAKE_CURRENT_SOURCE_DIR}/fmt)
list(LENGTH BUF BUF_LEN)
if(BUF_LEN EQUAL 0)
  message(SEND_ERROR "The fmt submodule is not available. Please run
git submodule update --init --recursive")
endif()

file(GLOB BUF ${CMAKE_CURRENT_SOURCE_DIR}/tinytoml)
list(LENGTH BUF BUF_LEN)
if(BUF_LEN EQUAL 0)
  message(SEND_ERROR "The tinytoml submodule is not available. Please run
git submodule update --init --recursive")
endif()

include_directories(SYSTEM ${CMAKE_CURRENT_SOURCE_DIR}/fmt/include)
include_directories(SYSTEM ${CMAKE_CURRENT_SOURCE_DIR}/tinytoml/include)
