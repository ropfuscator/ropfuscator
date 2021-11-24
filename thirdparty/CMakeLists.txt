if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/fmt/.git")
  message(SEND_ERROR "The fmt submodule is not available. Please run
git submodule update --init --recursive")
endif()

if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tinytoml/.git")
  message(SEND_ERROR "The tinytoml submodule is not available. Please run
git submodule update --init --recursive")
endif()

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/fmt/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/tinytoml/include)
