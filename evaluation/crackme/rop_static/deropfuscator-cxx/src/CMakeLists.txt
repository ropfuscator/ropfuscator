include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../ELFIO)
include_directories(${CMAKE_CURRENT_SOURCE_DIR})

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

add_executable(deropfuscator deropfuscator.cpp elfanalysis.cpp)
target_link_libraries(deropfuscator LINK_PUBLIC capstone)
