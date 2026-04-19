cmake_minimum_required(VERSION 3.16)
project(BalatroTrainer VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(trainer SHARED src/BalatroTrainer.cpp)

target_include_directories(trainer PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
)

target_link_libraries(trainer PRIVATE kernel32 user32 psapi)

if(MSVC)
    target_compile_options(trainer PRIVATE /W4 /WX-)
    target_compile_definitions(trainer PRIVATE
        WIN32_LEAN_AND_MEAN
        NOMINMAX
        _CRT_SECURE_NO_WARNINGS
    )
endif()

set_target_properties(trainer PROPERTIES
    OUTPUT_NAME "trainer"
    RUNTIME_OUTPUT_DIRECTORY        "${CMAKE_BINARY_DIR}"
    RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}"
    RUNTIME_OUTPUT_DIRECTORY_DEBUG  "${CMAKE_BINARY_DIR}"
)
