cmake_minimum_required(VERSION 3.16)
project(TemplateTrainer VERSION 1.0.0 LANGUAGES CXX)

# TODO: Rename project to match your game, e.g. project(MyGameTrainer ...)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# TODO: Rename source file to match your trainer, e.g. src/MyGameTrainer.cpp
add_library(trainer SHARED src/TemplateTrainer.cpp)

target_include_directories(trainer PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
)

target_link_libraries(trainer PRIVATE kernel32 user32)

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
