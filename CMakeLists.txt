cmake_minimum_required(VERSION 3.24)

project(saslik-skewer VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_AUTOMOC ON)

find_package(Qt6 6.5 REQUIRED COMPONENTS Widgets)

add_executable(skewer
    src/main.cpp
    src/application_model.cpp
    src/application_model.hpp
    src/main_window.cpp
    src/main_window.hpp
    src/process_scanner.cpp
    src/process_scanner.hpp
)

target_link_libraries(skewer PRIVATE Qt6::Widgets)
target_compile_options(skewer PRIVATE -Wall -Wextra -Wpedantic)

install(TARGETS skewer RUNTIME DESTINATION bin)
