cmake_minimum_required(VERSION 3.24)

project(saslik-skewer VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_AUTOMOC ON)

find_package(Qt6 6.5 REQUIRED COMPONENTS Widgets)
find_package(PkgConfig REQUIRED)
pkg_check_modules(SYSTEMD REQUIRED IMPORTED_TARGET libsystemd)
pkg_check_modules(NCURSESW REQUIRED IMPORTED_TARGET ncursesw)

add_executable(skewer
    src/main.cpp
    src/application_model.cpp
    src/application_model.hpp
    src/cgroup_manager.cpp
    src/cgroup_manager.hpp
    src/desktop_catalog.cpp
    src/desktop_catalog.hpp
    src/main_window.cpp
    src/main_window.hpp
    src/process_scanner.cpp
    src/process_scanner.hpp
    src/tui.cpp
    src/tui.hpp
)

target_link_libraries(skewer PRIVATE Qt6::Widgets PkgConfig::SYSTEMD PkgConfig::NCURSESW)
target_compile_options(skewer PRIVATE -Wall -Wextra -Wpedantic)

install(TARGETS skewer RUNTIME DESTINATION bin)

include(CTest)
if(BUILD_TESTING)
    add_executable(cgroup_manager_test
        tests/cgroup_manager_test.cpp
        src/cgroup_manager.cpp
        src/cgroup_manager.hpp
    )
    target_include_directories(cgroup_manager_test PRIVATE src)
    target_link_libraries(cgroup_manager_test PRIVATE Qt6::Core PkgConfig::SYSTEMD)
    target_compile_options(cgroup_manager_test PRIVATE -Wall -Wextra -Wpedantic)
    add_test(NAME cgroup_manager COMMAND cgroup_manager_test)
endif()
