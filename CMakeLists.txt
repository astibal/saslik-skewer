cmake_minimum_required(VERSION 3.24)

project(saslik-skewer VERSION 0.9.50 LANGUAGES CXX)

include(GNUInstallDirs)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

find_package(Qt6 6.5 REQUIRED COMPONENTS Network Widgets Test)
find_package(PkgConfig REQUIRED)
pkg_check_modules(SYSTEMD REQUIRED IMPORTED_TARGET libsystemd)
pkg_check_modules(NCURSESW REQUIRED IMPORTED_TARGET ncursesw)

add_executable(skewer
    data/icons.qrc
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
    src/routing_plan.cpp
    src/routing_plan.hpp
    src/routing_controller.cpp
    src/routing_controller.hpp
    src/tui.cpp
    src/tui.hpp
)

add_executable(skewer-net-helper
    src/net_helper.cpp
    src/routing_plan.cpp
    src/routing_plan.hpp
)

target_link_libraries(skewer PRIVATE Qt6::Network Qt6::Widgets PkgConfig::SYSTEMD PkgConfig::NCURSESW)
target_compile_options(skewer PRIVATE -Wall -Wextra -Wpedantic)
target_compile_definitions(skewer PRIVATE
    SKEWER_VERSION="${PROJECT_VERSION}"
    SKEWER_INSTALLED_HELPER_PATH="${CMAKE_INSTALL_FULL_LIBEXECDIR}/skewer-net-helper")
target_link_libraries(skewer-net-helper PRIVATE Qt6::Core Qt6::Network)
target_compile_options(skewer-net-helper PRIVATE -Wall -Wextra -Wpedantic)

install(TARGETS skewer RUNTIME DESTINATION bin)
install(TARGETS skewer-net-helper RUNTIME DESTINATION ${CMAKE_INSTALL_LIBEXECDIR})
install(FILES data/org.saslik.Skewer.desktop DESTINATION share/applications)
install(FILES data/org.saslik.Skewer.svg DESTINATION share/icons/hicolor/scalable/apps)
set(SKEWER_HELPER_PATH "${CMAKE_INSTALL_FULL_LIBEXECDIR}/skewer-net-helper")
configure_file(data/org.saslik.skewer.policy.in org.saslik.skewer.policy @ONLY)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/org.saslik.skewer.policy
        DESTINATION share/polkit-1/actions)

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

    add_executable(routing_plan_test
        tests/routing_plan_test.cpp
        src/routing_plan.cpp
        src/routing_plan.hpp
    )
    target_include_directories(routing_plan_test PRIVATE src)
    target_link_libraries(routing_plan_test PRIVATE Qt6::Core Qt6::Network)
    target_compile_options(routing_plan_test PRIVATE -Wall -Wextra -Wpedantic)
    add_test(NAME routing_plan COMMAND routing_plan_test)

    add_executable(application_model_test
        tests/application_model_test.cpp
        src/application_model.cpp
        src/application_model.hpp
        src/desktop_catalog.cpp
        src/desktop_catalog.hpp
        src/process_scanner.cpp
        src/process_scanner.hpp
    )
    target_include_directories(application_model_test PRIVATE src)
    target_link_libraries(application_model_test PRIVATE Qt6::Widgets Qt6::Test)
    target_compile_options(application_model_test PRIVATE -Wall -Wextra -Wpedantic)
    add_test(NAME application_model COMMAND application_model_test)
    set_tests_properties(application_model PROPERTIES ENVIRONMENT "QT_QPA_PLATFORM=offscreen")
endif()

set(CPACK_GENERATOR DEB)
set(CPACK_PACKAGE_NAME skewer)
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_CONTACT "Ales Stibal <astib@mag0.net>")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Application traffic selector for Saslik")
set(CPACK_DEBIAN_PACKAGE_SECTION net)
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
set(CPACK_DEBIAN_PACKAGE_DEPENDS "iproute2, nftables, polkitd, pkexec, sudo, systemd, libqt6svg6, qt6-svg-plugins, qt6-qpa-plugins, qt6-wayland")
set(CPACK_PACKAGING_INSTALL_PREFIX /usr)
set(CPACK_PACKAGE_FILE_NAME "skewer-linux-amd64")
include(CPack)
