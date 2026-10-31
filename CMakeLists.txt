cmake_minimum_required(VERSION 3.24)

project(saslik-skewer VERSION 0.9.50.11 LANGUAGES CXX)

# Select platform dependencies before discovering Linux-only services/libraries.
if(WIN32)
    set(SKEWER_APP_VERSION "${PROJECT_VERSION}")
    set(SKEWER_WINDOWS_APP ON CACHE BOOL "Build the Windows application")
    include(CTest)
    add_subdirectory(platform/windows)
    return()
endif()

include(GNUInstallDirs)
add_subdirectory(platform/traffic)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
# Fail closed for Release, RelWithDebInfo, MinSizeRel and unspecified builds.
add_compile_definitions(SKEWER_DEVELOPMENT_BINARY=$<IF:$<CONFIG:Debug>,1,0>)

find_package(Qt6 6.4 REQUIRED COMPONENTS Network Widgets Test Concurrent)
find_package(PkgConfig REQUIRED)
find_package(OpenSSL 3.0 REQUIRED)
pkg_check_modules(SYSTEMD REQUIRED IMPORTED_TARGET libsystemd)
pkg_check_modules(NCURSESW REQUIRED IMPORTED_TARGET ncursesw)
find_path(NSS_INCLUDE_DIR cert.h PATH_SUFFIXES nss REQUIRED)
find_path(NSPR_INCLUDE_DIR prtypes.h PATH_SUFFIXES nspr REQUIRED)
find_library(NSS_LIBRARY nss3 REQUIRED)
find_library(NSPR_LIBRARY nspr4 REQUIRED)
add_executable(skewer-nss-helper src/nss_helper.cpp)
target_include_directories(skewer-nss-helper PRIVATE ${NSS_INCLUDE_DIR} ${NSPR_INCLUDE_DIR})
target_link_libraries(skewer-nss-helper PRIVATE Qt6::Network ${NSS_LIBRARY} ${NSPR_LIBRARY})
target_compile_options(skewer-nss-helper PRIVATE -Wall -Wextra -Wpedantic)
target_compile_definitions(skewer-nss-helper PRIVATE QT_NO_KEYWORDS)
install(TARGETS skewer-nss-helper RUNTIME DESTINATION ${CMAKE_INSTALL_LIBEXECDIR})
add_executable(skewer-session src/session_main.cpp src/session_guard.hpp src/session_status.cpp src/routing_plan.cpp src/pairing.cpp)
target_link_libraries(skewer-session PRIVATE Qt6::Network PkgConfig::SYSTEMD)
target_link_libraries(skewer-session PRIVATE OpenSSL::SSL OpenSSL::Crypto)
target_link_libraries(skewer-session PRIVATE skewer-ipv4-prefix)
target_compile_options(skewer-session PRIVATE -Wall -Wextra -Wpedantic)
install(TARGETS skewer-session RUNTIME DESTINATION ${CMAKE_INSTALL_LIBEXECDIR})
configure_file(data/skewer.bashrc skewer.bashrc COPYONLY)
install(FILES data/skewer.bashrc DESTINATION ${CMAKE_INSTALL_LIBEXECDIR})
configure_file(data/skewer-prompt.bash skewer-prompt.bash COPYONLY)
install(FILES data/skewer-prompt.bash DESTINATION ${CMAKE_INSTALL_LIBEXECDIR})

add_executable(skewer
    data/icons.qrc
    src/main.cpp
    src/tuntom_client.cpp
    src/pairing.cpp
    src/launcher.cpp
    src/connections.cpp
    src/session_status.cpp
    src/application_model.cpp
    src/application_model.hpp
    src/cgroup_manager.cpp
    src/cgroup_manager.hpp
    src/ca_store.cpp
    src/ca_store.hpp
    src/ca_panel.cpp src/ca_panel.hpp
    src/runtime_trust.cpp src/runtime_trust.hpp
    src/portal_trust.cpp src/portal_trust.hpp
    src/desktop_catalog.cpp
    src/desktop_catalog.hpp
    src/main_window.cpp
    src/main_window.hpp
    src/preferences_dialog.cpp
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
    src/tuntom_process.cpp
    src/socket_cleanup.cpp
    src/ca_store.cpp src/ca_store.hpp
    src/routing_plan.cpp
    src/routing_plan.hpp
)
add_dependencies(skewer skewer-session)

target_link_libraries(skewer PRIVATE Qt6::Network Qt6::Widgets Qt6::Concurrent PkgConfig::SYSTEMD PkgConfig::NCURSESW)
target_link_libraries(skewer PRIVATE OpenSSL::SSL OpenSSL::Crypto)
target_link_libraries(skewer PRIVATE skewer-ipv4-prefix)
target_compile_options(skewer PRIVATE -Wall -Wextra -Wpedantic)
target_compile_definitions(skewer PRIVATE
    SKEWER_VERSION="${PROJECT_VERSION}"
    SKEWER_INSTALLED_HELPER_PATH="${CMAKE_INSTALL_FULL_LIBEXECDIR}/skewer-net-helper")
target_link_libraries(skewer-net-helper PRIVATE Qt6::Core Qt6::Network)
target_link_libraries(skewer-net-helper PRIVATE skewer-ipv4-prefix)
target_compile_options(skewer-net-helper PRIVATE -Wall -Wextra -Wpedantic)
target_compile_definitions(skewer-net-helper PRIVATE SKEWER_INSTALLED_HELPER_PATH="${CMAKE_INSTALL_FULL_LIBEXECDIR}/skewer-net-helper")

install(TARGETS skewer RUNTIME DESTINATION bin)
install(FILES data/skewer-shell-scripting.1 DESTINATION ${CMAKE_INSTALL_MANDIR}/man1)
install(TARGETS skewer-net-helper RUNTIME DESTINATION ${CMAKE_INSTALL_LIBEXECDIR})
install(FILES data/org.saslik.Skewer.desktop DESTINATION share/applications)
install(FILES data/org.saslik.Skewer.svg DESTINATION share/icons/hicolor/scalable/apps)
set(SKEWER_HELPER_PATH "${CMAKE_INSTALL_FULL_LIBEXECDIR}/skewer-net-helper")
configure_file(data/org.saslik.skewer.policy.in org.saslik.skewer.policy @ONLY)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/org.saslik.skewer.policy
        DESTINATION share/polkit-1/actions)

include(CTest)
if(BUILD_TESTING)
    add_executable(diagnostics_test tests/diagnostics_test.cpp)
    target_include_directories(diagnostics_test PRIVATE src)
    target_link_libraries(diagnostics_test PRIVATE Qt6::Core)
    add_test(NAME support_archive COMMAND python3 ${CMAKE_CURRENT_SOURCE_DIR}/tests/support_archive_test.py $<TARGET_FILE:diagnostics_test>)
    set_tests_properties(support_archive PROPERTIES TIMEOUT 45)
    add_test(NAME tunnel_preflight COMMAND python3 ${CMAKE_CURRENT_SOURCE_DIR}/tests/tunnel_preflight_test.py $<TARGET_FILE:skewer>)
    set_tests_properties(tunnel_preflight PROPERTIES TIMEOUT 15)
    add_subdirectory(platform/common)
    add_executable(host_routing_test tests/host_routing_test.cpp)
    target_include_directories(host_routing_test PRIVATE src)
    target_link_libraries(host_routing_test PRIVATE Qt6::Core Qt6::Network)
    add_test(NAME host_routing COMMAND host_routing_test)
    add_test(NAME host_routing_packets COMMAND python3 ${CMAKE_CURRENT_SOURCE_DIR}/tests/host_routing_packet_test.py $<TARGET_FILE:host_routing_test>)
    set_tests_properties(host_routing_packets PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 30)
    add_executable(socket_cleanup_test tests/socket_cleanup_test.cpp src/socket_cleanup.cpp)
    target_include_directories(socket_cleanup_test PRIVATE src)
    target_link_libraries(socket_cleanup_test PRIVATE Qt6::Core)
    add_test(NAME socket_cleanup COMMAND socket_cleanup_test)
    add_executable(socket_exemption_test tests/socket_exemption_test.cpp)
    target_include_directories(socket_exemption_test PRIVATE src)
    target_link_libraries(socket_exemption_test PRIVATE Qt6::Core)
    add_test(NAME socket_exemption COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/tests/socket_exemption_test.sh $<TARGET_FILE:socket_exemption_test>)
    set_tests_properties(socket_exemption PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 20)
    add_executable(socket_cleanup_integration_test tests/socket_cleanup_integration_test.cpp src/socket_cleanup.cpp src/cgroup_manager.cpp)
    target_include_directories(socket_cleanup_integration_test PRIVATE src)
    target_link_libraries(socket_cleanup_integration_test PRIVATE Qt6::Network PkgConfig::SYSTEMD)
    add_test(NAME socket_cleanup_integration COMMAND socket_cleanup_integration_test)
    set_tests_properties(socket_cleanup_integration PROPERTIES TIMEOUT 15)
    add_executable(launcher_test tests/launcher_test.cpp src/launcher.cpp src/desktop_catalog.cpp src/cgroup_manager.cpp)
    target_include_directories(launcher_test PRIVATE src)
    target_link_libraries(launcher_test PRIVATE Qt6::Widgets PkgConfig::SYSTEMD)
    add_test(NAME launcher COMMAND launcher_test)
    set_tests_properties(launcher PROPERTIES ENVIRONMENT "QT_QPA_PLATFORM=offscreen")
    add_test(NAME session_cli COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/tests/session_cli_test.sh $<TARGET_FILE:skewer>)
    add_test(NAME shell_prompt COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/tests/prompt_test.sh
        ${CMAKE_CURRENT_SOURCE_DIR}/data/skewer-prompt.bash)
    add_executable(session_guard_test tests/session_guard_test.cpp)
    target_include_directories(session_guard_test PRIVATE src)
    target_link_libraries(session_guard_test PRIVATE Qt6::Core)
    add_test(NAME session_guard COMMAND session_guard_test)
    add_executable(session_integration_test tests/session_integration_test.cpp src/cgroup_manager.cpp)
    target_include_directories(session_integration_test PRIVATE src)
    target_link_libraries(session_integration_test PRIVATE Qt6::Core PkgConfig::SYSTEMD)
    target_compile_definitions(session_integration_test PRIVATE SKEWER_TEST_BINARY="$<TARGET_FILE:skewer>")
    add_dependencies(session_integration_test skewer)
    add_test(NAME session_integration COMMAND session_integration_test)
    set_tests_properties(session_integration PROPERTIES TIMEOUT 20)
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
    target_link_libraries(routing_plan_test PRIVATE Qt6::Core Qt6::Network skewer-ipv4-prefix)
    target_compile_options(routing_plan_test PRIVATE -Wall -Wextra -Wpedantic)
    add_test(NAME routing_plan COMMAND routing_plan_test)
    add_executable(helper_protocol_test tests/helper_protocol_test.cpp)
    target_include_directories(helper_protocol_test PRIVATE src)
    target_link_libraries(helper_protocol_test PRIVATE Qt6::Core)
    add_test(NAME helper_protocol COMMAND helper_protocol_test)
    set_tests_properties(cgroup_manager session_integration socket_cleanup_integration
        PROPERTIES SKIP_RETURN_CODE 77)
    add_executable(interface_routing_test tests/interface_routing_test.cpp)
    target_include_directories(interface_routing_test PRIVATE src)
    target_link_libraries(interface_routing_test PRIVATE Qt6::Core)
    target_compile_options(interface_routing_test PRIVATE -Wall -Wextra -Wpedantic)
    add_test(NAME interface_routing COMMAND interface_routing_test)
    add_executable(trust_tree_test tests/trust_tree_test.cpp)
    target_include_directories(trust_tree_test PRIVATE src)
    target_link_libraries(trust_tree_test PRIVATE Qt6::Widgets)
    add_test(NAME trust_tree COMMAND trust_tree_test)
    set_tests_properties(trust_tree PROPERTIES ENVIRONMENT "QT_QPA_PLATFORM=offscreen")
    add_dependencies(interface_routing_test skewer-net-helper)
    find_program(SKEWER_TEST_PYTHON python3)
    if(SKEWER_TEST_PYTHON)
        add_test(NAME helper_session COMMAND ${SKEWER_TEST_PYTHON}
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/helper_session_test.py $<TARGET_FILE:skewer-net-helper>)
        set_tests_properties(helper_session PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 45)
        add_test(NAME routing_guard_packets COMMAND ${SKEWER_TEST_PYTHON}
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/routing_guard_packet_test.py $<TARGET_FILE:routing_plan_test>)
        set_tests_properties(routing_guard_packets PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 20)
        add_test(NAME interface_packets COMMAND ${SKEWER_TEST_PYTHON}
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/interface_packet_test.py $<TARGET_FILE:interface_routing_test>)
        set_tests_properties(interface_packets PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 20)
    endif()

    add_executable(ca_store_test tests/ca_store_test.cpp src/ca_store.cpp src/ca_store.hpp)
    target_include_directories(ca_store_test PRIVATE src)
    target_link_libraries(ca_store_test PRIVATE Qt6::Network)
    target_compile_options(ca_store_test PRIVATE -Wall -Wextra -Wpedantic)
    target_compile_definitions(ca_store_test PRIVATE
        SKEWER_INSTALLED_HELPER_PATH="${CMAKE_INSTALL_FULL_LIBEXECDIR}/skewer-net-helper")
    add_test(NAME ca_store COMMAND ca_store_test)
    add_dependencies(ca_store_test skewer-nss-helper)

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
    target_link_libraries(application_model_test PRIVATE Qt6::Widgets Qt6::Test Qt6::Concurrent)
    target_compile_options(application_model_test PRIVATE -Wall -Wextra -Wpedantic)
    add_test(NAME application_model COMMAND application_model_test)
    set_tests_properties(application_model PROPERTIES ENVIRONMENT "QT_QPA_PLATFORM=offscreen")
    add_executable(saslik_status_test
        tests/saslik_status_test.cpp
        src/main_window.cpp src/main_window.hpp
        src/preferences_dialog.cpp
        src/launcher.cpp
        src/connections.cpp
        src/ca_store.cpp src/ca_store.hpp
        src/ca_panel.cpp src/ca_panel.hpp
        src/runtime_trust.cpp src/runtime_trust.hpp
        src/portal_trust.cpp src/portal_trust.hpp
        src/application_model.cpp src/application_model.hpp
        src/cgroup_manager.cpp src/cgroup_manager.hpp
        src/desktop_catalog.cpp src/process_scanner.cpp
        src/routing_controller.cpp src/routing_plan.cpp)
    target_include_directories(saslik_status_test PRIVATE src)
    target_link_libraries(saslik_status_test PRIVATE Qt6::Widgets Qt6::Network Qt6::Concurrent Qt6::Test
        PkgConfig::SYSTEMD skewer-ipv4-prefix)
    target_sources(saslik_status_test PRIVATE src/pairing.cpp)
    target_link_libraries(saslik_status_test PRIVATE OpenSSL::SSL OpenSSL::Crypto)
    target_compile_definitions(saslik_status_test PRIVATE
        SKEWER_VERSION="${PROJECT_VERSION}"
        SKEWER_INSTALLED_HELPER_PATH="${CMAKE_INSTALL_FULL_LIBEXECDIR}/skewer-net-helper")
    add_test(NAME saslik_status COMMAND saslik_status_test)
    set_tests_properties(saslik_status PROPERTIES ENVIRONMENT "QT_QPA_PLATFORM=offscreen")
    add_executable(tui_test tests/tui_test.cpp src/tui.cpp
        src/ca_store.cpp src/connections.cpp src/runtime_trust.cpp src/runtime_trust.hpp
        src/application_model.cpp src/desktop_catalog.cpp src/process_scanner.cpp
        src/cgroup_manager.cpp src/routing_controller.cpp src/routing_plan.cpp)
    target_include_directories(tui_test PRIVATE src)
    target_link_libraries(tui_test PRIVATE Qt6::Widgets Qt6::Network Qt6::Concurrent
        PkgConfig::SYSTEMD PkgConfig::NCURSESW skewer-ipv4-prefix)
    target_compile_definitions(tui_test PRIVATE
        SKEWER_INSTALLED_HELPER_PATH="${CMAKE_INSTALL_FULL_LIBEXECDIR}/skewer-net-helper")
    add_test(NAME tui COMMAND tui_test)
    set_tests_properties(tui PROPERTIES ENVIRONMENT "QT_QPA_PLATFORM=offscreen")
endif()

if(BUILD_TESTING)
    add_executable(tuntom_session_test tests/tuntom_session_test.cpp)
    target_include_directories(tuntom_session_test PRIVATE src)
    target_link_libraries(tuntom_session_test PRIVATE Qt6::Network)
    add_test(NAME tuntom_session COMMAND tuntom_session_test)
    add_executable(preferences_test tests/preferences_test.cpp src/preferences_dialog.cpp)
    target_include_directories(preferences_test PRIVATE src)
    target_link_libraries(preferences_test PRIVATE Qt6::Widgets Qt6::Concurrent)
    add_test(NAME preferences COMMAND preferences_test)
    foreach(policy IN ITEMS configured release)
        add_executable(tuntom_binary_${policy}_test tests/tuntom_binary_test.cpp)
        target_include_directories(tuntom_binary_${policy}_test PRIVATE src)
        target_link_libraries(tuntom_binary_${policy}_test PRIVATE Qt6::Core)
        add_test(NAME tuntom_binary_${policy} COMMAND tuntom_binary_${policy}_test)
    endforeach()
    target_compile_definitions(tuntom_binary_release_test PRIVATE SKEWER_TEST_RELEASE_POLICY=1)
    set_tests_properties(preferences PROPERTIES ENVIRONMENT "QT_QPA_PLATFORM=offscreen")
    add_executable(tuntom_routing_driver tests/tuntom_routing_driver.cpp
        src/tuntom_process.cpp src/socket_cleanup.cpp src/ca_store.cpp src/routing_plan.cpp)
    target_include_directories(tuntom_routing_driver PRIVATE src)
    target_link_libraries(tuntom_routing_driver PRIVATE Qt6::Network skewer-ipv4-prefix)
    target_compile_definitions(tuntom_routing_driver PRIVATE
        SKEWER_INSTALLED_HELPER_PATH="${CMAKE_INSTALL_FULL_LIBEXECDIR}/skewer-net-helper")
    add_test(NAME tuntom_routing COMMAND python3 ${CMAKE_CURRENT_SOURCE_DIR}/tests/tuntom_routing_test.py
        $<TARGET_FILE:skewer-net-helper> $<TARGET_FILE:tuntom_routing_driver>)
    set_tests_properties(tuntom_routing PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 45)
    add_executable(tuntom_control_test tests/tuntom_control_test.cpp src/pairing.cpp)
    add_executable(pairing_snapshot_test tests/pairing_snapshot_test.cpp src/pairing.cpp)
    target_include_directories(pairing_snapshot_test PRIVATE src)
    target_link_libraries(pairing_snapshot_test PRIVATE Qt6::Network OpenSSL::SSL OpenSSL::Crypto)
    add_test(NAME pairing_snapshot COMMAND pairing_snapshot_test)
    target_include_directories(tuntom_control_test PRIVATE src)
    target_link_libraries(tuntom_control_test PRIVATE Qt6::Network OpenSSL::SSL OpenSSL::Crypto)
endif()

set(CPACK_GENERATOR DEB)
set(CPACK_PACKAGE_NAME skewer)
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_CONTACT "Ales Stibal <astib@mag0.net>")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Application traffic selector for Saslik")
set(CPACK_DEBIAN_PACKAGE_SECTION net)
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
# Qt 6.4 ships its SVG plugins inside libqt6svg6; newer releases split them out.
set(CPACK_DEBIAN_PACKAGE_DEPENDS "iproute2, nftables, polkitd, pkexec, sudo, systemd, ca-certificates, libnss3-tools, libqt6svg6, qt6-svg-plugins | libqt6svg6 (<< 6.5), qt6-qpa-plugins, qt6-wayland")
set(CPACK_PACKAGING_INSTALL_PREFIX /usr)
set(CPACK_PACKAGE_FILE_NAME "skewer-linux-amd64")
include(CPack)
