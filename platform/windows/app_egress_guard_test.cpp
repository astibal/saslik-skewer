#include <winsock2.h>
#include <ws2tcpip.h>
#include "app_egress_guard.hpp"
#include <rpc.h>
#include <array>
#include <iostream>
#include <stdexcept>

namespace {
using skewer::windows::traffic::AppImageBlock;
void require(bool value, const char* message) {
    if (!value) {
        throw std::runtime_error(message);
    }
}

class Socket final {
public:
    Socket(int family, int type) : handle(socket(family, type, 0)) {
        require(handle != INVALID_SOCKET, "Create test socket");
    }
    ~Socket() { closesocket(handle); }
    Socket(const Socket&) = delete;
    Socket& operator=(const Socket&) = delete;
    SOCKET handle;
};

void probe(int family, bool tcp, bool blocked) {
    const auto type = tcp ? SOCK_STREAM : SOCK_DGRAM;
    Socket listener(family, type), sender(family, type);
    sockaddr_storage address{};
    int length{};
    if (family == AF_INET) {
        auto& v4 = reinterpret_cast<sockaddr_in&>(address);
        v4.sin_family = AF_INET;
        v4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        length = sizeof(v4);
    } else {
        auto& v6 = reinterpret_cast<sockaddr_in6&>(address);
        v6.sin6_family = AF_INET6;
        v6.sin6_addr = in6addr_loopback;
        length = sizeof(v6);
    }
    auto* endpoint = reinterpret_cast<sockaddr*>(&address);
    require(bind(listener.handle, endpoint, length) == 0, "Bind loopback test listener");
    require(getsockname(listener.handle, endpoint, &length) == 0, "Read test listener port");
    if (tcp) {
        require(listen(listener.handle, 1) == 0, "Listen for test connection");
    }
    const int result =
        tcp ? connect(sender.handle, endpoint, length) : sendto(sender.handle, "x", 1, 0, endpoint, length);
    const int error = result == SOCKET_ERROR ? WSAGetLastError() : 0;
    if (blocked) {
        if (tcp || result == SOCKET_ERROR) {
            // A refused TCP connection is not evidence of enforcement.
            require(result == SOCKET_ERROR && error == WSAEACCES, "Expected WFP access denial");
        } else {
            // Unconnected UDP may report successful buffering before WFP's
            // asynchronous ALE decision. Observe delivery, not sendto alone.
            DWORD timeout = 500;
            require(setsockopt(listener.handle, SOL_SOCKET, SO_RCVTIMEO,
                               reinterpret_cast<const char*>(&timeout), sizeof(timeout)) == 0,
                    "Set blocked UDP observation deadline");
            char data{};
            const auto received = recv(listener.handle, &data, 1, 0);
            require(received == SOCKET_ERROR && WSAGetLastError() == WSAETIMEDOUT,
                    "Blocked UDP reached its listener");
        }
    } else {
        require(result != SOCKET_ERROR, "Unselected/released application lost connectivity");
        if (tcp) {
            const auto accepted = accept(listener.handle, nullptr, nullptr);
            require(accepted != INVALID_SOCKET, "Accept test connection");
            closesocket(accepted);
        } else {
            DWORD timeout = 1000;
            require(setsockopt(listener.handle, SOL_SOCKET, SO_RCVTIMEO,
                               reinterpret_cast<const char*>(&timeout), sizeof(timeout)) == 0,
                    "Set test receive deadline");
            char data{};
            require(recv(listener.handle, &data, 1, 0) == 1 && data == 'x', "UDP was not delivered");
        }
    }
    std::cout << "PASS " << (family == AF_INET ? "IPv4 " : "IPv6 ") << (tcp ? "TCP " : "UDP ")
              << (blocked ? "blocked" : "delivered") << '\n';
}

std::wstring executable() {
    std::array<wchar_t, 32768> path{};
    const auto size = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
    require(size != 0 && size < path.size(), "Read test executable path");
    return {path.data(), size};
}

void validateInputs() {
    const GUID id{0x769f6ad4, 0xda38, 0x4e85, {0x95, 0x98, 0xa7, 0xa7, 0xad, 0x23, 0x65, 0x89}};
    const auto rejected = [](GUID policy, const std::wstring& path) {
        try {
            AppImageBlock guard(policy, path);
        } catch (const std::invalid_argument&) {
            return true;
        }
        return false;
    };
    require(rejected({}, executable()), "Null policy ID accepted");
    require(rejected(id, L"relative.exe"), "Relative executable accepted");
    require(rejected(id, L"C:relative.exe"), "Drive-relative executable accepted");
    require(rejected(id, executable() + std::wstring(1, L'\0') + L"suffix"), "Embedded NUL accepted");
    AppImageBlock valid(id, executable()); // Construction never changes WFP policy.
    std::cout << "PASS policy input validation (no policy installed)" << std::endl;
}
} // namespace

int wmain(int argc, wchar_t** argv) {
    try {
        if (argc == 2 && std::wstring_view(argv[1]) == L"--self-test") {
            validateInputs();
            return 0;
        }
        require(argc == 3, "Usage: app_egress_guard_test --probe allowed|blocked OR "
                           "--live-arm-wait|--live-status|--live-release GUID");
        const std::wstring mode = argv[1];
        if (mode == L"--probe") {
            const std::wstring expected = argv[2];
            require(expected == L"allowed" || expected == L"blocked", "Invalid probe expectation");
            WSADATA data{};
            require(WSAStartup(MAKEWORD(2, 2), &data) == 0, "Start Winsock");
            struct Cleanup {
                ~Cleanup() { WSACleanup(); }
            } cleanup;
            for (const auto family : {AF_INET, AF_INET6}) {
                for (const auto tcp : {true, false}) {
                    probe(family, tcp, expected == L"blocked");
                }
            }
            return 0;
        }
        require(mode == L"--live-arm-wait" || mode == L"--live-status" || mode == L"--live-release",
                "Unknown command; no policy changed");
        GUID id{};
        require(UuidFromStringW(reinterpret_cast<RPC_WSTR>(argv[2]), &id) == RPC_S_OK, "Invalid policy ID");
        AppImageBlock guard(id, executable());
        if (mode == L"--live-release") {
            guard.release();
            require(!guard.installed(), "Guard remains after explicit release");
            std::cout << "PASS released" << std::endl;
            return 0;
        }
        if (mode == L"--live-status") {
            require(guard.installed(), "Guard is absent");
            std::cout << "PASS installed" << std::endl;
            return 0;
        }
        guard.arm();
        guard.arm(); // Reapplying the same policy must be idempotent.
        require(guard.installed(), "Guard missing after commit");
        std::cout << "ARMED" << std::endl;
        // The harness kills this exact process, then verifies kernel protection.
        // Do not release on exit, including this bounded fixture timeout.
        Sleep(60000);
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL: " << error.what() << std::endl;
        return 1;
    }
}
