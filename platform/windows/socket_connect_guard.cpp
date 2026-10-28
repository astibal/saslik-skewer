#include "socket_connect_guard.hpp"
#include "windivert_api.hpp"
#include <bit>
#include <vector>
#include <system_error>

namespace skewer::windows::traffic {
namespace {
[[noreturn]] void fail(const char* operation) {
    throw std::system_error(static_cast<int>(GetLastError()), std::system_category(), operation);
}
template <typename T> T resolve(HMODULE module, const char* name) {
    const auto symbol = GetProcAddress(module, name);
    if (!symbol) {
        fail(name);
    }
    return std::bit_cast<T>(symbol);
}
} // namespace
class SocketConnectGuard::Impl final {
public:
    Impl(const std::wstring& dll, const ProcessTarget& target, Mode mode) {
        const bool drive =
            !dll.empty() && ((dll[0] >= L'A' && dll[0] <= L'Z') || (dll[0] >= L'a' && dll[0] <= L'z'));
        if (!drive || dll.size() < 4 || dll[1] != L':' || dll[2] != L'\\' ||
            dll.find(L'\0') != std::wstring::npos ||
            (mode != Mode::All && mode != Mode::UnsupportedForIpv4Tcp)) {
            throw std::invalid_argument("Invalid socket guard configuration");
        }
        if (!target.running()) {
            throw std::runtime_error("Socket guard target exited");
        }
        const auto module = LoadLibraryExW(dll.c_str(), nullptr,
                                           LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (!module) {
            fail("Load socket guard DLL");
        }
        library_ =
            std::shared_ptr<void>(module, [](void* value) { FreeLibrary(static_cast<HMODULE>(value)); });
        const auto open = resolve<decltype(&WinDivertOpen)>(module, "WinDivertOpen");
        close_ = resolve<decltype(&WinDivertClose)>(module, "WinDivertClose");
        const auto base = "processId == " + std::to_string(target.key().pid) + " and event == CONNECT";
        // SOCKET ipv6 predicates did not block IPv6 TCP in the 2.2.2 VM
        // regression. Match the normalized endpoint outside the IPv4-mapped
        // range instead; verify both rejection and preserved IPv4 TCP in tests.
        const std::vector<std::string> filters =
            mode == Mode::All ? std::vector<std::string>{base}
                              : std::vector<std::string>{
                                    base + " and (remoteAddr < ::ffff:0:0 or remoteAddr > ::ffff:ffff:ffff)",
                                    base + " and protocol != TCP"};
        handles_.reserve(filters.size());
        try {
            for (const auto& filter : filters) {
                const auto handle = open(filter.c_str(), WINDIVERT_LAYER_SOCKET, 0,
                                         WINDIVERT_FLAG_DROP | WINDIVERT_FLAG_RECV_ONLY);
                if (handle == INVALID_HANDLE_VALUE) {
                    fail("Open socket attempt guard");
                }
                handles_.push_back(handle);
            }
            if (!target.running()) {
                throw std::runtime_error("Socket guard target exited during setup");
            }
        } catch (...) {
            for (const auto handle : handles_) {
                close_(handle);
            }
            throw;
        }
    }
    ~Impl() {
        for (const auto handle : handles_) {
            close_(handle);
        }
    }

private:
    std::shared_ptr<void> library_;
    decltype(&WinDivertClose) close_{};
    std::vector<HANDLE> handles_;
};
SocketConnectGuard::SocketConnectGuard(const std::wstring& dll, const ProcessTarget& target, Mode mode)
    : impl_(std::make_unique<Impl>(dll, target, mode)) {}
SocketConnectGuard::~SocketConnectGuard() = default;
} // namespace skewer::windows::traffic
