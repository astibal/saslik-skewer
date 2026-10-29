#include "routing_client.hpp"
#include <string_view>

namespace skewer::windows {
std::unique_ptr<Handle> connectRoutingService(const std::wstring& name, bool pairing, HANDLE cancel,
                                              DWORD timeout_ms) {
    if (name.empty() || name.size() > 80 ||
        name.find_first_not_of(L"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_") !=
            std::wstring::npos ||
        !timeout_ms || timeout_ms > 60000) {
        throw std::invalid_argument("Invalid routing service connection parameters");
    }
    const auto path = L"\\\\.\\pipe\\SkewerSelection-" + name + (pairing ? L"-pair" : L"");
    const auto deadline = GetTickCount64() + timeout_ms;
    for (;;) {
        if (WaitForSingleObject(cancel, 0) != WAIT_TIMEOUT) {
            throw std::runtime_error("Routing service connection cancelled");
        }
        auto pipe = std::make_unique<Handle>(CreateFileW(
            path.c_str(), FILE_GENERIC_READ | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA, 0,
            nullptr, OPEN_EXISTING, FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
            nullptr));
        if (*pipe) {
            DWORD mode = PIPE_READMODE_MESSAGE;
            if (!SetNamedPipeHandleState(pipe->get(), &mode, nullptr, nullptr)) {
                // Capture immediately: cleanup or formatting must not replace
                // the OS error needed to diagnose a disconnect/re-accept race.
                const auto error = GetLastError();
                throw std::runtime_error("Cannot configure routing pipe message mode (Win32 " +
                                         std::to_string(error) + ")");
            }
            // Reject a spoofed pipe before callers can send even a command.
            try {
                auto server = verifySelectionService(pipe->get(), name);
                return pipe;
            } catch (const std::runtime_error& error) {
                const std::string_view detail(error.what());
                if (detail != "Unexpected selection pipe server" &&
                    detail != "Selection service restarted during verification") {
                    throw;
                }
                // Disconnect/re-accept can briefly expose an endpoint that no
                // longer belongs to the current SCM generation. Send nothing,
                // close it, and retry within the caller's original budget.
                pipe.reset();
                if (GetTickCount64() >= deadline) throw;
                if (WaitForSingleObject(cancel, 20) != WAIT_TIMEOUT) {
                    throw std::runtime_error("Routing service connection cancelled");
                }
                continue;
            }
        }
        const auto error = GetLastError();
        if ((error != ERROR_PIPE_BUSY && error != ERROR_FILE_NOT_FOUND) || GetTickCount64() >= deadline) {
            throw std::runtime_error("Routing service unavailable (Win32 " +
                                     std::to_string(error) + ")");
        }
        if (WaitForSingleObject(cancel, 20) != WAIT_TIMEOUT) {
            throw std::runtime_error("Routing service connection cancelled");
        }
    }
}
} // namespace skewer::windows
