#include "selection_transport.hpp"
#include <stdexcept>
#include <type_traits>
#include <sddl.h>

namespace skewer::windows {
namespace {
class Operation {
public:
    explicit Operation(HANDLE pipe) : pipe_(pipe), event_(CreateEventW(nullptr, TRUE, FALSE, nullptr)) {
        if (!event_) {
            throw std::runtime_error("Cannot create pipe I/O event");
        }
        overlapped_.hEvent = event_.get();
    }
    ~Operation() {
        // Cancel then drain before either OVERLAPPED or the caller's buffer
        // goes away. Never close a handle with outstanding stack-backed I/O.
        if (pending_) {
            CancelIoEx(pipe_, &overlapped_);
            DWORD ignored{};
            GetOverlappedResult(pipe_, &overlapped_, &ignored, TRUE);
        }
    }
    void connect(HANDLE cancel, DWORD timeout_ms) {
        if (WaitForSingleObject(cancel, 0) != WAIT_TIMEOUT) {
            throw std::runtime_error("Selection accept cancelled");
        }
        if (ConnectNamedPipe(pipe_, &overlapped_)) {
            return;
        }
        const auto error = GetLastError();
        if (error == ERROR_PIPE_CONNECTED) {
            return;
        }
        if (error != ERROR_IO_PENDING) {
            throw std::runtime_error("Cannot accept selection client");
        }
        pending_ = true;
        const HANDLE events[]{cancel, event_.get()};
        if (WaitForMultipleObjects(2, events, FALSE, timeout_ms) != WAIT_OBJECT_0 + 1) {
            throw std::runtime_error("Selection accept cancelled or timed out");
        }
        DWORD ignored{};
        const auto completed = GetOverlappedResult(pipe_, &overlapped_, &ignored, FALSE);
        pending_ = false;
        if (!completed || WaitForSingleObject(cancel, 0) != WAIT_TIMEOUT) {
            throw std::runtime_error("Selection accept failed or cancelled");
        }
    }
    DWORD transfer(void* buffer, DWORD size, bool write, HANDLE cancel, ULONGLONG deadline) {
        if (WaitForSingleObject(cancel, 0) != WAIT_TIMEOUT || GetTickCount64() >= deadline) {
            throw std::runtime_error("Selection transport cancelled or timed out");
        }
        DWORD transferred{};
        const BOOL ok = write ? WriteFile(pipe_, buffer, size, &transferred, &overlapped_)
                              : ReadFile(pipe_, buffer, size, &transferred, &overlapped_);
        if (!ok) {
            if (GetLastError() != ERROR_IO_PENDING) {
                // Includes ERROR_MORE_DATA: oversized messages are never split
                // into subsequent requests, even if their prefix looks valid.
                throw std::runtime_error("Selection pipe I/O failed");
            }
            pending_ = true;
            const auto now = GetTickCount64();
            const DWORD remaining = now >= deadline ? 0 : static_cast<DWORD>(deadline - now);
            const HANDLE events[]{cancel, event_.get()};
            if (WaitForMultipleObjects(2, events, FALSE, remaining) != WAIT_OBJECT_0 + 1) {
                throw std::runtime_error("Selection transport cancelled or timed out");
            }
            const BOOL completed = GetOverlappedResult(pipe_, &overlapped_, &transferred, FALSE);
            pending_ = false;
            if (!completed) {
                throw std::runtime_error("Selection pipe completion failed");
            }
        }
        if (WaitForSingleObject(cancel, 0) != WAIT_TIMEOUT || GetTickCount64() >= deadline) {
            throw std::runtime_error("Selection transport cancelled or timed out");
        }
        return transferred;
    }

private:
    HANDLE pipe_;
    Handle event_;
    OVERLAPPED overlapped_{};
    bool pending_{};
};
} // namespace

std::unique_ptr<Handle> createSelectionPipe(std::wstring_view suffix, HANDLE user_token) {
    if (suffix.empty() || suffix.size() > 80 ||
        suffix.find_first_not_of(L"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_") !=
            std::wstring_view::npos) {
        throw std::invalid_argument("Invalid local pipe identifier");
    }
    DWORD size{};
    GetTokenInformation(user_token, TokenUser, nullptr, 0, &size);
    if (!size || size > 65536) {
        throw std::invalid_argument("Cannot query pipe owner token");
    }
    std::vector<unsigned char> storage(size);
    if (!GetTokenInformation(user_token, TokenUser, storage.data(), size, &size)) {
        throw std::runtime_error("Cannot read pipe owner token");
    }
    LPWSTR raw_sid{};
    if (!ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(storage.data())->User.Sid, &raw_sid)) {
        throw std::runtime_error("Cannot encode pipe owner SID");
    }
    std::unique_ptr<wchar_t, decltype(&LocalFree)> sid(raw_sid, LocalFree);
    // Specific read/write rights exclude FILE_CREATE_PIPE_INSTANCE (0x4),
    // unlike GENERIC_WRITE. SYSTEM retains endpoint administration rights.
    const auto sddl = std::wstring(L"D:P(A;;GA;;;SY)(A;;0x0012019b;;;") + sid.get() + L")";
    PSECURITY_DESCRIPTOR raw_descriptor{};
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &raw_descriptor,
                                                              nullptr)) {
        throw std::runtime_error("Cannot build selection pipe ACL");
    }
    std::unique_ptr<void, decltype(&LocalFree)> descriptor(raw_descriptor, LocalFree);
    SECURITY_ATTRIBUTES attributes{sizeof(attributes), descriptor.get(), FALSE};
    const auto name = std::wstring(L"\\\\.\\pipe\\SkewerSelection-") + std::wstring(suffix);
    auto pipe = std::make_unique<Handle>(CreateNamedPipeW(
        name.c_str(), PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, 1, 128, 128, 0,
        &attributes));
    if (!*pipe) {
        throw std::runtime_error("Cannot create exclusive selection pipe");
    }
    return pipe;
}

void acceptSelection(HANDLE pipe, HANDLE cancel, DWORD timeout_ms) {
    if (!timeout_ms || timeout_ms > 60000 || !cancel || cancel == INVALID_HANDLE_VALUE) {
        throw std::invalid_argument("Invalid selection accept budget or cancellation event");
    }
    Operation accept(pipe);
    accept.connect(cancel, timeout_ms);
}

std::unique_ptr<Handle> verifySelectionServer(HANDLE pipe, ProcessKey expected) {
    DWORD flags{};
    ULONG pid{};
    if (!expected.pid || !expected.created || !GetNamedPipeInfo(pipe, &flags, nullptr, nullptr, nullptr) ||
        (flags & PIPE_SERVER_END) || !GetNamedPipeServerProcessId(pipe, &pid) || pid != expected.pid) {
        throw std::runtime_error("Unexpected selection pipe server");
    }
    auto process =
        std::make_unique<Handle>(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, pid));
    if (!*process || processKey(process->get(), pid) != expected ||
        WaitForSingleObject(process->get(), 0) != WAIT_TIMEOUT) {
        throw std::runtime_error("Selection server identity is stale or inaccessible");
    }
    return process;
}

std::unique_ptr<Handle> verifySelectionService(HANDLE pipe, const std::wstring& service_name) {
    if (service_name.empty() || service_name.size() > 256 || service_name.find(L'\0') != std::wstring::npos ||
        service_name.find_first_of(L"/\\") != std::wstring::npos) {
        throw std::invalid_argument("Invalid selection service name");
    }
    // SCM handles require CloseServiceHandle, not CloseHandle.
    struct ServiceCloser {
        void operator()(SC_HANDLE handle) const { CloseServiceHandle(handle); }
    };
    using ServiceHandle = std::unique_ptr<std::remove_pointer_t<SC_HANDLE>, ServiceCloser>;
    ServiceHandle manager(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (!manager) {
        throw std::runtime_error("Cannot query service manager");
    }
    ServiceHandle service(OpenServiceW(manager.get(), service_name.c_str(), SERVICE_QUERY_STATUS));
    if (!service) {
        throw std::runtime_error("Cannot query selection service");
    }
    const auto status = [&] {
        SERVICE_STATUS_PROCESS value{};
        DWORD needed{};
        if (!QueryServiceStatusEx(service.get(), SC_STATUS_PROCESS_INFO, reinterpret_cast<BYTE*>(&value),
                                  sizeof(value), &needed) ||
            value.dwCurrentState != SERVICE_RUNNING || value.dwServiceType != SERVICE_WIN32_OWN_PROCESS ||
            !value.dwProcessId) {
            throw std::runtime_error("Selection service is not running in its own process");
        }
        return value.dwProcessId;
    };
    const auto pid = status();
    Handle candidate(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, pid));
    if (!candidate) {
        throw std::runtime_error("Cannot pin selection service process");
    }
    auto process = verifySelectionServer(pipe, processKey(candidate.get(), pid));
    if (status() != pid || WaitForSingleObject(process->get(), 0) != WAIT_TIMEOUT) {
        throw std::runtime_error("Selection service restarted during verification");
    }
    return process;
}

SelectionResult serveSelection(HANDLE pipe, HANDLE cancel, DWORD timeout_ms) {
    if (!timeout_ms || timeout_ms > 60000 || !cancel || cancel == INVALID_HANDLE_VALUE) {
        throw std::invalid_argument("Selection requires a cancellation event and a 1..60000 ms budget");
    }
    const auto deadline = GetTickCount64() + timeout_ms;
    SelectionRequest request{};
    DWORD received{};
    {
        Operation read(pipe);
        received = read.transfer(request.data(), request.size(), false, cancel, deadline);
    }
    auto result = processSelectionRequest(pipe, std::span(request).first(received));
    {
        Operation write(pipe);
        if (write.transfer(result.reply.data(), result.reply.size(), true, cancel, deadline) !=
            result.reply.size()) {
            throw std::runtime_error("Incomplete selection reply");
        }
    }
    // Do not FlushFileBuffers: a peer that never reads must not block shutdown.
    return result;
}

namespace {
SelectionReply exchangeRequest(HANDLE pipe, const std::wstring& service_name, SelectionRequest request,
                               HANDLE cancel, DWORD timeout_ms) {
    if (!timeout_ms || timeout_ms > 60000 || !cancel || cancel == INVALID_HANDLE_VALUE) {
        throw std::invalid_argument("Invalid client exchange budget or cancellation event");
    }
    const auto deadline = GetTickCount64() + timeout_ms;
    auto server = verifySelectionService(pipe, service_name);
    {
        Operation write(pipe);
        if (write.transfer(request.data(), request.size(), true, cancel, deadline) != request.size()) {
            throw std::runtime_error("Incomplete selection request");
        }
    }
    SelectionReply reply{};
    {
        Operation read(pipe);
        if (read.transfer(reply.data(), reply.size(), false, cancel, deadline) != reply.size()) {
            throw std::runtime_error("Incomplete selection reply");
        }
    }
    if (WaitForSingleObject(server->get(), 0) != WAIT_TIMEOUT) {
        throw std::runtime_error("Selection service exited during exchange");
    }
    return reply;
}
} // namespace

SelectionStatus exchangeSelection(HANDLE pipe, const std::wstring& service_name, ProcessKey target,
                                  HANDLE cancel, DWORD timeout_ms) {
    return decodeSelectionReply(
        exchangeRequest(pipe, service_name, encodeSelectionRequest(target), cancel, timeout_ms));
}

SelectionStatus exchangeScopeProbe(HANDLE pipe, const std::wstring& service_name,
                                   skewer::traffic::RoutingScope scope, HANDLE cancel, DWORD timeout_ms) {
    const auto caller = processKey(GetCurrentProcess(), GetCurrentProcessId());
    return decodeScopeReply(
        exchangeRequest(pipe, service_name, encodeScopeProbe(caller, scope), cancel, timeout_ms));
}

void finishSelection(HANDLE pipe, HANDLE cancel, DWORD timeout_ms) {
    if (!timeout_ms || timeout_ms > 60000) {
        throw std::invalid_argument("Invalid selection finish budget");
    }
    std::uint8_t unexpected{};
    try {
        Operation read(pipe);
        read.transfer(&unexpected, 1, false, cancel, GetTickCount64() + timeout_ms);
    } catch (const std::runtime_error&) {
        // Peer close, cancellation, timeout or I/O failure all retire this
        // connection. There is deliberately no second request on the stream.
    }
}
} // namespace skewer::windows
