#include "selection_transport.hpp"
#include "pairing_handoff.hpp"
#include "routing_control.hpp"
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
    return createSelectionPipe(suffix, ServiceOwner::fromToken(user_token));
}
std::unique_ptr<Handle> createSelectionPipe(std::wstring_view suffix, const ServiceOwner& owner) {
    if (suffix.empty() || suffix.size() > 80 ||
        suffix.find_first_not_of(L"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_") !=
            std::wstring_view::npos) {
        throw std::invalid_argument("Invalid local pipe identifier");
    }
    // Specific read/write rights exclude FILE_CREATE_PIPE_INSTANCE (0x4),
    // unlike GENERIC_WRITE. SYSTEM retains endpoint administration rights.
    const auto sddl = std::wstring(L"D:P(A;;GA;;;SY)(A;;0x0012019b;;;") + owner.sid() + L")";
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

namespace {
using HandoffAck = std::array<std::uint8_t, 8>;
constexpr HandoffAck handoff_ready{'S', 'K', 'P', 'A', 1, 0, 0, 0};
constexpr HandoffAck handoff_received{'S', 'K', 'P', 'A', 1, 1, 0, 0};
struct HandoffWire {
    std::array<std::uint8_t, 808> bytes{};
    ~HandoffWire() { SecureZeroMemory(bytes.data(), bytes.size()); }
};
ULONGLONG handoffDeadline(HANDLE cancel, DWORD timeout) {
    if (!timeout || timeout > 60000 || !cancel || cancel == INVALID_HANDLE_VALUE) {
        throw std::invalid_argument("Invalid pairing handoff budget");
    }
    return GetTickCount64() + timeout;
}
void handoffTransfer(HANDLE pipe, void* data, DWORD size, bool write, HANDLE cancel, ULONGLONG deadline) {
    Operation operation(pipe);
    if (operation.transfer(data, size, write, cancel, deadline) != size) {
        throw std::runtime_error("Incomplete pairing handoff message");
    }
}
void checkHandoffText(const std::string& text, size_t limit) {
    if (text.empty() || text.size() > limit ||
        std::any_of(text.begin(), text.end(), [](unsigned char c) { return c < 33 || c > 126; })) {
        throw std::invalid_argument("Invalid pairing handoff text");
    }
}
} // namespace

void sendPairingHandoff(HANDLE pipe, const std::wstring& service_name, const PairingHandoff& value,
                        HANDLE cancel, DWORD timeout_ms) {
    const auto deadline = handoffDeadline(cancel, timeout_ms);
    checkHandoffText(value.endpoint, 512);
    checkHandoffText(value.identity, 256);
    auto server = verifySelectionService(pipe, service_name);
    auto hello = encodeSelectionRequest(processKey(GetCurrentProcess(), GetCurrentProcessId()));
    handoffTransfer(pipe, hello.data(), hello.size(), true, cancel, deadline);
    HandoffAck ack{};
    handoffTransfer(pipe, ack.data(), ack.size(), false, cancel, deadline);
    if (ack != handoff_ready || WaitForSingleObject(server->get(), 0) != WAIT_TIMEOUT) {
        throw std::runtime_error("Pairing handoff not authorized");
    }
    HandoffWire wire;
    auto& bytes = wire.bytes;
    bytes[0] = 'S';
    bytes[1] = 'K';
    bytes[2] = 'P';
    bytes[3] = 1;
    bytes[4] = value.endpoint.size() & 255;
    bytes[5] = value.endpoint.size() >> 8;
    bytes[6] = value.identity.size() & 255;
    bytes[7] = value.identity.size() >> 8;
    std::copy(value.endpoint.begin(), value.endpoint.end(), bytes.begin() + 8);
    std::copy(value.identity.begin(), value.identity.end(), bytes.begin() + 520);
    std::copy(value.key.begin(), value.key.end(), bytes.begin() + 776);
    handoffTransfer(pipe, bytes.data(), bytes.size(), true, cancel, deadline);
    handoffTransfer(pipe, ack.data(), ack.size(), false, cancel, deadline);
    if (ack != handoff_received || WaitForSingleObject(server->get(), 0) != WAIT_TIMEOUT) {
        throw std::runtime_error("Pairing handoff not acknowledged");
    }
}

std::unique_ptr<PairingHandoff> receivePairingHandoff(HANDLE pipe, HANDLE owner_token, HANDLE cancel,
                                                      DWORD timeout_ms) {
    return receivePairingHandoff(pipe, ServiceOwner::fromToken(owner_token), cancel, timeout_ms);
}
std::unique_ptr<PairingHandoff> receivePairingHandoff(HANDLE pipe, const ServiceOwner& owner, HANDLE cancel,
                                                      DWORD timeout_ms) {
    const auto deadline = handoffDeadline(cancel, timeout_ms);
    SelectionRequest hello{};
    handoffTransfer(pipe, hello.data(), hello.size(), false, cancel, deadline);
    const auto key = decodeSelectionRequest(hello);
    ULONG actual_pid{};
    if (!GetNamedPipeClientProcessId(pipe, &actual_pid) || actual_pid != key.pid) {
        throw std::runtime_error("Pairing caller identity mismatch");
    }
    auto client = authorizePipeSelection(pipe, key);
    // The pipe ACL includes SYSTEM administration. Do not let that substitute
    // for the intended user's ownership at this credential boundary.
    ProcessTarget owner_bound(key, owner);
    auto ack = handoff_ready;
    handoffTransfer(pipe, ack.data(), ack.size(), true, cancel, deadline);
    HandoffWire wire;
    auto& bytes = wire.bytes;
    handoffTransfer(pipe, bytes.data(), bytes.size(), false, cancel, deadline);
    const size_t endpoint_size = bytes[4] | (unsigned(bytes[5]) << 8);
    const size_t identity_size = bytes[6] | (unsigned(bytes[7]) << 8);
    if (bytes[0] != 'S' || bytes[1] != 'K' || bytes[2] != 'P' || bytes[3] != 1 || endpoint_size > 512 ||
        identity_size > 256 ||
        std::any_of(bytes.begin() + 8 + endpoint_size, bytes.begin() + 520, [](auto b) { return b != 0; }) ||
        std::any_of(bytes.begin() + 520 + identity_size, bytes.begin() + 776,
                    [](auto b) { return b != 0; })) {
        throw std::runtime_error("Invalid pairing handoff envelope");
    }
    auto value = std::make_unique<PairingHandoff>();
    value->endpoint.assign(reinterpret_cast<const char*>(bytes.data() + 8), endpoint_size);
    value->identity.assign(reinterpret_cast<const char*>(bytes.data() + 520), identity_size);
    checkHandoffText(value->endpoint, 512);
    checkHandoffText(value->identity, 256);
    std::copy(bytes.begin() + 776, bytes.end(), value->key.begin());
    if (!client->running() || !owner_bound.running()) {
        throw std::runtime_error("Pairing caller exited during handoff");
    }
    ack = handoff_received;
    handoffTransfer(pipe, ack.data(), ack.size(), true, cancel, deadline);
    return value;
}

namespace {
void putGeneration(std::uint8_t* bytes, std::uint64_t generation) {
    for (unsigned i = 0; i < 8; ++i) {
        bytes[i] = static_cast<std::uint8_t>(generation >> (8 * i));
    }
}
std::uint64_t getGeneration(const std::uint8_t* bytes) {
    std::uint64_t result{};
    for (unsigned i = 0; i < 8; ++i) {
        result |= std::uint64_t(bytes[i]) << (8 * i);
    }
    return result;
}
} // namespace
void serveRoutingCommand(HANDLE pipe, HANDLE owner_token, HANDLE cancel, DWORD timeout_ms,
                         const RoutingHandler& handler) {
    serveRoutingCommand(pipe, ServiceOwner::fromToken(owner_token), cancel, timeout_ms, handler);
}
void serveRoutingCommand(HANDLE pipe, const ServiceOwner& owner, HANDLE cancel, DWORD timeout_ms,
                         const RoutingHandler& handler) {
    if (!handler) {
        throw std::invalid_argument("Missing routing handler");
    }
    const auto deadline = handoffDeadline(cancel, timeout_ms);
    std::array<std::uint8_t, 32> request{};
    handoffTransfer(pipe, request.data(), request.size(), false, cancel, deadline);
    const auto key = decodeSelectionRequest(std::span(request).first(20));
    if (request[20] != 'R' || request[21] != 1 || request[22] > 2 || request[23]) {
        throw std::invalid_argument("Invalid routing command");
    }
    ULONG actual_pid{};
    if (!GetNamedPipeClientProcessId(pipe, &actual_pid) || actual_pid != key.pid) {
        throw std::runtime_error("Routing caller identity mismatch");
    }
    auto client = authorizePipeSelection(pipe, key);
    ProcessTarget owner_bound(key, owner);
    if (!client->running() || !owner_bound.running()) {
        throw std::runtime_error("Routing caller exited");
    }
    const auto result = handler(static_cast<RoutingCommand>(request[22]), getGeneration(request.data() + 24));
    if (result.result > RoutingResult::Busy || result.phase > RoutingPhase::Failed) {
        throw std::logic_error("Invalid routing backend response");
    }
    std::array<std::uint8_t, 16> response{'S',
                                          'K',
                                          'R',
                                          'C',
                                          1,
                                          static_cast<std::uint8_t>(result.result),
                                          static_cast<std::uint8_t>(result.phase),
                                          0};
    putGeneration(response.data() + 8, result.generation);
    handoffTransfer(pipe, response.data(), response.size(), true, cancel, deadline);
}
RoutingReply exchangeRoutingCommand(HANDLE pipe, const std::wstring& service_name, RoutingCommand command,
                                    std::uint64_t generation, HANDLE cancel, DWORD timeout_ms) {
    if (command > RoutingCommand::Stop) {
        throw std::invalid_argument("Unknown routing command");
    }
    const auto deadline = handoffDeadline(cancel, timeout_ms);
    auto server = verifySelectionService(pipe, service_name);
    std::array<std::uint8_t, 32> request{};
    const auto identity = encodeSelectionRequest(processKey(GetCurrentProcess(), GetCurrentProcessId()));
    std::copy(identity.begin(), identity.end(), request.begin());
    request[20] = 'R';
    request[21] = 1;
    request[22] = static_cast<std::uint8_t>(command);
    putGeneration(request.data() + 24, generation);
    handoffTransfer(pipe, request.data(), request.size(), true, cancel, deadline);
    std::array<std::uint8_t, 16> response{};
    handoffTransfer(pipe, response.data(), response.size(), false, cancel, deadline);
    if (response[0] != 'S' || response[1] != 'K' || response[2] != 'R' || response[3] != 'C' ||
        response[4] != 1 || response[5] > 2 || response[6] > 5 || response[7] ||
        WaitForSingleObject(server->get(), 0) != WAIT_TIMEOUT) {
        throw std::runtime_error("Invalid routing response or exited service");
    }
    return {static_cast<RoutingResult>(response[5]), static_cast<RoutingPhase>(response[6]),
            getGeneration(response.data() + 8)};
}
} // namespace skewer::windows
