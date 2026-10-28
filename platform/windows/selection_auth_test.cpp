#include "processes.hpp"
#include "selection_auth.hpp"
#include "selection_request.hpp"
#include "selection_transport.hpp"
#include "pairing_handoff.hpp"
#include <sddl.h>
#include <iostream>
#include <stdexcept>
#include <future>

namespace {
using namespace skewer::windows;
void require(bool ok, const char* message) {
    if (!ok) {
        throw std::runtime_error(message);
    }
}
template <typename Action> void rejects(Action action, const char* message) {
    bool rejected{};
    try {
        action();
    } catch (const std::exception&) {
        rejected = true;
    }
    require(rejected, message);
}
void malformedHandoffTest() {
    HANDLE raw{};
    require(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw), "Open handoff test token");
    Handle token(raw);
    const auto key = processKey(GetCurrentProcess(), GetCurrentProcessId());
    for (unsigned scenario = 0; scenario < 3; ++scenario) {
        const auto suffix =
            L"MalformedHandoff-" + std::to_wstring(key.pid) + L"-" + std::to_wstring(scenario);
        auto server = createSelectionPipe(suffix, token.get());
        const auto path = L"\\\\.\\pipe\\SkewerSelection-" + suffix;
        Handle client(CreateFileW(
            path.c_str(), FILE_GENERIC_READ | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA, 0,
            nullptr, OPEN_EXISTING, SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, nullptr));
        require(bool(client), "Connect handoff test client");
        Handle cancel(CreateEventW(nullptr, TRUE, FALSE, nullptr));
        require(bool(cancel), "Create handoff test cancellation");
        acceptSelection(server->get(), cancel.get(), 1000);
        auto receiver = std::async(std::launch::async, [&] {
            return receivePairingHandoff(server->get(), token.get(), cancel.get(), 1000);
        });
        auto hello = encodeSelectionRequest(key);
        DWORD count{};
        require(WriteFile(client.get(), hello.data(), hello.size(), &count, nullptr), "Send handoff hello");
        std::array<std::uint8_t, 8> ack{};
        require(ReadFile(client.get(), ack.data(), ack.size(), &count, nullptr) && count == ack.size(),
                "Read handoff authorization");
        std::array<std::uint8_t, 808> bytes{};
        bytes[0] = 'S';
        bytes[1] = 'K';
        bytes[2] = 'P';
        bytes[3] = 1;
        bytes[4] = 1;
        bytes[6] = 1;
        bytes[8] = 'e';
        bytes[520] = 'i';
        if (scenario == 1) {
            bytes[3] = 2;
        }
        if (scenario == 2) {
            bytes[9] = 1;
        }
        const DWORD size = scenario == 0 ? 807 : 808;
        require(WriteFile(client.get(), bytes.data(), size, &count, nullptr), "Send malformed handoff");
        rejects([&] { (void)receiver.get(); }, "Malformed handoff accepted");
    }
}
void transportTest() {
    const auto key = processKey(GetCurrentProcess(), GetCurrentProcessId());
    for (unsigned scenario = 0; scenario < 7; ++scenario) {
        const auto name = L"\\\\.\\pipe\\SkewerTransportFixture-" + std::to_wstring(key.pid) + L"-" +
                          std::to_wstring(scenario);
        PSECURITY_DESCRIPTOR raw{};
        require(ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;;GA;;;SY)(A;;GRGW;;;OW)",
                                                                     SDDL_REVISION_1, &raw, nullptr),
                "Pipe ACL");
        std::shared_ptr<void> descriptor(raw, [](void* p) { LocalFree(p); });
        SECURITY_ATTRIBUTES security{sizeof(security), raw, FALSE};
        Handle server(CreateNamedPipeW(
            name.c_str(), PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, 1, 128, 128,
            0, &security));
        require(static_cast<bool>(server), "Create transport pipe");
        Handle client(CreateFileW(name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
                                  SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, nullptr));
        require(static_cast<bool>(client), "Connect transport client");
        Handle event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
        OVERLAPPED connection{};
        connection.hEvent = event.get();
        require(ConnectNamedPipe(server.get(), &connection) || GetLastError() == ERROR_PIPE_CONNECTED,
                "Accept transport client");
        Handle cancel(CreateEventW(nullptr, TRUE, scenario == 2, nullptr));
        require(static_cast<bool>(cancel), "Create cancellation event");
        if (scenario == 0) {
            PairingHandoff value;
            value.endpoint = "skewer://127.0.0.1:18767/pair";
            value.identity = "public-test";
            value.key.fill(0x5a);
            rejects(
                [&] {
                    sendPairingHandoff(client.get(), L"SkewerAbsentServiceFixture", value, cancel.get(), 50);
                },
                "Non-SCM server received credentials");
            DWORD available{};
            require(PeekNamedPipe(server.get(), nullptr, 0, nullptr, &available, nullptr) && !available,
                    "Client wrote before authenticating server");
        }
        if (scenario != 1 && scenario != 2) {
            const auto encoded =
                scenario >= 5
                    ? encodeScopeProbe(key, scenario == 5 ? skewer::traffic::RoutingScope::Applications
                                                          : skewer::traffic::RoutingScope::WholeHost)
                    : encodeSelectionRequest(key);
            auto bytes = std::vector<std::uint8_t>(encoded.begin(), encoded.end());
            if (scenario == 3) {
                bytes.push_back(0);
            }
            if (scenario == 4) {
                bytes.pop_back();
            }
            DWORD count{};
            require(WriteFile(client.get(), bytes.data(), bytes.size(), &count, nullptr) &&
                        count == bytes.size(),
                    "Send transport request");
        }
        if (scenario >= 1 && scenario <= 3) {
            rejects([&] { serveSelection(server.get(), cancel.get(), 50); },
                    "Idle, cancelled or oversized request accepted");
            continue;
        }
        auto result = serveSelection(server.get(), cancel.get(), 2000);
        const auto expected = scenario >= 5   ? SelectionStatus::ScopeUnsupported
                              : scenario == 0 ? SelectionStatus::Verified
                                              : SelectionStatus::InvalidRequest;
        require(decodeSelectionReply(result.reply) == expected && bool(result.target) == (scenario == 0),
                "Wrong transport result");
        SelectionReply reply{};
        DWORD count{};
        require(ReadFile(client.get(), reply.data(), reply.size(), &count, nullptr) &&
                    count == reply.size() && decodeSelectionReply(reply) == expected,
                "Transport reply lost");
    }
}
void listenerTest() {
    HANDLE raw{};
    require(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw), "Listener token");
    Handle token(raw);
    Handle cancel(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    require(static_cast<bool>(cancel), "Listener cancel event");
    const auto suffix = L"Test-" + std::to_wstring(GetCurrentProcessId());
    rejects([&] { createSelectionPipe(L"../unsafe", token.get()); }, "Unsafe name accepted");
    {
        auto pipe = createSelectionPipe(suffix, token.get());
        rejects([&] { createSelectionPipe(suffix, token.get()); }, "Duplicate server accepted");
        rejects([&] { acceptSelection(pipe->get(), cancel.get(), 25); }, "Idle accept did not time out");
    }
    {
        auto pipe = createSelectionPipe(suffix, token.get());
        SetEvent(cancel.get());
        rejects([&] { acceptSelection(pipe->get(), cancel.get(), 100); }, "Cancelled accept succeeded");
        ResetEvent(cancel.get());
    }
    auto pipe = createSelectionPipe(suffix, token.get());
    const auto name = L"\\\\.\\pipe\\SkewerSelection-" + suffix;
    Handle client(
        CreateFileW(name.c_str(), FILE_GENERIC_READ | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA,
                    0, nullptr, OPEN_EXISTING, SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, nullptr));
    require(static_cast<bool>(client), "Connect ACL-restricted listener");
    acceptSelection(pipe->get(), cancel.get(), 1000);
    const auto key = processKey(GetCurrentProcess(), GetCurrentProcessId());
    auto server_identity = verifySelectionServer(client.get(), key);
    require(WaitForSingleObject(server_identity->get(), 0) == WAIT_TIMEOUT, "Server pin lost");
    auto stale_server = key;
    ++stale_server.created;
    rejects([&] { verifySelectionServer(client.get(), stale_server); }, "Stale server accepted");
    auto wrong_server = key;
    wrong_server.pid ^= 1;
    rejects([&] { verifySelectionServer(client.get(), wrong_server); }, "Different server accepted");
    rejects([&] { verifySelectionServer(pipe->get(), key); }, "Server-side endpoint accepted");
    rejects([&] { verifySelectionService(client.get(), L"SkewerMissingService-Test"); },
            "Unregistered service accepted");
    rejects([&] { verifySelectionService(client.get(), L"bad/name"); }, "Invalid service name accepted");
    const auto request = encodeSelectionRequest(key);
    DWORD count{};
    require(WriteFile(client.get(), request.data(), request.size(), &count, nullptr) &&
                count == request.size(),
            "Write listener request");
    auto result = serveSelection(pipe->get(), cancel.get(), 1000);
    require(result.target && result.target->key() == key, "Listener selection failed");
    SelectionReply reply{};
    require(ReadFile(client.get(), reply.data(), reply.size(), &count, nullptr) && count == reply.size() &&
                decodeSelectionReply(reply) == SelectionStatus::Verified,
            "Listener reply failed");
}
void test() {
    const auto key = processKey(GetCurrentProcess(), GetCurrentProcessId());
    HANDLE raw{};
    require(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &raw), "Open test token");
    Handle primary(raw);
    ProcessTarget own(key, primary.get());
    require(own.running() && own.key() == key, "Primary token selection failed");
    HANDLE identified{};
    require(DuplicateTokenEx(primary.get(), TOKEN_QUERY, nullptr, SecurityIdentification, TokenImpersonation,
                             &identified),
            "Create identification token");
    {
        Handle token(identified);
        ProcessTarget selected(key, token.get());
        require(selected.running(), "Identification-level selection failed");
    }
    rejects([&] { ProcessTarget target(key, nullptr); }, "Null token accepted");
    rejects([&] { ProcessTarget target(key, INVALID_HANDLE_VALUE); }, "Invalid token accepted");
    rejects([&] { ProcessTarget target(key, GetCurrentProcess()); }, "Process handle accepted as token");
    auto stale = key;
    ++stale.created;
    rejects([&] { ProcessTarget target(stale, primary.get()); }, "Stale identity accepted");
    HANDLE anonymous{};
    require(DuplicateTokenEx(primary.get(), TOKEN_QUERY, nullptr, SecurityAnonymous, TokenImpersonation,
                             &anonymous),
            "Create anonymous token");
    Handle anonymous_token(anonymous);
    rejects([&] { ProcessTarget target(key, anonymous_token.get()); }, "Anonymous token accepted");
    // Handle lifetime is independent of the borrowed authorization token.
    require(own.running(), "Pinned process was lost");
}
void requestTest() {
    for (auto status : {SelectionStatus::Verified, SelectionStatus::InvalidRequest, SelectionStatus::Denied,
                        SelectionStatus::ScopeUnsupported}) {
        const auto reply = encodeSelectionReply(status);
        require(decodeSelectionReply(reply) == status, "Reply status changed");
        if (status == SelectionStatus::Verified) {
            rejects([&] { decodeScopeReply(reply); }, "Process verification granted routing capability");
        } else {
            require(decodeScopeReply(reply) == status, "Scope failure status changed");
        }
        for (std::size_t size = 0; size < reply.size(); ++size) {
            rejects([&] { decodeSelectionReply(std::span(reply).first(size)); }, "Short reply accepted");
        }
        for (unsigned i = 0; i < reply.size(); ++i) {
            auto bad = reply;
            bad[i] = 0xff;
            rejects([&] { decodeSelectionReply(bad); }, "Invalid reply accepted");
        }
    }
    auto malformed = processSelectionRequest(INVALID_HANDLE_VALUE, {});
    require(!malformed.target && decodeSelectionReply(malformed.reply) == SelectionStatus::InvalidRequest,
            "Malformed request reached authorization");
    const ProcessKey key{0x12345678, 0x123456789abcdef0ULL};
    for (auto scope :
         {skewer::traffic::RoutingScope::Applications, skewer::traffic::RoutingScope::WholeHost}) {
        const auto probe = encodeScopeProbe(key, scope);
        const auto decoded = decodeScopeProbe(probe);
        require(decoded.caller == key && decoded.scope == scope, "Scope probe changed");
        rejects([&] { decodeSelectionRequest(probe); }, "Scope probe became process selection");
        for (std::size_t length = 0; length < probe.size(); ++length) {
            rejects([&] { decodeScopeProbe(std::span(probe).first(length)); }, "Short probe accepted");
        }
        auto malformed_probe = probe;
        malformed_probe[7] = 2;
        auto rejected = processSelectionRequest(INVALID_HANDLE_VALUE, malformed_probe);
        require(decodeSelectionReply(rejected.reply) == SelectionStatus::InvalidRequest && !rejected.target,
                "Invalid scope reached authentication");
        auto extended_probe = std::vector<std::uint8_t>(probe.begin(), probe.end());
        extended_probe.push_back(0);
        rejects([&] { decodeScopeProbe(extended_probe); }, "Extended probe accepted");
    }
    const auto encoded = encodeSelectionRequest(key);
    require(encoded[8] == 0x78 && encoded[11] == 0x12 && encoded[12] == 0xf0 && encoded[19] == 0x12,
            "Incorrect wire byte order");
    require(decodeSelectionRequest(encoded) == key, "Request identity changed");
    for (std::size_t size = 0; size < encoded.size(); ++size) {
        rejects([&] { decodeSelectionRequest(std::span(encoded).first(size)); },
                "Truncated request accepted");
    }
    auto extended = std::vector<std::uint8_t>(encoded.begin(), encoded.end());
    extended.push_back(0);
    rejects([&] { decodeSelectionRequest(extended); }, "Trailing bytes accepted");
    for (unsigned i = 0; i < 8; ++i) {
        auto bad = encoded;
        bad[i] ^= 0xff;
        rejects([&] { decodeSelectionRequest(bad); }, "Unknown header accepted");
    }
    for (const auto invalid : {ProcessKey{0, 1}, ProcessKey{1, 0}}) {
        rejects([&] { encodeSelectionRequest(invalid); }, "Incomplete identity encoded");
        auto bad = encoded;
        const unsigned begin = invalid.pid ? 12 : 8;
        const unsigned end = invalid.pid ? 20 : 12;
        for (unsigned i = begin; i < end; ++i) {
            bad[i] = 0;
        }
        rejects([&] { decodeSelectionRequest(bad); }, "Incomplete wire identity accepted");
    }
}
void pipeTest(const ProcessKey* foreign = nullptr) {
    const auto key = processKey(GetCurrentProcess(), GetCurrentProcessId());
    const auto name = L"\\\\.\\pipe\\SkewerAuthFixture-" + std::to_wstring(key.pid) + L"-" +
                      std::to_wstring(GetTickCount64());
    PSECURITY_DESCRIPTOR raw{};
    require(ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;;GA;;;SY)(A;;GRGW;;;OW)",
                                                                 SDDL_REVISION_1, &raw, nullptr),
            "Create fixture pipe ACL");
    std::shared_ptr<void> descriptor(raw, [](void* value) { LocalFree(value); });
    SECURITY_ATTRIBUTES security{sizeof(security), raw, FALSE};
    Handle server(
        CreateNamedPipeW(name.c_str(), PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                         PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                         1, 64, 64, 3000, &security));
    require(static_cast<bool>(server), "Create local fixture pipe");
    Handle client(CreateFileW(name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
                              SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, nullptr));
    require(static_cast<bool>(client), "Connect identification-level client");
    require(ConnectNamedPipe(server.get(), nullptr) || GetLastError() == ERROR_PIPE_CONNECTED,
            "Accept local client");
    const auto request = encodeSelectionRequest(key);
    DWORD transferred{};
    require(WriteFile(client.get(), request.data(), request.size(), &transferred, nullptr) &&
                transferred == request.size(),
            "Write fixture request");
    SelectionRequest received{};
    require(ReadFile(server.get(), received.data(), received.size(), &transferred, nullptr) &&
                transferred == received.size(),
            "Read fixture request");
    auto selected = authorizePipeSelection(server.get(), decodeSelectionRequest(received));
    require(selected->running() && selected->key() == key, "Pipe identity did not authorize its process");
    auto result = processSelectionRequest(server.get(), received);
    require(result.target && result.target->key() == key && result.target->running() &&
                decodeSelectionReply(result.reply) == SelectionStatus::Verified,
            "Dispatcher did not retain verified target");
    require(WriteFile(server.get(), result.reply.data(), result.reply.size(), &transferred, nullptr) &&
                transferred == result.reply.size(),
            "Write selection reply");
    SelectionReply reply{};
    require(ReadFile(client.get(), reply.data(), reply.size(), &transferred, nullptr) &&
                transferred == reply.size() && decodeSelectionReply(reply) == SelectionStatus::Verified,
            "Client did not receive verified reply");
    auto stale = key;
    ++stale.created;
    auto denied = processSelectionRequest(server.get(), encodeSelectionRequest(stale));
    require(!denied.target && decodeSelectionReply(denied.reply) == SelectionStatus::Denied,
            "Stale request reported success");
    rejects([&] { authorizePipeSelection(server.get(), stale); }, "Pipe accepted stale process");
    rejects([&] { authorizePipeSelection(client.get(), key); }, "Client handle accepted as server");
    if (foreign) {
        auto other = processSelectionRequest(server.get(), encodeSelectionRequest(*foreign));
        require(!other.target && decodeSelectionReply(other.reply) == SelectionStatus::Denied,
                "Dispatcher accepted foreign process");
        rejects([&] { authorizePipeSelection(server.get(), *foreign); }, "Foreign-user process accepted");
    }
    HANDLE token{};
    const bool impersonating = OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &token) != FALSE;
    const auto error = GetLastError();
    Handle unexpected(token);
    require(!impersonating && error == ERROR_NO_TOKEN, "Authorization leaked impersonation");
}
} // namespace
int main(int argc, char** argv) {
    try {
        HANDLE raw{};
        require(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw), "Open stable owner token");
        std::wstring owner_text;
        {
            Handle token(raw);
            owner_text = ServiceOwner::fromToken(token.get()).sid();
        }
        const ServiceOwner owner(owner_text);
        const auto self = processKey(GetCurrentProcess(), GetCurrentProcessId());
        ProcessTarget persistent(self, owner);
        require(persistent.running(), "Stable owner failed after source token closed");
        const ServiceOwner other(owner_text == L"S-1-5-18" ? L"S-1-5-19" : L"S-1-5-18");
        rejects([&] { ProcessTarget denied(self, other); }, "Foreign configured owner accepted");
        for (const auto* invalid : {L"", L"SY", L"S-1-5-18)(A;;GA;;;WD)", L"not-a-sid"}) {
            rejects([&] { ServiceOwner bad(invalid); }, "Invalid configured SID accepted");
        }
        test();
        requestTest();
        transportTest();
        malformedHandoffTest();
        listenerTest();
        if (argc == 1) {
            pipeTest();
        } else {
            require(argc == 3 && std::string(argv[1]) == "--foreign", "Invalid test arguments");
            const std::string number(argv[2]);
            require(!number.empty() && number.find_first_not_of("0123456789") == std::string::npos,
                    "Invalid foreign PID");
            const auto value = std::stoull(number);
            require(value > 0 && value <= MAXDWORD && value != GetCurrentProcessId(),
                    "Foreign PID out of range");
            const auto pid = static_cast<DWORD>(value);
            Handle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, pid));
            require(static_cast<bool>(process), "Cannot inspect foreign fixture");
            const auto foreign = processKey(process.get(), pid);
            pipeTest(&foreign);
            std::cout << "PASS: pipe client cannot select the foreign-user service fixture\n";
        }
        std::cout << "PASS: authenticated token selection and invalid/stale/anonymous rejection\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
