#include <winsock2.h>
#include <ws2tcpip.h>
#include "flow_tracking.hpp"
#include <rpc.h>
#include <array>
#include <chrono>
#include <iostream>
#include <stdexcept>

namespace {
using namespace skewer::windows;
using namespace skewer::windows::traffic;

void require(bool value, const char* message) {
    if (!value) {
        throw std::runtime_error(message);
    }
}

class Socket final {
public:
    Socket(int family, int type) : value(socket(family, type, 0)) {
        require(value != INVALID_SOCKET, "Create traffic fixture socket");
    }
    ~Socket() { closesocket(value); }
    Socket(const Socket&) = delete;
    Socket& operator=(const Socket&) = delete;
    SOCKET value;
};

void sendLoopback(int family, bool tcp) {
    Socket server(family, tcp ? SOCK_STREAM : SOCK_DGRAM);
    Socket client(family, tcp ? SOCK_STREAM : SOCK_DGRAM);
    sockaddr_storage storage{};
    int size{};
    if (family == AF_INET) {
        auto& address = reinterpret_cast<sockaddr_in&>(storage);
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        size = sizeof(address);
    } else {
        auto& address = reinterpret_cast<sockaddr_in6&>(storage);
        address.sin6_family = AF_INET6;
        address.sin6_addr = in6addr_loopback;
        size = sizeof(address);
    }
    auto* address = reinterpret_cast<sockaddr*>(&storage);
    require(bind(server.value, address, size) == 0, "Bind loopback fixture");
    require(getsockname(server.value, address, &size) == 0, "Read fixture endpoint");
    if (tcp) {
        require(listen(server.value, 1) == 0, "Listen for fixture connection");
        require(connect(client.value, address, size) == 0, "Passive observer blocked TCP");
        const auto accepted = accept(server.value, nullptr, nullptr);
        require(accepted != INVALID_SOCKET, "Accept fixture TCP");
        closesocket(accepted);
        return;
    }
    DWORD timeout = 1000;
    require(setsockopt(server.value, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout),
                       sizeof(timeout)) == 0,
            "Set UDP fixture deadline");
    require(sendto(client.value, "x", 1, 0, address, size) == 1, "Send fixture UDP");
    char data{};
    require(recv(server.value, &data, 1, 0) == 1 && data == 'x', "Passive observer blocked UDP");
}

std::wstring executable() {
    std::array<wchar_t, 32768> buffer{};
    const auto size = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
    require(size && size < buffer.size(), "Resolve fixture executable");
    return {buffer.data(), size};
}

std::wstring eventPrefix() {
    UUID id{};
    require(UuidCreate(&id) == RPC_S_OK, "Create fixture ID");
    RPC_WSTR text{};
    require(UuidToStringW(&id, &text) == RPC_S_OK, "Format fixture ID");
    const std::wstring value(reinterpret_cast<wchar_t*>(text));
    RpcStringFreeW(&text);
    return L"Local\\SkewerFlowTest-" + value;
}

class Child final {
public:
    Child()
        : prefix_(eventPrefix()), go_(create(L"-go")), done_(create(L"-done")),
          release_(create(L"-release")) {
        process_ = launch(executable(), {L"--child", prefix_});
    }
    ~Child() {
        // This test owns the launched handle, not a process discovered by PID.
        if (WaitForSingleObject(process_.hProcess, 0) == WAIT_TIMEOUT) {
            TerminateProcess(process_.hProcess, 1);
            WaitForSingleObject(process_.hProcess, 5000);
        }
        CloseHandle(process_.hThread);
        CloseHandle(process_.hProcess);
    }
    Child(const Child&) = delete;
    Child& operator=(const Child&) = delete;
    ProcessKey key() const { return processKey(process_.hProcess, process_.dwProcessId); }
    void start() { require(SetEvent(go_.get()), "Start fixture traffic"); }
    void waitDone() {
        require(WaitForSingleObject(done_.get(), 5000) == WAIT_OBJECT_0, "Fixture traffic failed");
    }
    void finish() {
        require(SetEvent(release_.get()), "Release fixture child");
        require(WaitForSingleObject(process_.hProcess, 5000) == WAIT_OBJECT_0, "Fixture child did not exit");
        DWORD code{};
        require(GetExitCodeProcess(process_.hProcess, &code) && code == 0, "Fixture child failed");
    }

private:
    HANDLE create(const wchar_t* suffix) {
        const auto event = CreateEventW(nullptr, TRUE, FALSE, (prefix_ + suffix).c_str());
        require(event != nullptr, "Create fixture synchronization event");
        return event;
    }
    std::wstring prefix_;
    Handle go_, done_, release_;
    PROCESS_INFORMATION process_{};
};

void childMain(const std::wstring& prefix) {
    Handle go(OpenEventW(SYNCHRONIZE, FALSE, (prefix + L"-go").c_str()));
    Handle done(OpenEventW(EVENT_MODIFY_STATE, FALSE, (prefix + L"-done").c_str()));
    Handle release(OpenEventW(SYNCHRONIZE, FALSE, (prefix + L"-release").c_str()));
    require(go && done && release, "Open fixture events");
    require(WaitForSingleObject(go.get(), 30000) == WAIT_OBJECT_0, "Fixture start deadline");
    WSADATA data{};
    require(WSAStartup(MAKEWORD(2, 2), &data) == 0, "Start fixture Winsock");
    struct Cleanup {
        ~Cleanup() { WSACleanup(); }
    } cleanup;
    for (const auto family : {AF_INET, AF_INET6}) {
        for (const auto tcp : {true, false}) {
            sendLoopback(family, tcp);
        }
    }
    require(SetEvent(done.get()), "Report fixture completion");
    // Keep the selected process alive until its queued events have been read.
    require(WaitForSingleObject(release.get(), 30000) == WAIT_OBJECT_0, "Fixture release deadline");
}

void observeTraffic(TrackedFlowObserver& observer, HANDLE cancellation, ProcessKey key) {
    std::array<bool, 4> established{};
    bool deleted = false;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    while (std::chrono::steady_clock::now() < deadline) {
        const auto result = observer.next(cancellation, 500);
        if (result.status == FlowObserver::Status::Timeout) {
            continue;
        }
        require(result.status == FlowObserver::Status::Event && result.event.has_value(),
                "Unexpected observer stop");
        const auto& event = *result.event;
        require(event.process == key, "Observer attributed traffic to another process");
        require(event.endpoint_id != 0 && event.loopback, "Invalid fixture flow identity");
        require(event.local.port && event.remote.port, "Missing flow endpoint ports");
        require(!event.local.address.empty() && event.local.address == event.remote.address,
                "Invalid loopback addresses");
        const auto index = (event.ipv6 ? 2 : 0) + (event.protocol == IPPROTO_UDP ? 1 : 0);
        if (event.kind == FlowEvent::Kind::Established) {
            established[index] = true;
            const auto tuple = flowTuple(event);
            require(tuple.has_value(), "Live flow address conversion failed");
            require(tuple->source_port == event.local.port && tuple->destination_port == event.remote.port,
                    "Live flow ports changed byte order");
            require(event.ipv6 ? tuple->source[15] == 1 && tuple->source[0] == 0
                               : tuple->source[0] == 127 && tuple->source[3] == 1,
                    "Live loopback binary address mismatch");
            const auto owner = observer.lookup(*tuple);
            require(owner.status == skewer::traffic::FlowIndex::Status::Observed && owner.process &&
                        owner.process->pid == key.pid && owner.process->created == key.created,
                    "Live flow did not reach the correlation index");
            require(observer.lookup(tuple->reversed()).process == owner.process,
                    "Reverse live flow lost its owner");
        } else {
            deleted = true;
        }
        std::cout << "FLOW " << event.process.pid << ' ' << (event.ipv6 ? "IPv6 " : "IPv4 ")
                  << static_cast<unsigned>(event.protocol) << ' ' << event.local.address << ':'
                  << event.local.port << " -> " << event.remote.address << ':' << event.remote.port << '\n';
        if (established[0] && established[1] && established[2] && established[3] && deleted) {
            return;
        }
    }
    throw std::runtime_error("Missing TCP/UDP IPv4/IPv6 establishment or deletion events");
}

void liveTest(const std::wstring& dll) {
    bool rejected_null{};
    try {
        // Must reject before loading any DLL or opening a WinDivert handle.
        FlowObserver invalid(L"not-a-dll", std::unique_ptr<ProcessTarget>{});
    } catch (const std::invalid_argument& error) {
        rejected_null = std::string(error.what()) == "Flow observer requires a live verified process";
    }
    require(rejected_null, "Missing authenticated selection was not rejected first");
    Child selected, other;
    Handle cancellation(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    require(static_cast<bool>(cancellation), "Create observer cancellation event");
    {
        HANDLE raw{};
        require(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw), "Open authenticated fixture token");
        Handle token(raw);
        auto target = std::make_unique<ProcessTarget>(selected.key(), token.get());
        TrackedFlowObserver observer(dll, std::move(target));
        FlowObserver lifecycle(dll, selected.key(), FlowObserver::Mode::SocketLifecycle);
        require(!target, "Observer did not take selection ownership");
        other.start();
        other.waitDone();
        require(observer.next(cancellation.get(), 250).status == FlowObserver::Status::Timeout,
                "Unselected same-image instance leaked into observer");
        selected.start();
        observeTraffic(observer, cancellation.get(), selected.key());
        selected.waitDone();
        bool saw_connect{}, saw_close{};
        const auto deadline = GetTickCount64() + 5000;
        while (GetTickCount64() < deadline && !(saw_connect && saw_close)) {
            const auto result = lifecycle.next(cancellation.get(), 100);
            if (result.event) {
                require(result.event->process == selected.key(), "Socket lifecycle changed identity");
                saw_connect |= result.event->kind == FlowEvent::Kind::ConnectAttempt;
                saw_close |= result.event->kind == FlowEvent::Kind::SocketClosed;
            }
        }
        require(saw_connect && saw_close, "Missing CONNECT/CLOSE lifecycle events");
        require(SetEvent(cancellation.get()), "Cancel observer");
        require(observer.next(cancellation.get(), 1000).status == FlowObserver::Status::Cancelled,
                "Cancellation did not take precedence");
        require(observer.lookup({}).status == skewer::traffic::FlowIndex::Status::Unreliable,
                "Cancelled observation retained correlation context");
        require(ResetEvent(cancellation.get()), "Reset fixture cancellation");
        require(observer.next(cancellation.get(), 0).status == FlowObserver::Status::Cancelled,
                "Cancelled observer restarted itself");
    }
    {
        TrackedFlowObserver observer(dll, selected.key());
        require(observer.next(cancellation.get(), 0).status == FlowObserver::Status::Timeout,
                "Idle read did not pend");
        selected.finish();
        require(observer.lookup({}).status == skewer::traffic::FlowIndex::Status::Unreliable,
                "Target exit retained correlation context before the next read");
        require(observer.next(cancellation.get(), 1000).status == FlowObserver::Status::TargetExited,
                "Exited target did not retire its observer");
    }
    {
        TrackedFlowObserver observer(dll, other.key());
        require(observer.next(cancellation.get(), 0).status == FlowObserver::Status::Timeout,
                "Idle read did not pend");
        // Destruction must cancel and drain this pending request safely.
    }
    other.finish();
    std::cout << "PASS: passive per-instance flow observation, IPv4/IPv6 TCP/UDP, cancellation and exit\n";
}
} // namespace

int wmain(int argc, wchar_t** argv) {
    try {
        require(argc == 3, "Usage: flow_observer_test --live ABSOLUTE_WINDIVERT_DLL");
        if (std::wstring_view(argv[1]) == L"--child") {
            childMain(argv[2]);
        } else {
            require(std::wstring_view(argv[1]) == L"--live", "Explicit live test flag required");
            liveTest(argv[2]);
        }
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL: " << error.what() << std::endl;
        return 1;
    }
}
