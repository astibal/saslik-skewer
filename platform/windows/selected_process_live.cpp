#include "selected_session_packets.hpp"
#include "selected_owner_resolver.hpp"
#include "socket_connect_guard.hpp"
#include "routing_client.hpp"
#include "routed_launch.hpp"
#include <QCoreApplication>
#include <QDir>
#include <QTextStream>
#include <future>
#include <sstream>
#include <vector>

using namespace skewer::windows;
namespace {
void require(bool ok, const char* message) {
    if (!ok) {
        throw std::runtime_error(message);
    }
}
std::vector<std::uint8_t> dnsQuery(const QString& host, std::uint16_t id) {
    std::vector<std::uint8_t> query{
        static_cast<std::uint8_t>(id >> 8), static_cast<std::uint8_t>(id),
        0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    for (const auto& label : host.toLatin1().split('.')) {
        require(!label.isEmpty() && label.size() <= 63, "DNS fixture host invalid");
        query.push_back(static_cast<std::uint8_t>(label.size()));
        query.insert(query.end(), label.begin(), label.end());
    }
    query.insert(query.end(), {0x00, 0x00, 0x01, 0x00, 0x01});
    return query;
}
void sendDnsQuery(SOCKET socket, const std::vector<std::uint8_t>& query) {
    require(send(socket, reinterpret_cast<const char*>(query.data()), static_cast<int>(query.size()), 0) ==
                static_cast<int>(query.size()),
            "DNS fixture send failed");
}
bool receiveDnsResponse(SOCKET socket, const std::vector<std::uint8_t>& query) {
    std::array<std::uint8_t, 2048> response{};
    const auto received = recv(socket, reinterpret_cast<char*>(response.data()),
                               static_cast<int>(response.size()), 0);
    return received >= 12 && response[0] == query[0] && response[1] == query[1] &&
           (response[2] & 0x80) != 0;
}
int runUdpChild(const QString& host, const QString& destination) {
    WSADATA data{};
    require(WSAStartup(MAKEWORD(2, 2), &data) == 0, "UDP child Winsock startup failed");
    struct Cleanup {
        ~Cleanup() { WSACleanup(); }
    } cleanup;
    SOCKET socket = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    require(socket != INVALID_SOCKET, "UDP child socket failed");
    struct SocketCleanup {
        SOCKET value;
        ~SocketCleanup() { closesocket(value); }
    } close{socket};
    DWORD timeout = 15000;
    require(setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout),
                       sizeof(timeout)) == 0,
            "UDP child timeout failed");
    sockaddr_in server{};
    server.sin_family = AF_INET;
    server.sin_port = htons(53);
    require(InetPtonA(AF_INET, destination.toLatin1().constData(), &server.sin_addr) == 1,
            "UDP child destination invalid");
    sockaddr_in local{};
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_ANY);
    bool bound{};
    const auto first_port = static_cast<std::uint16_t>(40000 + GetCurrentProcessId() % 20000);
    for (unsigned attempt = 0; attempt < 32 && !bound; ++attempt) {
        local.sin_port = htons(static_cast<std::uint16_t>(first_port + attempt));
        bound = bind(socket, reinterpret_cast<const sockaddr*>(&local), sizeof(local)) == 0;
    }
    require(bound, "UDP child bind failed");

    const auto query = dnsQuery(host, 0x534b);
    require(connect(socket, reinterpret_cast<const sockaddr*>(&server), sizeof(server)) == 0,
            "UDP child connect failed");
    // Let the passive SOCKET lifecycle and owner-table views converge before
    // the one-shot datagram. The production resolver remains fail-closed.
    Sleep(50);
    sendDnsQuery(socket, query);
    require(receiveDnsResponse(socket, query), "UDP child DNS response failed");
    return 0;
}
int runHttpsDescendant(const QString& host, const QString& destination) {
    wchar_t system[MAX_PATH]{};
    const auto length = GetSystemDirectoryW(system, MAX_PATH);
    require(length && length < MAX_PATH, "Resolve descendant system directory");
    const auto curl = std::wstring(system) + L"\\curl.exe";
    // Exercise new Job members throughout one active generation, not only the
    // initial child. No sleep/retry: an admission-time connect refusal is a bug.
    for (unsigned attempt = 0; attempt < 8; ++attempt) {
        const auto child = launch(curl,
                                  {L"--noproxy", L"*", L"-4", L"-k", L"--fail", L"--silent",
                                   L"--show-error", L"--max-time", L"20", L"--output", L"NUL",
                                   L"--resolve", (host + ":443:" + destination).toStdWString(),
                                   ("https://" + host + "/").toStdWString()});
        Handle process(child.hProcess), thread(child.hThread);
        require(WaitForSingleObject(process.get(), 25000) == WAIT_OBJECT_0,
                "Descendant curl timed out");
        DWORD exit{};
        require(GetExitCodeProcess(process.get(), &exit), "Read descendant curl exit code");
        if (exit != 0) {
            QTextStream(stderr) << "HTTPS descendant attempt " << attempt + 1
                                << " failed with exit " << exit << '\n';
            return static_cast<int>(exit);
        }
    }
    return 0;
}
int runUdpDescendant(const QString& host, const QString& destination) {
    const auto child = launch(QCoreApplication::applicationFilePath().toStdWString(),
                              {L"--udp-child", host.toStdWString(), destination.toStdWString()});
    Handle process(child.hProcess), thread(child.hThread);
    require(WaitForSingleObject(process.get(), 20000) == WAIT_OBJECT_0,
            "Descendant DNS/UDP child timed out");
    DWORD exit{};
    require(GetExitCodeProcess(process.get(), &exit), "Read descendant DNS/UDP exit code");
    return static_cast<int>(exit);
}
// Own only the child created by this fixture; never terminate a discovered PID.
struct Child {
    PROCESS_INFORMATION process{};
    void stop() {
        if (process.hProcess) {
            if (WaitForSingleObject(process.hProcess, 0) == WAIT_TIMEOUT) {
                TerminateProcess(process.hProcess, 1);
                WaitForSingleObject(process.hProcess, 2000);
            }
        }
    }
    ~Child() {
        stop();
        if (process.hProcess) {
            CloseHandle(process.hProcess);
        }
        if (process.hThread) {
            CloseHandle(process.hThread);
        }
    }
};
int runGatedHttpsChild(const QString& ready_name, const QString& go_name,
                       const QString& host, const QString& destination) {
    Handle ready(OpenEventW(EVENT_MODIFY_STATE, FALSE, ready_name.toStdWString().c_str()));
    Handle go(OpenEventW(SYNCHRONIZE, FALSE, go_name.toStdWString().c_str()));
    require(bool(ready) && bool(go) && SetEvent(ready.get()), "Open existing-tree fixture events");
    require(WaitForSingleObject(go.get(), 30000) == WAIT_OBJECT_0,
            "Existing descendant was not released after routing activation");
    return runHttpsDescendant(host, destination);
}
int runExistingParent(const QString& ready_name, const QString& go_name,
                      const QString& host, const QString& destination) {
    const auto child = launch(QCoreApplication::applicationFilePath().toStdWString(),
                              {L"--gated-https-child", ready_name.toStdWString(),
                               go_name.toStdWString(), host.toStdWString(), destination.toStdWString()});
    Handle process(child.hProcess), thread(child.hThread);
    require(WaitForSingleObject(process.get(), 35000) == WAIT_OBJECT_0,
            "Existing descendant fixture timed out");
    DWORD exit{};
    require(GetExitCodeProcess(process.get(), &exit), "Read existing descendant exit code");
    return static_cast<int>(exit);
}
int runExistingTcpChild(const QString& ready_name, const QString& inspect_name,
                        std::uint16_t port) {
    WSADATA data{};
    require(WSAStartup(MAKEWORD(2, 2), &data) == 0, "Existing TCP child Winsock startup failed");
    struct WinsockCleanup {
        ~WinsockCleanup() { WSACleanup(); }
    } winsock_cleanup;
    Handle ready(OpenEventW(EVENT_MODIFY_STATE, FALSE, ready_name.toStdWString().c_str()));
    Handle inspect(OpenEventW(SYNCHRONIZE, FALSE, inspect_name.toStdWString().c_str()));
    require(bool(ready) && bool(inspect), "Open existing TCP fixture events");
    SOCKET socket = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    require(socket != INVALID_SOCKET, "Create existing TCP fixture socket");
    struct CloseSocket {
        SOCKET value;
        ~CloseSocket() { closesocket(value); }
    } close{socket};
    sockaddr_in peer{};
    peer.sin_family = AF_INET;
    peer.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    peer.sin_port = htons(port);
    require(connect(socket, reinterpret_cast<const sockaddr*>(&peer), sizeof(peer)) == 0,
            "Connect existing TCP fixture socket");
    require(SetEvent(ready.get()), "Signal existing TCP fixture readiness");
    require(WaitForSingleObject(inspect.get(), 30000) == WAIT_OBJECT_0,
            "Existing TCP fixture was not inspected after Attach");
    DWORD timeout = 2000;
    require(setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO,
                       reinterpret_cast<const char*>(&timeout), sizeof(timeout)) == 0,
            "Set existing TCP fixture timeout");
    char byte{};
    const auto received = recv(socket, &byte, 1, 0);
    const auto error = received == SOCKET_ERROR ? WSAGetLastError() : 0;
    require(received == 0 || (received == SOCKET_ERROR &&
                              (error == WSAECONNRESET || error == WSAENOTCONN)),
            "Pre-Attach TCP connection remained usable after routing activation");
    return 0;
}
int runExistingUdpChild(const QString& ready_name, const QString& inspect_name,
                        const QString& host, const QString& destination) {
    WSADATA data{};
    require(WSAStartup(MAKEWORD(2, 2), &data) == 0, "Existing UDP child Winsock startup failed");
    struct WinsockCleanup {
        ~WinsockCleanup() { WSACleanup(); }
    } winsock_cleanup;
    Handle ready(OpenEventW(EVENT_MODIFY_STATE, FALSE, ready_name.toStdWString().c_str()));
    Handle inspect(OpenEventW(SYNCHRONIZE, FALSE, inspect_name.toStdWString().c_str()));
    require(bool(ready) && bool(inspect), "Open existing UDP fixture events");
    SOCKET socket = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    require(socket != INVALID_SOCKET, "Create existing UDP fixture socket");
    struct CloseSocket {
        SOCKET value;
        ~CloseSocket() { closesocket(value); }
    } close{socket};
    sockaddr_in local{};
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_ANY);
    local.sin_port = 0;
    require(bind(socket, reinterpret_cast<const sockaddr*>(&local), sizeof(local)) == 0,
            "Bind existing UDP fixture socket");
    sockaddr_in peer{};
    peer.sin_family = AF_INET;
    peer.sin_port = htons(53);
    require(InetPtonA(AF_INET, destination.toLatin1().constData(), &peer.sin_addr) == 1 &&
                connect(socket, reinterpret_cast<const sockaddr*>(&peer), sizeof(peer)) == 0,
            "Connect existing UDP fixture socket");
    DWORD timeout = 2500;
    require(setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO,
                       reinterpret_cast<const char*>(&timeout), sizeof(timeout)) == 0,
            "Set existing UDP fixture timeout");
    require(SetEvent(ready.get()), "Signal existing UDP fixture readiness");
    require(WaitForSingleObject(inspect.get(), 30000) == WAIT_OBJECT_0,
            "Existing UDP fixture was not inspected after Attach");

    // The service publishes Active only after packet capture is armed. Its
    // selected-group resolver never returns Direct for a selected owner, so a
    // valid reply here proves this pre-existing unique bind used the tunnel.
    const auto query = dnsQuery(host, 0x534c);
    sendDnsQuery(socket, query);
    require(receiveDnsResponse(socket, query),
            "Pre-Attach UDP socket did not complete through selected routing");
    return 0;
}
int runExistingIpv6Child(const QString& ready_name, const QString& inspect_name,
                         const QString& attempted_name, const QString& release_name,
                         std::uint16_t port) {
    WSADATA data{};
    require(WSAStartup(MAKEWORD(2, 2), &data) == 0, "Existing IPv6 child Winsock startup failed");
    struct WinsockCleanup {
        ~WinsockCleanup() { WSACleanup(); }
    } winsock_cleanup;
    Handle ready(OpenEventW(EVENT_MODIFY_STATE, FALSE, ready_name.toStdWString().c_str()));
    Handle inspect(OpenEventW(SYNCHRONIZE, FALSE, inspect_name.toStdWString().c_str()));
    Handle attempted(OpenEventW(EVENT_MODIFY_STATE, FALSE, attempted_name.toStdWString().c_str()));
    Handle release(OpenEventW(SYNCHRONIZE, FALSE, release_name.toStdWString().c_str()));
    require(bool(ready) && bool(inspect) && bool(attempted) && bool(release),
            "Open existing IPv6 fixture events");
    SOCKET socket = ::socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    require(socket != INVALID_SOCKET, "Create existing IPv6 fixture socket");
    struct CloseSocket {
        SOCKET value;
        ~CloseSocket() { closesocket(value); }
    } close{socket};
    sockaddr_in6 peer{};
    peer.sin6_family = AF_INET6;
    peer.sin6_addr = in6addr_loopback;
    peer.sin6_port = htons(port);
    require(connect(socket, reinterpret_cast<const sockaddr*>(&peer), sizeof(peer)) == 0,
            "Connect existing IPv6 fixture socket");
    require(SetEvent(ready.get()), "Signal existing IPv6 fixture readiness");
    require(WaitForSingleObject(inspect.get(), 30000) == WAIT_OBJECT_0,
            "Existing IPv6 fixture was not inspected after Attach");
    const char blocked = 'B';
    require(send(socket, &blocked, 1, 0) == 1 && SetEvent(attempted.get()),
            "Send protected IPv6 fixture byte");
    require(WaitForSingleObject(release.get(), 10000) == WAIT_OBJECT_0,
            "Existing IPv6 fixture was not released");
    const char restored = 'R';
    require(send(socket, &restored, 1, 0) == 1, "Send released IPv6 fixture byte");
    return 0;
}
class Worker final : public TunnelPacketWorker {
public:
    Worker(SelectedSessionPackets& packets, Child& child, HANDLE stop)
        : packets_(packets), child_(child), stop_(stop) {}
    void prepare(const Tuntom::Endpoint& endpoint) override { packets_.prepare(endpoint); }
    void poll() override {
        packets_.poll();
        if (!resumed_) {
            require(ResumeThread(child_.process.hThread) == 1, "Resume selected child");
            resumed_ = true;
        }
        if (WaitForSingleObject(child_.process.hProcess, 0) == WAIT_OBJECT_0) {
            SetEvent(stop_);
        }
    }
    void block() noexcept override { packets_.block(); }

private:
    SelectedSessionPackets& packets_;
    Child& child_;
    HANDLE stop_;
    bool resumed_{};
};
void throughService(const std::wstring& executable, const std::vector<std::wstring>& arguments,
                    const std::wstring& name, const char* description) {
    Handle cancel(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    require(bool(cancel), "Create service fixture cancellation");
    const auto command = [&](RoutingCommand operation, std::uint64_t generation) {
        auto pipe = connectRoutingService(name, false, cancel.get(), 3000);
        return exchangeRoutingCommand(pipe->get(), name, operation, generation, cancel.get(), 3000);
    };
    const auto started = launchRouted(name, executable, arguments, cancel.get());
    Child child;
    child.process = started.process;
    struct Release {
        Child& child;
        std::function<void()> stop;
        ~Release() {
            child.stop();
            try {
                stop();
            } catch (...) {
            }
        }
    } release{child, [&] { command(RoutingCommand::Stop, started.generation); }};
    require(WaitForSingleObject(child.process.hProcess, 25000) == WAIT_OBJECT_0,
            "Service-routed curl timed out");
    DWORD exit{};
    require(GetExitCodeProcess(child.process.hProcess, &exit) && exit == 0, description);
    QTextStream(stdout) << "PASS: " << description << " through SCM service\n";
}
void throughExistingService(const std::wstring& executable, const QString& host,
                            const QString& destination, const std::wstring& name) {
    Handle cancel(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    require(bool(cancel), "Create existing-tree cancellation event");
    const auto suffix = std::to_wstring(GetCurrentProcessId()) + L"-" +
                        std::to_wstring(GetTickCount64());
    const auto ready_name = L"Local\\SkewerExistingReady-" + suffix;
    const auto go_name = L"Local\\SkewerExistingGo-" + suffix;
    Handle ready(CreateEventW(nullptr, TRUE, FALSE, ready_name.c_str()));
    Handle go(CreateEventW(nullptr, TRUE, FALSE, go_name.c_str()));
    require(bool(ready) && bool(go), "Create existing-tree fixture events");
    const auto command = [&](RoutingCommand operation, std::uint64_t generation) {
        auto pipe = connectRoutingService(name, false, cancel.get(), 3000);
        return exchangeRoutingCommand(pipe->get(), name, operation, generation, cancel.get(), 3000);
    };
    const auto initial = command(RoutingCommand::Status, 0);
    require(initial.result == RoutingResult::Ok &&
                (initial.phase == RoutingPhase::Idle || initial.phase == RoutingPhase::Failed),
            "Routing service is busy before existing-tree fixture");
    std::uint64_t generation{};
    Child parent{launch(executable,
                        {L"--existing-parent", ready_name, go_name,
                         host.toStdWString(), destination.toStdWString()})};
    struct Release {
        Child& child;
        std::function<void()> stop;
        ~Release() {
            child.stop();
            try { stop(); } catch (...) {}
        }
    } release{parent, [&] {
        if (generation) command(RoutingCommand::Stop, generation);
    }};
    require(WaitForSingleObject(ready.get(), 5000) == WAIT_OBJECT_0,
            "Pre-existing descendant was not ready before Attach");
    const auto identity = processKey(parent.process.hProcess, parent.process.dwProcessId);
    auto pipe = connectRoutingService(name, false, cancel.get(), 3000);
    const auto started = exchangeSelectedRouting(pipe->get(), name, identity,
                                                 initial.generation, cancel.get(), 3000);
    require(started.result == RoutingResult::Ok, "Existing process tree selection failed");
    generation = started.generation;
    const auto deadline = GetTickCount64() + 30000;
    for (;;) {
        const auto state = command(RoutingCommand::Status, 0);
        require(state.result == RoutingResult::Ok && state.generation == started.generation &&
                    (state.phase == RoutingPhase::Starting || state.phase == RoutingPhase::Blocked ||
                     state.phase == RoutingPhase::Active),
                "Existing process tree stopped before readiness");
        if (state.phase == RoutingPhase::Active) break;
        require(GetTickCount64() < deadline, "Existing process tree did not become Active");
        Sleep(50);
    }
    require(SetEvent(go.get()), "Release pre-existing descendant fixture");
    require(WaitForSingleObject(parent.process.hProcess, 30000) == WAIT_OBJECT_0,
            "Pre-existing descendant HTTPS timed out");
    DWORD exit{};
    require(GetExitCodeProcess(parent.process.hProcess, &exit) && exit == 0,
            "Pre-existing descendant HTTPS failed");
    const auto stopped = command(RoutingCommand::Stop, started.generation);
    require(stopped.result == RoutingResult::Ok, "Stop existing-tree routing");
    const auto stop_deadline = GetTickCount64() + 5000;
    for (;;) {
        const auto state = command(RoutingCommand::Status, 0);
        require(state.result == RoutingResult::Ok && state.generation == started.generation,
                "Existing-tree stop generation changed");
        if (state.phase == RoutingPhase::Idle || state.phase == RoutingPhase::Failed) break;
        require(GetTickCount64() < stop_deadline, "Existing-tree routing did not stop");
        Sleep(25);
    }
    generation = 0;
    QTextStream(stdout) << "PASS: pre-existing descendant adopted through SCM service\n";
}
void resetExistingTcpThroughService(const std::wstring& executable, const std::wstring& name) {
    SOCKET listener = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    require(listener != INVALID_SOCKET, "Create existing TCP listener");
    struct CloseSocket {
        SOCKET value;
        ~CloseSocket() { closesocket(value); }
    } close_listener{listener};
    sockaddr_in local{};
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    require(bind(listener, reinterpret_cast<const sockaddr*>(&local), sizeof(local)) == 0 &&
                listen(listener, 1) == 0,
            "Bind existing TCP listener");
    int local_size = sizeof(local);
    require(getsockname(listener, reinterpret_cast<sockaddr*>(&local), &local_size) == 0,
            "Read existing TCP listener address");

    Handle cancel(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    require(bool(cancel), "Create existing TCP cancellation event");
    const auto suffix = std::to_wstring(GetCurrentProcessId()) + L"-" +
                        std::to_wstring(GetTickCount64());
    const auto ready_name = L"Local\\SkewerExistingTcpReady-" + suffix;
    const auto inspect_name = L"Local\\SkewerExistingTcpInspect-" + suffix;
    Handle ready(CreateEventW(nullptr, TRUE, FALSE, ready_name.c_str()));
    Handle inspect(CreateEventW(nullptr, TRUE, FALSE, inspect_name.c_str()));
    require(bool(ready) && bool(inspect), "Create existing TCP fixture events");
    Child child{launch(executable,
                       {L"--existing-tcp-child", ready_name, inspect_name,
                        std::to_wstring(ntohs(local.sin_port))})};
    fd_set readable;
    FD_ZERO(&readable);
    FD_SET(listener, &readable);
    timeval accept_timeout{5, 0};
    require(select(0, &readable, nullptr, nullptr, &accept_timeout) == 1,
            "Existing TCP fixture did not reach the listener");
    SOCKET accepted = accept(listener, nullptr, nullptr);
    require(accepted != INVALID_SOCKET, "Accept existing TCP fixture connection");
    CloseSocket close_accepted{accepted};
    require(WaitForSingleObject(ready.get(), 5000) == WAIT_OBJECT_0,
            "Existing TCP child did not connect before Attach");

    const auto command = [&](RoutingCommand operation, std::uint64_t generation) {
        auto pipe = connectRoutingService(name, false, cancel.get(), 3000);
        return exchangeRoutingCommand(pipe->get(), name, operation, generation, cancel.get(), 3000);
    };
    const auto initial = command(RoutingCommand::Status, 0);
    require(initial.result == RoutingResult::Ok &&
                (initial.phase == RoutingPhase::Idle || initial.phase == RoutingPhase::Failed),
            "Routing service is busy before existing TCP fixture");
    std::uint64_t generation{};
    struct Release {
        Child& child;
        std::function<void()> stop;
        ~Release() {
            child.stop();
            try { stop(); } catch (...) {}
        }
    } release{child, [&] { if (generation) command(RoutingCommand::Stop, generation); }};
    const auto identity = processKey(child.process.hProcess, child.process.dwProcessId);
    auto pipe = connectRoutingService(name, false, cancel.get(), 3000);
    const auto started = exchangeSelectedRouting(pipe->get(), name, identity,
                                                 initial.generation, cancel.get(), 3000);
    require(started.result == RoutingResult::Ok, "Existing TCP process selection failed");
    generation = started.generation;
    const auto deadline = GetTickCount64() + 30000;
    for (;;) {
        const auto state = command(RoutingCommand::Status, 0);
        require(state.result == RoutingResult::Ok && state.generation == generation &&
                    (state.phase == RoutingPhase::Starting || state.phase == RoutingPhase::Blocked ||
                     state.phase == RoutingPhase::Active),
                "Existing TCP routing stopped before readiness");
        if (state.phase == RoutingPhase::Active) break;
        require(GetTickCount64() < deadline, "Existing TCP routing did not become Active");
        Sleep(50);
    }
    require(SetEvent(inspect.get()), "Release existing TCP fixture inspection");
    require(WaitForSingleObject(child.process.hProcess, 5000) == WAIT_OBJECT_0,
            "Pre-Attach TCP connection was not reset");
    DWORD exit{};
    require(GetExitCodeProcess(child.process.hProcess, &exit) && exit == 0,
            "Pre-Attach TCP cleanup child failed");
    const auto stopped = command(RoutingCommand::Stop, generation);
    require(stopped.result == RoutingResult::Ok, "Stop existing TCP routing");
    const auto stop_deadline = GetTickCount64() + 5000;
    for (;;) {
        const auto state = command(RoutingCommand::Status, 0);
        require(state.result == RoutingResult::Ok && state.generation == generation,
                "Existing TCP stop generation changed");
        if (state.phase == RoutingPhase::Idle || state.phase == RoutingPhase::Failed) break;
        require(GetTickCount64() < stop_deadline, "Existing TCP routing did not stop");
        Sleep(25);
    }
    generation = 0;
    QTextStream(stdout) << "PASS: pre-Attach IPv4 TCP connection reset by SCM service\n";
}
void routeExistingUdpThroughService(const std::wstring& executable, const QString& host,
                                    const QString& destination, const std::wstring& name) {
    Handle cancel(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    require(bool(cancel), "Create existing UDP cancellation event");
    const auto suffix = std::to_wstring(GetCurrentProcessId()) + L"-" +
                        std::to_wstring(GetTickCount64());
    const auto ready_name = L"Local\\SkewerExistingUdpReady-" + suffix;
    const auto inspect_name = L"Local\\SkewerExistingUdpInspect-" + suffix;
    Handle ready(CreateEventW(nullptr, TRUE, FALSE, ready_name.c_str()));
    Handle inspect(CreateEventW(nullptr, TRUE, FALSE, inspect_name.c_str()));
    require(bool(ready) && bool(inspect), "Create existing UDP fixture events");
    Child child{launch(executable,
                       {L"--existing-udp-child", ready_name, inspect_name,
                        host.toStdWString(), destination.toStdWString()})};
    require(WaitForSingleObject(ready.get(), 5000) == WAIT_OBJECT_0,
            "Existing UDP child did not bind before Attach");

    const auto command = [&](RoutingCommand operation, std::uint64_t generation) {
        auto pipe = connectRoutingService(name, false, cancel.get(), 3000);
        return exchangeRoutingCommand(pipe->get(), name, operation, generation, cancel.get(), 3000);
    };
    const auto initial = command(RoutingCommand::Status, 0);
    require(initial.result == RoutingResult::Ok &&
                (initial.phase == RoutingPhase::Idle || initial.phase == RoutingPhase::Failed),
            "Routing service is busy before existing UDP fixture");
    std::uint64_t generation{};
    struct Cleanup {
        Child& child;
        std::function<void()> stop;
        ~Cleanup() {
            child.stop();
            try { stop(); } catch (...) {}
        }
    } cleanup{child, [&] { if (generation) command(RoutingCommand::Stop, generation); }};
    const auto identity = processKey(child.process.hProcess, child.process.dwProcessId);
    auto pipe = connectRoutingService(name, false, cancel.get(), 3000);
    const auto started = exchangeSelectedRouting(pipe->get(), name, identity,
                                                 initial.generation, cancel.get(), 3000);
    require(started.result == RoutingResult::Ok, "Existing UDP process selection failed");
    generation = started.generation;
    const auto active_deadline = GetTickCount64() + 30000;
    for (;;) {
        const auto state = command(RoutingCommand::Status, 0);
        require(state.result == RoutingResult::Ok && state.generation == generation &&
                    (state.phase == RoutingPhase::Starting || state.phase == RoutingPhase::Blocked ||
                     state.phase == RoutingPhase::Active),
                "Existing UDP routing stopped before readiness");
        if (state.phase == RoutingPhase::Active) break;
        require(GetTickCount64() < active_deadline, "Existing UDP routing did not become Active");
        Sleep(50);
    }
    require(SetEvent(inspect.get()), "Release existing UDP tunnel probe");
    require(WaitForSingleObject(child.process.hProcess, 10000) == WAIT_OBJECT_0,
            "Pre-Attach UDP tunnel probe timed out");
    DWORD exit{};
    require(GetExitCodeProcess(child.process.hProcess, &exit) && exit == 0,
            "Pre-Attach UDP tunnel child failed");
    const auto stopped = command(RoutingCommand::Stop, generation);
    require(stopped.result == RoutingResult::Ok, "Stop existing UDP routing");
    const auto stop_deadline = GetTickCount64() + 5000;
    for (;;) {
        const auto state = command(RoutingCommand::Status, 0);
        require(state.result == RoutingResult::Ok && state.generation == generation,
                "Existing UDP stop generation changed");
        if (state.phase == RoutingPhase::Idle || state.phase == RoutingPhase::Failed) break;
        require(GetTickCount64() < stop_deadline, "Existing UDP routing did not stop");
        Sleep(25);
    }
    generation = 0;
    QTextStream(stdout)
        << "PASS: unique pre-Attach UDP socket routed through SCM service\n";
}
void blockExistingIpv6ThroughService(const std::wstring& executable, const std::wstring& name) {
    SOCKET listener = ::socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    require(listener != INVALID_SOCKET, "Create existing IPv6 listener");
    struct CloseSocket {
        SOCKET value;
        ~CloseSocket() { closesocket(value); }
    } close_listener{listener};
    DWORD ipv6_only = 1;
    require(setsockopt(listener, IPPROTO_IPV6, IPV6_V6ONLY,
                       reinterpret_cast<const char*>(&ipv6_only), sizeof(ipv6_only)) == 0,
            "Configure existing IPv6 listener");
    sockaddr_in6 local{};
    local.sin6_family = AF_INET6;
    local.sin6_addr = in6addr_loopback;
    require(bind(listener, reinterpret_cast<const sockaddr*>(&local), sizeof(local)) == 0 &&
                listen(listener, 1) == 0,
            "Bind existing IPv6 listener");
    int local_size = sizeof(local);
    require(getsockname(listener, reinterpret_cast<sockaddr*>(&local), &local_size) == 0,
            "Read existing IPv6 listener address");

    Handle cancel(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    require(bool(cancel), "Create existing IPv6 cancellation event");
    const auto suffix = std::to_wstring(GetCurrentProcessId()) + L"-" +
                        std::to_wstring(GetTickCount64());
    const auto ready_name = L"Local\\SkewerExistingIpv6Ready-" + suffix;
    const auto inspect_name = L"Local\\SkewerExistingIpv6Inspect-" + suffix;
    const auto attempted_name = L"Local\\SkewerExistingIpv6Attempted-" + suffix;
    const auto release_name = L"Local\\SkewerExistingIpv6Release-" + suffix;
    Handle ready(CreateEventW(nullptr, TRUE, FALSE, ready_name.c_str()));
    Handle inspect(CreateEventW(nullptr, TRUE, FALSE, inspect_name.c_str()));
    Handle attempted(CreateEventW(nullptr, TRUE, FALSE, attempted_name.c_str()));
    Handle release_event(CreateEventW(nullptr, TRUE, FALSE, release_name.c_str()));
    require(bool(ready) && bool(inspect) && bool(attempted) && bool(release_event),
            "Create existing IPv6 fixture events");
    Child child{launch(executable,
                       {L"--existing-ipv6-child", ready_name, inspect_name, attempted_name,
                        release_name, std::to_wstring(ntohs(local.sin6_port))})};
    fd_set readable;
    FD_ZERO(&readable);
    FD_SET(listener, &readable);
    timeval accept_timeout{5, 0};
    require(select(0, &readable, nullptr, nullptr, &accept_timeout) == 1,
            "Existing IPv6 fixture did not reach the listener");
    SOCKET accepted = accept(listener, nullptr, nullptr);
    require(accepted != INVALID_SOCKET, "Accept existing IPv6 fixture connection");
    CloseSocket close_accepted{accepted};
    require(WaitForSingleObject(ready.get(), 5000) == WAIT_OBJECT_0,
            "Existing IPv6 child did not connect before Attach");

    const auto command = [&](RoutingCommand operation, std::uint64_t generation) {
        auto pipe = connectRoutingService(name, false, cancel.get(), 3000);
        return exchangeRoutingCommand(pipe->get(), name, operation, generation, cancel.get(), 3000);
    };
    const auto initial = command(RoutingCommand::Status, 0);
    require(initial.result == RoutingResult::Ok &&
                (initial.phase == RoutingPhase::Idle || initial.phase == RoutingPhase::Failed),
            "Routing service is busy before existing IPv6 fixture");
    std::uint64_t generation{};
    struct Cleanup {
        Child& child;
        std::function<void()> stop;
        ~Cleanup() {
            child.stop();
            try { stop(); } catch (...) {}
        }
    } cleanup{child, [&] { if (generation) command(RoutingCommand::Stop, generation); }};
    const auto identity = processKey(child.process.hProcess, child.process.dwProcessId);
    auto pipe = connectRoutingService(name, false, cancel.get(), 3000);
    const auto started = exchangeSelectedRouting(pipe->get(), name, identity,
                                                 initial.generation, cancel.get(), 3000);
    require(started.result == RoutingResult::Ok, "Existing IPv6 process selection failed");
    generation = started.generation;
    const auto active_deadline = GetTickCount64() + 30000;
    for (;;) {
        const auto state = command(RoutingCommand::Status, 0);
        require(state.result == RoutingResult::Ok && state.generation == generation &&
                    (state.phase == RoutingPhase::Starting || state.phase == RoutingPhase::Blocked ||
                     state.phase == RoutingPhase::Active),
                "Existing IPv6 routing stopped before readiness");
        if (state.phase == RoutingPhase::Active) break;
        require(GetTickCount64() < active_deadline, "Existing IPv6 routing did not become Active");
        Sleep(50);
    }
    require(SetEvent(inspect.get()) && WaitForSingleObject(attempted.get(), 5000) == WAIT_OBJECT_0,
            "Existing IPv6 protection probe did not run");
    FD_ZERO(&readable);
    FD_SET(accepted, &readable);
    timeval blocked_timeout{2, 0};
    require(select(0, &readable, nullptr, nullptr, &blocked_timeout) == 0,
            "Pre-Attach IPv6 traffic escaped selected routing protection");

    const auto stopped = command(RoutingCommand::Stop, generation);
    require(stopped.result == RoutingResult::Ok, "Stop existing IPv6 routing");
    const auto stop_deadline = GetTickCount64() + 5000;
    for (;;) {
        const auto state = command(RoutingCommand::Status, 0);
        require(state.result == RoutingResult::Ok && state.generation == generation,
                "Existing IPv6 stop generation changed");
        if (state.phase == RoutingPhase::Idle || state.phase == RoutingPhase::Failed) break;
        require(GetTickCount64() < stop_deadline, "Existing IPv6 routing did not stop");
        Sleep(25);
    }
    generation = 0;
    require(SetEvent(release_event.get()), "Release existing IPv6 fixture after Stop");
    // TCP may retransmit the protected byte after explicit Release removes
    // interception. That is expected: Release restores direct connectivity.
    // Require the new post-Release marker as proof that the connection resumed.
    bool restored{};
    const auto restored_deadline = GetTickCount64() + 5000;
    while (!restored && GetTickCount64() < restored_deadline) {
        FD_ZERO(&readable);
        FD_SET(accepted, &readable);
        timeval restored_timeout{0, 250000};
        if (select(0, &readable, nullptr, nullptr, &restored_timeout) != 1) continue;
        std::array<char, 16> bytes{};
        const auto received = recv(accepted, bytes.data(), static_cast<int>(bytes.size()), 0);
        require(received > 0, "Existing IPv6 connection closed during Release recovery");
        for (int i = 0; i < received; ++i) {
            require(bytes[i] == 'B' || bytes[i] == 'R',
                    "Released IPv6 payload was corrupted");
            restored |= bytes[i] == 'R';
        }
    }
    require(restored, "Existing IPv6 connection did not recover after Release");
    require(WaitForSingleObject(child.process.hProcess, 5000) == WAIT_OBJECT_0,
            "Existing IPv6 child did not exit after Release");
    DWORD exit{};
    require(GetExitCodeProcess(child.process.hProcess, &exit) && exit == 0,
            "Existing IPv6 protection child failed");
    QTextStream(stdout)
        << "PASS: pre-Attach IPv6 TCP blocked while selected and recovered after Release\n";
}
} // namespace

// Elevated, bounded development fixture: real independent curl process, pinned
// before its first instruction. Narrow destination capture; no host routes/DNS.
int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    app.setOrganizationName("Saslik");
    app.setApplicationName("Skewer");
    const auto args = app.arguments();
    if (args.size() == 4 && args[1] == "--udp-child") {
        try {
            return runUdpChild(args[2], args[3]);
        } catch (const std::exception& error) {
            QTextStream(stderr) << error.what() << '\n';
            return 1;
        }
    }
    if (args.size() == 4 && args[1] == "--https-descendant") {
        try {
            return runHttpsDescendant(args[2], args[3]);
        } catch (const std::exception& error) {
            QTextStream(stderr) << error.what() << '\n';
            return 1;
        }
    }
    if (args.size() == 4 && args[1] == "--udp-descendant") {
        try {
            return runUdpDescendant(args[2], args[3]);
        } catch (const std::exception& error) {
            QTextStream(stderr) << error.what() << '\n';
            return 1;
        }
    }
    if (args.size() == 6 && args[1] == "--gated-https-child") {
        try {
            return runGatedHttpsChild(args[2], args[3], args[4], args[5]);
        } catch (const std::exception& error) {
            QTextStream(stderr) << error.what() << '\n';
            return 1;
        }
    }
    if (args.size() == 6 && args[1] == "--existing-parent") {
        try {
            return runExistingParent(args[2], args[3], args[4], args[5]);
        } catch (const std::exception& error) {
            QTextStream(stderr) << error.what() << '\n';
            return 1;
        }
    }
    if (args.size() == 5 && args[1] == "--existing-tcp-child") {
        try {
            bool ok{};
            const auto port = args[4].toUShort(&ok);
            require(ok && port, "Invalid existing TCP fixture port");
            return runExistingTcpChild(args[2], args[3], port);
        } catch (const std::exception& error) {
            QTextStream(stderr) << error.what() << '\n';
            return 1;
        }
    }
    if (args.size() == 6 && args[1] == "--existing-udp-child") {
        try {
            return runExistingUdpChild(args[2], args[3], args[4], args[5]);
        } catch (const std::exception& error) {
            QTextStream(stderr) << error.what() << '\n';
            return 1;
        }
    }
    if (args.size() == 7 && args[1] == "--existing-ipv6-child") {
        try {
            bool ok{};
            const auto port = args[6].toUShort(&ok);
            require(ok && port, "Invalid existing IPv6 fixture port");
            return runExistingIpv6Child(args[2], args[3], args[4], args[5], port);
        } catch (const std::exception& error) {
            QTextStream(stderr) << error.what() << '\n';
            return 1;
        }
    }
    if (args.size() < 5 || args.size() > 7 ||
        (args.size() == 7 && args[6] != "--udp" && args[6] != "--descendant" &&
         args[6] != "--descendant-udp" && args[6] != "--existing-descendant" &&
         args[6] != "--existing-tcp" && args[6] != "--existing-udp" &&
         args[6] != "--existing-ipv6")) {
        QTextStream(stderr)
            << "Usage: selected_process_live PAIRED_ENDPOINT PEER_IPV4 DEST_IPV4 HOST "
               "[SERVICE [--udp|--descendant|--descendant-udp|--existing-descendant|--existing-tcp|--existing-udp|--existing-ipv6]|--udp]\n";
        return 2;
    }
    try {
        std::array<std::uint8_t, 4> address{};
        require(InetPtonA(AF_INET, args[3].toLatin1().constData(), address.data()) == 1,
                "Invalid destination address");
        const auto host = args[4].toStdString();
        require(
            !host.empty() && host.size() < 254 &&
                host.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-") ==
                    std::string::npos,
            "Invalid host");
        WSADATA data{};
        require(WSAStartup(MAKEWORD(2, 2), &data) == 0, "Winsock startup failed");
        struct Cleanup {
            ~Cleanup() { WSACleanup(); }
        } cleanup;
        Handle stop(CreateEventW(nullptr, TRUE, FALSE, nullptr));
        require(bool(stop), "Create stop event");
        const bool udp_probe = (args.size() == 6 && args[5] == "--udp") ||
                               (args.size() == 7 && args[6] == "--udp");
        wchar_t system[MAX_PATH]{};
        const auto length = GetSystemDirectoryW(system, MAX_PATH);
        require(length && length < MAX_PATH, "Resolve system directory");
        const auto executable = udp_probe ? app.applicationFilePath().toStdWString()
                                          : std::wstring(system) + L"\\curl.exe";
        if ((args.size() == 6 && !udp_probe) || args.size() == 7) {
            const bool existing_probe = args.size() == 7 && args[6] == "--existing-descendant";
            if (existing_probe) {
                throughExistingService(app.applicationFilePath().toStdWString(), args[4], args[3],
                                       args[5].toStdWString());
                return 0;
            }
            if (args.size() == 7 && args[6] == "--existing-tcp") {
                resetExistingTcpThroughService(app.applicationFilePath().toStdWString(),
                                               args[5].toStdWString());
                return 0;
            }
            if (args.size() == 7 && args[6] == "--existing-udp") {
                routeExistingUdpThroughService(app.applicationFilePath().toStdWString(), args[4],
                                               args[3], args[5].toStdWString());
                return 0;
            }
            if (args.size() == 7 && args[6] == "--existing-ipv6") {
                blockExistingIpv6ThroughService(app.applicationFilePath().toStdWString(),
                                                args[5].toStdWString());
                return 0;
            }
            const bool descendant_probe = args.size() == 7 && args[6] == "--descendant";
            const bool descendant_udp_probe = args.size() == 7 && args[6] == "--descendant-udp";
            const auto service_executable = descendant_probe || descendant_udp_probe
                ? app.applicationFilePath().toStdWString()
                : executable;
            const auto child_arguments = descendant_udp_probe
                ? std::vector<std::wstring>{L"--udp-descendant", args[4].toStdWString(),
                                            args[3].toStdWString()}
                : descendant_probe
                ? std::vector<std::wstring>{L"--https-descendant", args[4].toStdWString(),
                                            args[3].toStdWString()}
                : udp_probe
                ? std::vector<std::wstring>{L"--udp-child", args[4].toStdWString(),
                                            args[3].toStdWString()}
                : std::vector<std::wstring>{L"--noproxy", L"*", L"-4", L"-k", L"--fail",
                                            L"--silent", L"--show-error", L"--max-time", L"20",
                                            L"--output", L"NUL", L"--resolve",
                                            (args[4] + ":443:" + args[3]).toStdWString(),
                                            ("https://" + args[4] + "/").toStdWString()};
            const auto description = descendant_udp_probe ? "selected descendant DNS/UDP"
                                     : descendant_probe ? "selected descendant HTTPS"
                                     : udp_probe ? "selected root DNS/UDP"
                                                 : "selected root HTTPS";
            throughService(service_executable, child_arguments, args[5].toStdWString(), description);
            return 0;
        }
        auto command = udp_probe
            ? (QString::fromStdWString(L"\"" + executable + L"\"") + " --udp-child " + args[4] +
               " " + args[3])
                  .toStdWString()
            : (QString::fromStdWString(L"\"" + executable + L"\"") +
               " --noproxy * -4 -k --fail --silent --show-error --max-time 20 --output NUL --resolve " +
               args[4] + ":443:" + args[3] + " https://" + args[4] + "/")
                  .toStdWString();
        Child child;
        STARTUPINFOW startup{};
        startup.cb = sizeof(startup);
        require(CreateProcessW(executable.c_str(), command.data(), nullptr, nullptr, FALSE,
                               CREATE_SUSPENDED | CREATE_NO_WINDOW, nullptr, nullptr, &startup,
                               &child.process),
                "Create suspended curl");
        const auto identity = processKey(child.process.hProcess, child.process.dwProcessId);
        const auto dll = QDir::toNativeSeparators(app.applicationDirPath() + "/WinDivert.dll").toStdWString();
        traffic::PacketCapture capture(
            dll, "outbound and ip and " + std::string(udp_probe ? "udp" : "tcp") +
                     " and ip.DstAddr == " + args[3].toStdString() +
                     (udp_probe ? " and udp.DstPort == 53" : " and tcp.DstPort == 443"));
        struct StopBeforeCaptureRelease {
            Child& child;
            ~StopBeforeCaptureRelease() { child.stop(); }
        };
        traffic::SelectedOwnerResolver resolver(dll, std::make_unique<ProcessTarget>(identity));
        ProcessTarget pinned(identity);
        traffic::SocketConnectGuard unsupported(dll, pinned,
                                                traffic::SocketConnectGuard::Mode::UnsupportedForIpv4TcpUdp);
        StopBeforeCaptureRelease stopChild{child};
        std::atomic_bool ready{};
        std::uint64_t selected{}, direct{}, held{};
        skewer::traffic::OwnerEvidence last_evidence{};
        SelectedSessionPackets packets(
            capture,
            [&](auto tuple) {
                const auto result = resolver.resolve(tuple, stop.get());
                using From = traffic::SelectedOwnerResolver::Disposition;
                using To = SelectedCaptureBridge::Disposition;
                const auto decision = result.disposition == From::Tunnel   ? To::Tunnel
                                      : result.disposition == From::Direct ? To::Direct
                                                                           : To::Hold;
                selected += decision == To::Tunnel;
                direct += decision == To::Direct;
                held += decision == To::Hold;
                last_evidence = result.evidence;
                return SelectedCaptureBridge::Resolution{decision, result.flow};
            },
            [&](auto flow) {
                return flow.process == skewer::traffic::ProcessIdentity{identity.pid, identity.created} &&
                       pinned.running();
            },
            stop.get(), ready);
        Worker worker(packets, child, stop.get());
        PskTunnelControl control(QUrl(args[1]), args[2]);
        auto run = std::async(std::launch::async, [&] {
            return runPairedTunnel(packets, control, args[2], stop.get(), ready, nullptr, &worker);
        });
        if (run.wait_for(std::chrono::seconds(40)) != std::future_status::ready) {
            SetEvent(stop.get());
            run.wait();
            throw std::runtime_error("Selected process fixture timed out");
        }
        const auto counters = run.get();
        DWORD exit{};
        const auto exit_read = GetExitCodeProcess(child.process.hProcess, &exit) != FALSE;
        if (!exit_read || exit != 0 || !selected || !counters.tx || !counters.rx) {
            std::ostringstream detail;
            detail << "Selected " << (udp_probe ? "DNS UDP" : "curl HTTPS")
                   << " did not complete through the tunnel: exit=";
            if (exit_read) {
                detail << exit;
            } else {
                detail << "unavailable (win32=" << GetLastError() << ')';
            }
            detail << " selected=" << selected << " direct=" << direct << " held=" << held
                   << " evidence=" << static_cast<unsigned>(last_evidence) << " tx=" << counters.tx
                   << " rx=" << counters.rx;
            throw std::runtime_error(detail.str());
        }
        QTextStream(stdout)
            << "PASS: separate selected " << (udp_probe ? "DNS UDP" : "curl HTTPS")
            << " via shared paired session" << (udp_probe ? "" : " (trust unchecked)")
            << " selected=" << selected << " direct=" << direct << " tx=" << counters.tx
            << " rx=" << counters.rx << '\n';
        return 0;
    } catch (const std::exception& error) {
        QTextStream(stderr) << error.what() << '\n';
        return 1;
    }
}
