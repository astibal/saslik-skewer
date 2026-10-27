#include "processes.hpp"
#include "flow_tracking.hpp"
#include "pending_packets.hpp"
#include "selected_packets.hpp"
#include "tcp_owners.hpp"
#include "packet_capture.hpp"
#include <algorithm>
#include <array>
#include <bit>
#include <iostream>
#include <memory>
#include <stdexcept>
#ifdef SKEWER_TEST_TUNNEL_PATH
#include "packet_queue.hpp"
#include "tunnel_pump.hpp"
#endif
#include <ws2tcpip.h>
#include <windivert.h>

// Explicit VM-only NETWORK/FLOW correlation experiment. Filters match only this
// fixture's bound loopback socket pair. No global ownership/routing claim.
namespace {
using skewer::windows::Handle;

void require(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

#ifdef SKEWER_TEST_TUNNEL_PATH
void tunnelDropsUnhealthy(const std::vector<std::uint8_t>& original) {
    using namespace skewer::windows;
    PacketQueue queue;
    UdpEndpoint udp(UdpAddress::numeric("127.0.0.1", 0)), silent_peer(UdpAddress::numeric("127.0.0.1", 0));
    tuntom::ascon::key_type key{};
    key.fill(0x74);
    TunnelPump pump(queue, udp, silent_peer.localAddress(), 92, key);
    require(queue.enqueue(original), "Queue rejected drop fixture");
    pump.step(TunnelPump::Clock::now());
    require(!pump.healthy(TunnelPump::Clock::now()) && pump.counters().not_ready == 1 &&
                pump.counters().tx == 0 && !queue.takeReceived(),
            "Unhealthy tunnel did not discard captured packet");
}

std::vector<std::uint8_t> tunnelRoundTrip(const std::vector<std::uint8_t>& original) {
    using namespace skewer::windows;
    PacketQueue local, remote;
    UdpEndpoint local_udp(UdpAddress::numeric("127.0.0.1", 0));
    UdpEndpoint remote_udp(UdpAddress::numeric("127.0.0.1", 0));
    tuntom::ascon::key_type key{};
    key.fill(0x73); // Public test key, never used by a production session.
    TunnelPump client(local, local_udp, remote_udp.localAddress(), 91, key);
    TunnelPump server(remote, remote_udp, local_udp.localAddress(), 91, key, true);
    const auto deadline = GetTickCount64() + 2000;
    while (GetTickCount64() < deadline) {
        const auto now = TunnelPump::Clock::now();
        client.step(now);
        server.step(now);
        if (client.healthy(now) && server.healthy(now)) {
            break;
        }
        Sleep(1);
    }
    require(client.healthy(TunnelPump::Clock::now()) && server.healthy(TunnelPump::Clock::now()),
            "Packet tunnel handshake failed");
    const auto identity = processKey(GetCurrentProcess(), GetCurrentProcessId());
    const skewer::traffic::ProcessIdentity expected{identity.pid, identity.created};
    ProcessTarget process(identity);
    skewer::traffic::SelectedPackets<unsigned> selected(expected, 4, 256 * 1024, std::chrono::seconds(3));
    const auto now = TunnelPump::Clock::now();
    const auto ticket = selected.hold(original, 0, now);
    require(ticket.has_value(), "Selection gate rejected fixture packet");
    auto authorized = selected.takeForTunnel(
        *ticket, now, process.running(), client.healthy(now), [&](auto candidate, auto) {
            // Both exclusive endpoints belong to this fixture. Flow observation
            // alone would NOT justify this result in a general application.
            require(candidate == *skewer::traffic::parsePacketTuple(original).tuple, "Wrong gated tuple");
            return skewer::traffic::PacketOwner{skewer::traffic::PacketOwner::State::Unique, expected};
        });
    require(authorized && local.enqueue(authorized->bytes), "Verified packet did not enter tunnel queue");
    bool traversed{};
    while (GetTickCount64() < deadline) {
        const auto now = TunnelPump::Clock::now();
        client.step(now);
        server.step(now);
        if (auto received = remote.takeReceived()) {
            require(*received == original, "Tunnel changed captured packet");
            require(remote.enqueue(*received), "Remote echo queue rejected packet");
            traversed = true;
        }
        if (auto received = local.takeReceived()) {
            require(traversed && *received == original, "Invalid tunnel return packet");
            std::cout << "PASS: captured packet crossed encrypted Tuntom transport before reinjection\n";
            // No direct fallback on transport failure; only this authenticated
            // round-trip result reaches the fixture's explicit reinjection.
            return std::move(*received);
        }
        Sleep(1);
    }
    throw std::runtime_error("Captured packet did not traverse encrypted tunnel");
}
#endif

template <typename Function> Function resolve(HMODULE dll, const char* name) {
    const auto symbol = GetProcAddress(dll, name);
    require(symbol != nullptr, name);
    return std::bit_cast<Function>(symbol);
}

struct Socket {
    SOCKET value{INVALID_SOCKET};
    explicit Socket(int family, bool tcp = false)
        : value(socket(family, tcp ? SOCK_STREAM : SOCK_DGRAM, tcp ? IPPROTO_TCP : IPPROTO_UDP)) {
        require(value != INVALID_SOCKET, "Create fixture socket");
    }
    ~Socket() { closesocket(value); }
    Socket(const Socket&) = delete;
    Socket& operator=(const Socket&) = delete;
};

sockaddr_storage bindLoopback(SOCKET socket, int family) {
    const BOOL exclusive = TRUE;
    require(setsockopt(socket, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, reinterpret_cast<const char*>(&exclusive),
                       sizeof(exclusive)) == 0,
            "Reserve exclusive fixture endpoint");
    sockaddr_storage address{};
    int size{};
    if (family == AF_INET) {
        auto& v4 = reinterpret_cast<sockaddr_in&>(address);
        v4.sin_family = AF_INET;
        v4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        size = sizeof(v4);
    } else {
        auto& v6 = reinterpret_cast<sockaddr_in6&>(address);
        v6.sin6_family = AF_INET6;
        v6.sin6_addr = in6addr_loopback;
        size = sizeof(v6);
    }
    require(bind(socket, reinterpret_cast<sockaddr*>(&address), size) == 0, "Bind loopback");
    require(getsockname(socket, reinterpret_cast<sockaddr*>(&address), &size) == 0, "Get bound endpoint");
    return address;
}

unsigned port(const sockaddr_storage& address) {
    return ntohs(address.ss_family == AF_INET ? reinterpret_cast<const sockaddr_in&>(address).sin_port
                                              : reinterpret_cast<const sockaddr_in6&>(address).sin6_port);
}

bool readable(SOCKET socket, long milliseconds) {
    fd_set set;
    FD_ZERO(&set);
    FD_SET(socket, &set);
    timeval timeout{milliseconds / 1000, (milliseconds % 1000) * 1000};
    const auto result = select(0, &set, nullptr, nullptr, &timeout);
    require(result != SOCKET_ERROR, "Wait for UDP delivery");
    return result != 0;
}

#ifdef SKEWER_TEST_TUNNEL_PATH
void tcpTunnel(const std::wstring& path, int family) {
    using namespace skewer::windows;
    Socket source(family, true), listener(family, true);
    const auto local = bindLoopback(source.value, family), remote = bindLoopback(listener.value, family);
    const auto ports = "((tcp.SrcPort == " + std::to_string(port(local)) +
                       " and tcp.DstPort == " + std::to_string(port(remote)) +
                       ") or (tcp.SrcPort == " + std::to_string(port(remote)) +
                       " and tcp.DstPort == " + std::to_string(port(local)) + "))";
    traffic::PacketCapture capture(path, std::string("outbound and loopback and tcp and ") +
                                             (family == AF_INET ? "ip and " : "ipv6 and ") + ports);
    Handle stop(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    require(static_cast<bool>(stop), "TCP tunnel stop event");
    require(listen(listener.value, 1) == 0, "TCP tunnel listen");
    u_long nonblocking = 1;
    require(ioctlsocket(source.value, FIONBIO, &nonblocking) == 0 &&
                ioctlsocket(listener.value, FIONBIO, &nonblocking) == 0,
            "TCP nonblocking sockets");
    require(connect(source.value, reinterpret_cast<const sockaddr*>(&remote),
                    family == AF_INET ? sizeof(sockaddr_in) : sizeof(sockaddr_in6)) == SOCKET_ERROR &&
                WSAGetLastError() == WSAEWOULDBLOCK,
            "TCP must wait for diverted SYN");
    auto first = capture.next(stop.get(), 2000);
    require(first.packet.has_value() && !readable(listener.value, 50), "TCP bypassed held SYN");
    first.packet->bytes = tunnelRoundTrip(first.packet->bytes);
    capture.reinject(std::move(*first.packet));
    struct Accepted {
        SOCKET value{INVALID_SOCKET};
        ~Accepted() {
            if (value != INVALID_SOCKET) {
                closesocket(value);
            }
        }
    } accepted;
    constexpr char payload[] = "tcp-through-encrypted-tunnel";
    bool sent{}, replied{};
    std::string received, returned;
    const auto deadline = GetTickCount64() + 8000;
    while (GetTickCount64() < deadline) {
        auto packet = capture.next(stop.get(), 5);
        if (packet.packet) {
            packet.packet->bytes = tunnelRoundTrip(packet.packet->bytes);
            capture.reinject(std::move(*packet.packet));
        }
        if (accepted.value == INVALID_SOCKET) {
            accepted.value = accept(listener.value, nullptr, nullptr);
            if (accepted.value == INVALID_SOCKET) {
                require(WSAGetLastError() == WSAEWOULDBLOCK, "TCP tunnel accept failed");
                continue;
            }
            require(ioctlsocket(accepted.value, FIONBIO, &nonblocking) == 0, "Accepted socket nonblocking");
        }
        if (!sent) {
            require(send(source.value, payload, sizeof(payload), 0) == sizeof(payload), "TCP fixture send");
            sent = true;
        }
        std::array<char, 128> buffer{};
        if (readable(accepted.value, 0)) {
            const auto n = recv(accepted.value, buffer.data(), buffer.size(), 0);
            require(n > 0, "TCP server receive failed");
            received.append(buffer.data(), n);
        }
        if (!replied && received.size() == sizeof(payload)) {
            require(received == std::string(payload, sizeof(payload)), "TCP outbound payload changed");
            require(send(accepted.value, payload, sizeof(payload), 0) == sizeof(payload), "TCP reply send");
            replied = true;
        }
        if (readable(source.value, 0)) {
            const auto n = recv(source.value, buffer.data(), buffer.size(), 0);
            require(n > 0, "TCP client receive failed");
            returned.append(buffer.data(), n);
        }
        if (returned.size() == sizeof(payload)) {
            require(returned == std::string(payload, sizeof(payload)), "TCP return payload changed");
            require(capture.stats().captured_packets >= 5, "TCP exchange bypassed capture");
            std::cout << "PASS: full TCP handshake and bidirectional payload through encrypted transport "
                      << (family == AF_INET ? "IPv4" : "IPv6") << '\n';
            return;
        }
    }
    throw std::runtime_error("TCP tunnel exchange timed out");
}
#endif

void exercise(HMODULE dll, const std::wstring& path, int family, bool tcp = false) {
    using namespace skewer::windows;
    const auto identity = processKey(GetCurrentProcess(), GetCurrentProcessId());
    // Start observing before creating traffic. A selected-PID observer proves
    // correlation only, not the absence of another process sharing a tuple.
    traffic::TrackedFlowObserver observer(path, identity);
    traffic::FlowObserver attempts(path, std::make_unique<ProcessTarget>(identity),
                                   traffic::FlowObserver::Mode::ConnectAttempts);
    Handle cancellation(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    require(static_cast<bool>(cancellation), "Create observer cancellation event");
    const auto open = resolve<decltype(&WinDivertOpen)>(dll, "WinDivertOpen");
    const auto close = resolve<decltype(&WinDivertClose)>(dll, "WinDivertClose");
    const auto receive = resolve<decltype(&WinDivertRecvEx)>(dll, "WinDivertRecvEx");
    const auto format =
        resolve<decltype(&WinDivertHelperFormatIPv6Address)>(dll, "WinDivertHelperFormatIPv6Address");
    struct Filter {
        HANDLE value;
        decltype(close) release;
        ~Filter() { release(value); }
    };
    const auto connect_filter =
        "processId == " + std::to_string(identity.pid) + " and event == CONNECT and protocol == TCP";
    const auto socket_handle = open(connect_filter.c_str(), WINDIVERT_LAYER_SOCKET, 0,
                                    WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_RECV_ONLY);
    require(socket_handle != INVALID_HANDLE_VALUE, "Open passive CONNECT observer");
    Filter socket_guard{socket_handle, close};
    Socket source(family, tcp), destination(family, tcp);
    const auto local = bindLoopback(source.value, family);
    const auto remote = bindLoopback(destination.value, family);
    const std::string protocol = tcp ? "tcp" : "udp";
    const auto filter = std::string("outbound and loopback and ") + protocol + " and " +
                        (family == AF_INET ? "ip" : "ipv6") + " and " + protocol +
                        ".SrcPort == " + std::to_string(port(local)) + " and " + protocol +
                        ".DstPort == " + std::to_string(port(remote));
    if (tcp) {
        require(listen(destination.value, 1) == 0, "Listen for fixture connection");
        u_long nonblocking = 1;
        require(ioctlsocket(source.value, FIONBIO, &nonblocking) == 0, "Make connect nonblocking");
    }
    traffic::PacketCapture capture(path, filter);
    require(capture.next(cancellation.get(), 1).status == traffic::PacketCapture::Status::Timeout,
            "Idle capture did not time out");
    using HoldingQueue = skewer::traffic::PendingPackets<WINDIVERT_ADDRESS>;
    HoldingQueue held(4, 256 * 1024, std::chrono::seconds(3));

    for (bool reinject : {true, false}) {
        if (tcp && reinject) {
            // TCP scope here is the first SYN and attribution before handshake,
            // not a complete bidirectional TCP reinjection loop.
            continue;
        }
        // Always retire the request before stack buffers go out of scope,
        // including timeout and assertion failures after an asynchronous start.
        struct PendingRead {
            HANDLE handle;
            OVERLAPPED* operation;
            ~PendingRead() {
                CancelIoEx(handle, operation);
                DWORD ignored{};
                GetOverlappedResult(handle, operation, &ignored, TRUE);
            }
        };
        constexpr char payload[] = "skewer-network-fixture";
        const auto size = family == AF_INET ? sizeof(sockaddr_in) : sizeof(sockaddr_in6);
        if (tcp) {
            const auto result =
                connect(source.value, reinterpret_cast<const sockaddr*>(&remote), static_cast<int>(size));
            require(result == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK,
                    "TCP connect did not wait for held SYN");
        } else {
            require(sendto(source.value, payload, sizeof(payload), 0,
                           reinterpret_cast<const sockaddr*>(&remote),
                           static_cast<int>(size)) == sizeof(payload),
                    "Send fixture datagram");
        }
        auto captured = capture.next(cancellation.get(), 3000);
        require(captured.status == traffic::PacketCapture::Status::Packet && captured.packet.has_value(),
                "Capture deadline exceeded");
        const auto& packet = captured.packet->bytes;
        const auto& address = captured.packet->address;
        require(address.Outbound && address.Loopback &&
                    static_cast<bool>(address.IPv6) == (family == AF_INET6),
                "Invalid captured metadata");
        const auto ticket = held.hold(packet, address, HoldingQueue::Clock::now());
        require(ticket.has_value(), "Fixture holding queue rejected packet");
        require(!readable(destination.value, 100), "Packet leaked before reinjection");
        const auto parsed = skewer::traffic::parsePacketTuple(packet);
        require(parsed.status == skewer::traffic::TupleStatus::Parsed && parsed.tuple.has_value(),
                "Decode captured packet tuple");
        if (tcp) {
            const auto attempt = attempts.next(cancellation.get(), 2000);
            require(attempt.status == traffic::FlowObserver::Status::Event && attempt.event &&
                        attempt.event->kind == traffic::FlowEvent::Kind::ConnectAttempt &&
                        attempt.event->process == identity &&
                        traffic::flowTuple(*attempt.event) == parsed.tuple,
                    "Reusable CONNECT observer did not match the held SYN");
            const auto snapshot = traffic::captureTcpOwners();
            const auto candidates = traffic::tcpOwnerCandidates(snapshot.rows, *parsed.tuple);
            require(std::find(candidates.begin(), candidates.end(), identity.pid) != candidates.end(),
                    "Independent TCP table did not contain held-SYN owner");
            Handle socket_event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
            require(static_cast<bool>(socket_event), "Create CONNECT event");
            WINDIVERT_ADDRESS connect_address{};
            UINT connect_size = sizeof(connect_address), bytes{};
            OVERLAPPED connect_operation{};
            connect_operation.hEvent = socket_event.get();
            const auto ok = receive(socket_handle, nullptr, 0, &bytes, 0, &connect_address, &connect_size,
                                    &connect_operation);
            require(ok || GetLastError() == ERROR_IO_PENDING, "Receive CONNECT metadata");
            PendingRead connect_pending{socket_handle, &connect_operation};
            require(WaitForSingleObject(socket_event.get(), 2000) == WAIT_OBJECT_0,
                    "CONNECT metadata deadline exceeded");
            DWORD complete{};
            require(GetOverlappedResult(socket_handle, &connect_operation, &complete, FALSE),
                    "Complete CONNECT metadata");
            require(connect_size == sizeof(connect_address) &&
                        connect_address.Layer == WINDIVERT_LAYER_SOCKET &&
                        connect_address.Event == WINDIVERT_EVENT_SOCKET_CONNECT &&
                        connect_address.Socket.ProcessId == identity.pid &&
                        connect_address.Socket.Protocol == IPPROTO_TCP,
                    "Unexpected CONNECT metadata");
            std::array<char, 64> local_text{}, remote_text{};
            require(format(connect_address.Socket.LocalAddr, local_text.data(), local_text.size()) &&
                        format(connect_address.Socket.RemoteAddr, remote_text.data(), remote_text.size()),
                    "Format CONNECT endpoints");
            traffic::FlowEvent connection;
            connection.ipv6 = connect_address.IPv6;
            connection.protocol = IPPROTO_TCP;
            connection.local = {local_text.data(), connect_address.Socket.LocalPort};
            connection.remote = {remote_text.data(), connect_address.Socket.RemotePort};
            // Reuse endpoint normalization only. A CONNECT attempt is not an
            // established FLOW and must not be inserted as one in its cache.
            require(traffic::flowTuple(connection) == parsed.tuple,
                    "CONNECT endpoints do not match the held first SYN");
            require(!readable(destination.value, 300), "TCP completed while its SYN was held");
            require(held.discard(*ticket), "TCP pending packet was lost");
            continue;
        }
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
        auto owner = observer.lookup(*parsed.tuple);
        while (owner.status == skewer::traffic::FlowIndex::Status::Unknown &&
               std::chrono::steady_clock::now() < deadline) {
            const auto result = observer.next(cancellation.get(), 100);
            require(result.status == traffic::FlowObserver::Status::Event ||
                        result.status == traffic::FlowObserver::Status::Timeout,
                    "Flow observer unexpectedly stopped");
            owner = observer.lookup(*parsed.tuple);
        }
        const skewer::traffic::ProcessIdentity expected{identity.pid, identity.created};
        require(owner.status == skewer::traffic::FlowIndex::Status::Observed && owner.process == expected,
                "Held first packet could not be correlated with fixture process");
        const auto reverse = observer.lookup(parsed.tuple->reversed());
        require(reverse.status == skewer::traffic::FlowIndex::Status::Observed && reverse.process == expected,
                "Reverse tuple lost fixture identity");
        require(!readable(destination.value, 100), "Packet leaked while awaiting flow metadata");
        if (!reinject) {
#ifdef SKEWER_TEST_TUNNEL_PATH
            auto dropped = held.take(*ticket, HoldingQueue::Clock::now());
            require(dropped.has_value(), "Missing captured drop fixture");
            tunnelDropsUnhealthy(dropped->bytes);
#else
            require(held.discard(*ticket), "UDP pending packet was lost");
#endif
            require(!readable(destination.value, 300), "Discarded datagram was delivered");
            continue;
        }
        // Outbound checksum offload can leave checksums incomplete. Preserve
        // the capture's routing metadata and calculate checksums before send.
        auto ready = held.take(*ticket, HoldingQueue::Clock::now());
        require(ready.has_value(), "Correlated packet expired before reinjection");
#ifdef SKEWER_TEST_TUNNEL_PATH
        ready->bytes = tunnelRoundTrip(ready->bytes);
        require(!readable(destination.value, 100), "Packet escaped while traversing tunnel");
#endif
        capture.reinject({std::move(ready->bytes), ready->context});
        require(readable(destination.value, 3000), "Reinjected packet not delivered");
        std::array<char, 128> delivered{};
        const auto count = recv(destination.value, delivered.data(), static_cast<int>(delivered.size()), 0);
        require(count == sizeof(payload) &&
                    std::string(delivered.data(), count) == std::string(payload, sizeof(payload)),
                "Reinjected payload changed");
    }
    const auto stats = capture.stats();
    require(stats.captured_packets == (tcp ? 1u : 2u) && stats.injected_packets == (tcp ? 0u : 1u) &&
                stats.captured_bytes > stats.injected_bytes,
            "Capture counters mismatch");
    require(SetEvent(cancellation.get()), "Signal capture cancellation");
    require(attempts.next(cancellation.get(), 0).status == traffic::FlowObserver::Status::Cancelled,
            "CONNECT observer ignored cancellation");
    require(capture.next(cancellation.get(), 100).status == traffic::PacketCapture::Status::Cancelled,
            "Capture did not cancel");
    require(ResetEvent(cancellation.get()), "Reset cancellation fixture");
    require(capture.next(cancellation.get(), 0).status == traffic::PacketCapture::Status::Cancelled,
            "Cancelled capture restarted");
    bool rejected{};
    try {
        capture.reinject({});
    } catch (const std::logic_error&) {
        rejected = true;
    }
    require(rejected, "Cancelled capture allowed send");
    std::cout
        << "PASS: " << protocol << " " << (family == AF_INET ? "IPv4" : "IPv6")
        << (tcp ? " first SYN matches SOCKET CONNECT before handshake; connection remains blocked"
                : " held packet correlates with PID + creation time; reinjection delivers, discard drops")
        << std::endl;
}
void captureLifecycle(const std::wstring& path) {
    using Capture = skewer::windows::traffic::PacketCapture;
    Handle cancellation(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    require(static_cast<bool>(cancellation), "Create lifecycle cancellation event");
    {
        // An impossible filter permits deterministic pending-I/O teardown
        // without capturing unrelated host traffic.
        Capture capture(path, "false");
        require(capture.next(cancellation.get(), 1).status == Capture::Status::Timeout, "Idle timeout");
        require(capture.next(cancellation.get(), 1).status == Capture::Status::Timeout, "Pending read reuse");
        require(SetEvent(cancellation.get()), "Signal pending read cancellation");
        require(capture.next(cancellation.get(), 100).status == Capture::Status::Cancelled,
                "Pending read cancellation failed");
        require(capture.stats().captured_packets == 0, "Idle capture counted traffic");
    }
    require(ResetEvent(cancellation.get()), "Reset lifecycle cancellation");
    {
        Capture capture(path, "false");
        require(capture.next(cancellation.get(), 1).status == Capture::Status::Timeout, "Teardown timeout");
        // Destructor must drain the outstanding request before freeing buffers.
    }
    std::cout << "PASS: timeout reuse, pending cancellation and pending destruction" << std::endl;
}
} // namespace

int wmain(int argc, wchar_t** argv) {
    try {
        require(argc == 2, "Usage: packet_divert_test ABSOLUTE_TRUSTED_WINDIVERT_DLL");
        const std::wstring path(argv[1]);
        const bool drive =
            !path.empty() && ((path[0] >= L'A' && path[0] <= L'Z') || (path[0] >= L'a' && path[0] <= L'z'));
        require(path.size() >= 4 && drive && path[1] == L':' && path[2] == L'\\',
                "Absolute local DLL path required");
        WSADATA data{};
        require(WSAStartup(MAKEWORD(2, 2), &data) == 0, "Initialize Winsock");
        struct Winsock {
            ~Winsock() { WSACleanup(); }
        } winsock;
        const auto module = LoadLibraryExW(path.c_str(), nullptr,
                                           LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
        require(module != nullptr, "Load trusted WinDivert DLL");
        std::shared_ptr<void> library(module, [](void* value) { FreeLibrary(static_cast<HMODULE>(value)); });
        exercise(module, path, AF_INET);
        exercise(module, path, AF_INET6);
        exercise(module, path, AF_INET, true);
        exercise(module, path, AF_INET6, true);
#ifdef SKEWER_TEST_TUNNEL_PATH
        tcpTunnel(path, AF_INET);
        tcpTunnel(path, AF_INET6);
#endif
        captureLifecycle(path);
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL: " << error.what() << '\n';
        return 1;
    }
}
