#include "processes.hpp"
#include "flow_tracking.hpp"
#include "pending_packets.hpp"
#include "packet_capture.hpp"
#include <array>
#include <bit>
#include <iostream>
#include <memory>
#include <stdexcept>
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

void exercise(HMODULE dll, const std::wstring& path, int family, bool tcp = false) {
    using namespace skewer::windows;
    const auto identity = processKey(GetCurrentProcess(), GetCurrentProcessId());
    // Start observing before creating traffic. A selected-PID observer proves
    // correlation only, not the absence of another process sharing a tuple.
    traffic::TrackedFlowObserver observer(path, identity);
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
            require(held.discard(*ticket), "UDP pending packet was lost");
            require(!readable(destination.value, 300), "Discarded datagram was delivered");
            continue;
        }
        // Outbound checksum offload can leave checksums incomplete. Preserve
        // the capture's routing metadata and calculate checksums before send.
        auto ready = held.take(*ticket, HoldingQueue::Clock::now());
        require(ready.has_value(), "Correlated packet expired before reinjection");
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
        captureLifecycle(path);
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL: " << error.what() << '\n';
        return 1;
    }
}
