#include "paired_tunnel.hpp"
#include "selected_capture_bridge.hpp"
#include "selected_owner_resolver.hpp"
#include <QCoreApplication>
#include <QDir>
#include <QTextStream>
#include <algorithm>
#include <openssl/ssl.h>
#include <limits>

using namespace skewer::windows;
namespace {
void require(bool value, const char* message) {
    if (!value) {
        throw std::runtime_error(message);
    }
}
struct Socket {
    SOCKET value{INVALID_SOCKET};
    void close() {
        if (value != INVALID_SOCKET) {
            closesocket(value);
            value = INVALID_SOCKET;
        }
    }
    ~Socket() { close(); }
};
} // namespace
// Explicit elevated lab probe. No host routes or global filters are installed.
// Default scope is one exclusively bound source port. --broad is a bounded
// VM-only experiment intercepting all outbound IPv4 TCP, not a service mode.
int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    app.setOrganizationName("Saslik");
    app.setApplicationName("Skewer");
    const auto args = app.arguments();
    const bool tls = args.mid(5).contains("--tls");
    const bool broad = args.mid(5).contains("--broad");
    if (args.size() < 5 || args.size() > 7 ||
        std::any_of(args.begin() + std::min(5, int(args.size())), args.end(),
                    [](const auto& arg) { return arg != "--tls" && arg != "--broad"; })) {
        QTextStream(stderr)
            << "Usage: selected_tcp_live PAIRED_ENDPOINT PEER_IPV4 HTTP_IPV4 HTTP_HOST [--tls] [--broad]\n";
        return 2;
    }
    try {
        require(!args[4].isEmpty() && args[4].size() < 254 &&
                    args[4].toLatin1().toStdString().find_first_not_of(
                        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-") ==
                        std::string::npos,
                "Invalid HTTP host");
        WSADATA data{};
        require(WSAStartup(MAKEWORD(2, 2), &data) == 0, "Winsock startup failed");
        struct Cleanup {
            ~Cleanup() { WSACleanup(); }
        } cleanup;
        PskTunnelControl control(QUrl(args[1]), args[2]);
        auto paired = control.open();
        struct Lease {
            PskTunnelControl& control;
            PairedTunnel& paired;
            ~Lease() {
                std::fill(paired.key.begin(), paired.key.end(), 0);
                try {
                    control.close(paired.endpoint);
                } catch (...) {
                }
            }
        } lease{control, paired};
        require(paired.key.size() == 16 && paired.endpoint.leaseSeconds >= 30, "Invalid live probe lease");
        std::array<std::uint8_t, 4> address{};
        require(paired.endpoint.clientAddress.endsWith("/30") &&
                    InetPtonA(AF_INET, paired.endpoint.clientAddress.chopped(3).toLatin1().constData(),
                              address.data()) == 1,
                "Invalid tunnel address");
        const unsigned destinationPort = tls ? 443 : 80;
        sockaddr_in destination{};
        destination.sin_family = AF_INET;
        destination.sin_port = htons(destinationPort);
        require(InetPtonA(AF_INET, args[3].toLatin1().constData(), &destination.sin_addr) == 1,
                "Invalid HTTP address");
        const auto dll = QDir::toNativeSeparators(QCoreApplication::applicationDirPath() + "/WinDivert.dll")
                             .toStdWString();
        Socket source;
        source.value = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        require(source.value != INVALID_SOCKET, "Create TCP socket");
        const BOOL exclusive = TRUE;
        require(setsockopt(source.value, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
                           reinterpret_cast<const char*>(&exclusive), sizeof(exclusive)) == 0,
                "Reserve TCP socket");
        sockaddr_in local{};
        local.sin_family = AF_INET;
        require(bind(source.value, reinterpret_cast<const sockaddr*>(&local), sizeof(local)) == 0,
                "Bind TCP socket");
        int localSize = sizeof(local);
        require(getsockname(source.value, reinterpret_cast<sockaddr*>(&local), &localSize) == 0,
                "Read TCP port");
        traffic::PacketCapture capture(
            dll, broad
                     ? "outbound and ip and tcp"
                     : "outbound and ip and tcp and tcp.SrcPort == " + std::to_string(ntohs(local.sin_port)) +
                           " and ip.DstAddr == " + args[3].toStdString() +
                           " and tcp.DstPort == " + std::to_string(destinationPort));
        // Close the source before interception is destroyed, including exception paths.
        struct CloseBeforeGuard {
            Socket& socket;
            ~CloseBeforeGuard() { socket.close(); }
        } closeSocket{source};
        const auto identity = processKey(GetCurrentProcess(), GetCurrentProcessId());
        ProcessTarget pinned(identity);
        traffic::SelectedOwnerResolver resolver(dll, std::make_unique<ProcessTarget>(identity));
        Handle stop(CreateEventW(nullptr, TRUE, FALSE, nullptr));
        require(static_cast<bool>(stop), "Create cancellation event");
        TunnelPump* current = nullptr;
        const auto deadline = TunnelPump::Clock::now() + std::chrono::seconds(25);
        const auto healthy = [&] {
            return current && current->healthy(TunnelPump::Clock::now()) &&
                   TunnelPump::Clock::now() < deadline;
        };
        const auto live = [&](auto flow) {
            return flow.process == skewer::traffic::ProcessIdentity{identity.pid, identity.created} &&
                   pinned.running();
        };
        SelectedTunnelDevice device(address, live, healthy);
        UdpEndpoint udp(UdpAddress::numeric("0.0.0.0", 0));
        tuntom::ascon::key_type key{};
        std::copy(paired.key.begin(), paired.key.end(), key.begin());
        struct Wipe {
            tuntom::ascon::key_type& key;
            ~Wipe() { tuntom::secure_zero(key.data(), key.size()); }
        } wipe{key};
        TunnelPump pump(device, udp, UdpAddress::numeric(args[2].toStdString(), 40000 + paired.endpoint.id),
                        paired.endpoint.id, key);
        current = &pump;
        tuntom::secure_zero(key.data(), key.size());
        std::fill(paired.key.begin(), paired.key.end(), 0);
        while (!healthy() && TunnelPump::Clock::now() < deadline) {
            pump.step(TunnelPump::Clock::now());
            Sleep(2);
        }
        require(healthy(), "Paired tunnel handshake failed");
        std::uint64_t direct{}, held{};
        SelectedCaptureBridge bridge(
            capture, device,
            [&](auto tuple) {
                const auto result = resolver.resolve(tuple, stop.get());
                using Source = traffic::SelectedOwnerResolver::Disposition;
                using Target = SelectedCaptureBridge::Disposition;
                const auto action = result.disposition == Source::Tunnel   ? Target::Tunnel
                                    : result.disposition == Source::Direct ? Target::Direct
                                                                           : Target::Hold;
                if (action == Target::Direct) {
                    ++direct;
                }
                if (action == Target::Hold) {
                    ++held;
                }
                return SelectedCaptureBridge::Resolution{action, result.flow};
            },
            live, healthy);
        u_long nonblocking = 1;
        if (broad) {
            QTextStream(stdout) << "CAPTURE READY: outbound IPv4 TCP lab policy" << Qt::endl;
        }
        require(ioctlsocket(source.value, FIONBIO, &nonblocking) == 0, "Set nonblocking socket");
        require(connect(source.value, reinterpret_cast<const sockaddr*>(&destination), sizeof(destination)) ==
                        SOCKET_ERROR &&
                    WSAGetLastError() == WSAEWOULDBLOCK,
                "Expected diverted TCP connect");
        std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> context(nullptr, SSL_CTX_free);
        std::unique_ptr<SSL, decltype(&SSL_free)> connection(nullptr, SSL_free);
        if (tls) {
            context.reset(SSL_CTX_new(TLS_client_method()));
            require(static_cast<bool>(context), "Create TLS context");
            // Transport fixture only: inspect MITM connectivity without changing
            // any user/browser certificate store. This is not a trust test.
            SSL_CTX_set_verify(context.get(), SSL_VERIFY_NONE, nullptr);
            connection.reset(SSL_new(context.get()));
            require(connection && source.value <= static_cast<SOCKET>(std::numeric_limits<int>::max()),
                    "Create TLS connection");
            require(SSL_set_fd(connection.get(), static_cast<int>(source.value)) == 1 &&
                        SSL_set_tlsext_host_name(connection.get(), args[4].toLatin1().constData()) == 1,
                    "Configure TLS socket");
        }
        const auto retryTls = [&](int result) {
            const auto error = SSL_get_error(connection.get(), result);
            return error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE;
        };
        const auto request =
            ("GET / HTTP/1.0\r\nHost: " + args[4] + "\r\nConnection: close\r\n\r\n").toLatin1();
        int sent = 0;
        QByteArray response;
        bool connected = false, tlsReady = !tls;
        while (TunnelPump::Clock::now() < deadline) {
            pump.step(TunnelPump::Clock::now());
            require(healthy(), "Tunnel lost health; captured packets remain blocked");
            bridge.step(stop.get(), 2);
            if (!connected) {
                fd_set writable, errors;
                FD_ZERO(&writable);
                FD_ZERO(&errors);
                FD_SET(source.value, &writable);
                FD_SET(source.value, &errors);
                timeval poll{};
                require(select(0, nullptr, &writable, &errors, &poll) != SOCKET_ERROR, "Poll TCP connection");
                if (!FD_ISSET(source.value, &writable) && !FD_ISSET(source.value, &errors)) {
                    continue;
                }
                int error = 0, length = sizeof(error);
                require(getsockopt(source.value, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&error),
                                   &length) == 0 &&
                            !error,
                        "TCP connection failed");
                connected = true;
            }
            if (!tlsReady) {
                const auto result = SSL_connect(connection.get());
                if (result != 1) {
                    require(retryTls(result), "TLS handshake failed");
                    continue;
                }
                tlsReady = true;
            }
            if (sent < request.size()) {
                const auto n =
                    tls ? SSL_write(connection.get(), request.constData() + sent, request.size() - sent)
                        : send(source.value, request.constData() + sent, request.size() - sent, 0);
                if (n > 0) {
                    sent += n;
                } else if (tls) {
                    require(retryTls(n), "TLS write failed");
                    continue;
                } else {
                    const auto error = WSAGetLastError();
                    require(error == WSAEWOULDBLOCK || error == WSAENOTCONN, "TCP send failed");
                }
            }
            std::array<char, 4096> buffer{};
            const auto n = tls ? SSL_read(connection.get(), buffer.data(), buffer.size())
                               : recv(source.value, buffer.data(), buffer.size(), 0);
            if (n > 0) {
                response.append(buffer.data(), n);
            } else if (n == 0) {
                break;
            } else if (tls) {
                require(retryTls(n), "TLS read failed");
            } else {
                const auto error = WSAGetLastError();
                require(error == WSAEWOULDBLOCK || error == WSAENOTCONN, "TCP receive failed");
            }
            if (response.contains("\r\n\r\n")) {
                break;
            }
        }
        require(sent == request.size() && response.startsWith("HTTP/") && response.contains("\r\n\r\n"),
                "No complete HTTP response over selected tunnel");
        if (broad) {
            // Keep the policy alive briefly so the integration script can run
            // an independent, unselected client at the same time.
            const auto until = std::min(deadline, TunnelPump::Clock::now() + std::chrono::seconds(5));
            while (TunnelPump::Clock::now() < until) {
                pump.step(TunnelPump::Clock::now());
                require(healthy(), "Tunnel lost health during unrelated-client test");
                bridge.step(stop.get(), 2);
            }
        }
        QTextStream(stdout) << "PASS: selected " << (tls ? "HTTPS (trust not checked)" : "HTTP")
                            << " through paired Saslik: " << response.left(response.indexOf("\r\n"))
                            << " tx=" << pump.counters().tx << " rx=" << pump.counters().rx
                            << " direct=" << direct << " held=" << held << Qt::endl;
        source.close();
        bridge.stop();
        return 0;
    } catch (const std::exception& error) {
        QTextStream(stderr) << error.what() << Qt::endl;
        return 1;
    }
}
