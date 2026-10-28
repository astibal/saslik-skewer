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

    std::vector<std::uint8_t> query{
        0x53, 0x4b, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    };
    for (const auto& label : host.toLatin1().split('.')) {
        require(!label.isEmpty() && label.size() <= 63, "UDP child host invalid");
        query.push_back(static_cast<std::uint8_t>(label.size()));
        query.insert(query.end(), label.begin(), label.end());
    }
    query.insert(query.end(), {0x00, 0x00, 0x01, 0x00, 0x01});
    require(connect(socket, reinterpret_cast<const sockaddr*>(&server), sizeof(server)) == 0,
            "UDP child connect failed");
    // Let the passive SOCKET lifecycle and owner-table views converge before
    // the one-shot datagram. The production resolver remains fail-closed.
    Sleep(50);
    require(send(socket, reinterpret_cast<const char*>(query.data()), static_cast<int>(query.size()), 0) ==
                static_cast<int>(query.size()),
            "UDP child send failed");
    std::array<std::uint8_t, 2048> response{};
    const auto received = recv(socket, reinterpret_cast<char*>(response.data()),
                               static_cast<int>(response.size()), 0);
    require(received >= 12 && response[0] == query[0] && response[1] == query[1] &&
                (response[2] & 0x80) != 0,
            "UDP child DNS response failed");
    return 0;
}
int runHttpsDescendant(const QString& host, const QString& destination) {
    wchar_t system[MAX_PATH]{};
    const auto length = GetSystemDirectoryW(system, MAX_PATH);
    require(length && length < MAX_PATH, "Resolve descendant system directory");
    const auto curl = std::wstring(system) + L"\\curl.exe";
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
                    const std::wstring& name) {
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
    require(GetExitCodeProcess(child.process.hProcess, &exit) && exit == 0,
            "Service-routed curl HTTPS failed");
    QTextStream(stdout) << "PASS: independently launched selected process through SCM service\n";
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
    if (args.size() < 5 || args.size() > 7 ||
        (args.size() == 7 && args[6] != "--udp" && args[6] != "--descendant")) {
        QTextStream(stderr)
            << "Usage: selected_process_live PAIRED_ENDPOINT PEER_IPV4 DEST_IPV4 HOST "
               "[SERVICE [--udp|--descendant]|--udp]\n";
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
            const bool descendant_probe = args.size() == 7 && args[6] == "--descendant";
            const auto service_executable = descendant_probe ? app.applicationFilePath().toStdWString()
                                                              : executable;
            const auto child_arguments = descendant_probe
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
            throughService(service_executable, child_arguments, args[5].toStdWString());
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
