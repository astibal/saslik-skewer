#include "selected_session_packets.hpp"
#include "tcp_selection_resolver.hpp"
#include "socket_connect_guard.hpp"
#include <QCoreApplication>
#include <QDir>
#include <QTextStream>
#include <future>

using namespace skewer::windows;
namespace {
void require(bool ok, const char* message) {
    if (!ok) {
        throw std::runtime_error(message);
    }
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
} // namespace

// Elevated, bounded development fixture: real independent curl process, pinned
// before its first instruction. Narrow destination capture; no host routes/DNS.
int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    app.setOrganizationName("Saslik");
    app.setApplicationName("Skewer");
    const auto args = app.arguments();
    if (args.size() != 5) {
        QTextStream(stderr) << "Usage: selected_process_live PAIRED_ENDPOINT PEER_IPV4 DEST_IPV4 HOST\n";
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
        wchar_t system[MAX_PATH]{};
        const auto length = GetSystemDirectoryW(system, MAX_PATH);
        require(length && length < MAX_PATH, "Resolve system directory");
        const auto executable = std::wstring(system) + L"\\curl.exe";
        auto command =
            (QString::fromStdWString(L"\"" + executable + L"\"") +
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
        traffic::PacketCapture capture(dll, "outbound and ip and tcp and ip.DstAddr == " +
                                                args[3].toStdString() + " and tcp.DstPort == 443");
        struct StopBeforeCaptureRelease {
            Child& child;
            ~StopBeforeCaptureRelease() { child.stop(); }
        };
        traffic::TcpSelectionResolver resolver(dll, std::make_unique<ProcessTarget>(identity));
        ProcessTarget pinned(identity);
        traffic::SocketConnectGuard unsupported(
            dll, pinned, traffic::SocketConnectGuard::Mode::UnsupportedForIpv4Tcp);
        StopBeforeCaptureRelease stopChild{child};
        std::atomic_bool ready{};
        std::uint64_t selected{}, direct{};
        SelectedSessionPackets packets(
            capture,
            [&](auto tuple) {
                const auto result = resolver.resolve(tuple, stop.get());
                using From = traffic::TcpSelectionResolver::Disposition;
                using To = SelectedCaptureBridge::Disposition;
                const auto decision = result.disposition == From::Tunnel   ? To::Tunnel
                                      : result.disposition == From::Direct ? To::Direct
                                                                           : To::Hold;
                selected += decision == To::Tunnel;
                direct += decision == To::Direct;
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
        require(GetExitCodeProcess(child.process.hProcess, &exit) && exit == 0 && selected && counters.tx &&
                    counters.rx,
                "Selected curl did not complete through the tunnel");
        QTextStream(stdout)
            << "PASS: separate selected curl HTTPS via shared paired session (trust unchecked)"
            << " selected=" << selected << " direct=" << direct << " tx=" << counters.tx
            << " rx=" << counters.rx << '\n';
        return 0;
    } catch (const std::exception& error) {
        QTextStream(stderr) << error.what() << '\n';
        return 1;
    }
}
