#include "selected_service_tunnel.hpp"
#include "selected_session_packets.hpp"
#include "socket_connect_guard.hpp"
#include "tcp_selection_resolver.hpp"

namespace skewer::windows {
namespace {
class Runtime final : public PacketDevice, public TunnelPacketWorker {
public:
    Runtime(const std::wstring& dll, std::unique_ptr<ProcessTarget> target, std::string peer,
            std::uint16_t port, HANDLE cancel, std::atomic_bool& ready, std::atomic_bool& published)
        : dll_(dll), peer_(std::move(peer)), port_(port), cancel_(cancel), ready_(ready),
          published_(published), target_(target.get()), identity_(target->key()),
          resolver_(dll, std::move(target)),
          unsupported_(dll, *target_, traffic::SocketConnectGuard::Mode::UnsupportedForIpv4Tcp, peer_,
                       port_) {
        startup_ = std::make_unique<traffic::SocketConnectGuard>(dll, *target_,
                                                                 traffic::SocketConnectGuard::Mode::All);
    }
    bool running() const { return target_->running(); }
    void prepare(const Tuntom::Endpoint& endpoint) override {
        if (capture_) {
            throw std::logic_error("Selected runtime cannot be prepared twice");
        }
        // Only the configured control endpoint bypasses NETWORK capture. Its
        // matching SOCKET guard denies the selected process this direct path.
        // This also lets renewal/close finish while packet processing is blocked.
        capture_ = std::make_unique<traffic::PacketCapture>(
            dll_, "outbound and ip and tcp and (ip.DstAddr == " + peer_ +
                      " and tcp.DstPort == " + std::to_string(port_) + " ? false : true)");
        packets_ = std::make_unique<SelectedSessionPackets>(
            *capture_,
            [&](auto tuple) {
                const auto result = resolver_.resolve(tuple, cancel_);
                using From = traffic::TcpSelectionResolver::Disposition;
                using To = SelectedCaptureBridge::Disposition;
                const auto action = result.disposition == From::Tunnel   ? To::Tunnel
                                    : result.disposition == From::Direct ? To::Direct
                                                                         : To::Hold;
                return SelectedCaptureBridge::Resolution{action, result.flow};
            },
            [&](auto flow) {
                return flow.process == skewer::traffic::ProcessIdentity{identity_.pid, identity_.created} &&
                       running();
            },
            cancel_, ready_);
        try {
            packets_->prepare(endpoint);
        } catch (...) {
            // Startup guard still denies new selected attempts. Do not strand
            // unrelated traffic behind an incompletely initialized bridge.
            packets_.reset();
            capture_.reset();
            throw;
        }
    }
    void poll() override {
        if (!running()) {
            throw std::runtime_error("Selected process exited");
        }
        if (packets_) {
            packets_->poll();
            if (ready_.load()) {
                if (packets_->blocked()) {
                    throw std::runtime_error("Selected packet path retired while transport remained ready");
                }
                startup_.reset();
                // Publish only after interception and removal of the startup
                // socket block, not merely after the transport handshake.
                published_ = true;
            }
        }
    }
    void block() noexcept override {
        published_ = false;
        if (packets_) {
            packets_->block();
        }
    }
    HANDLE readEvent() const override { return packets_ ? packets_->readEvent() : nullptr; }
    HANDLE captureEvent() const override { return packets_ ? packets_->captureEvent() : nullptr; }
    std::optional<std::size_t> readPacket(std::span<std::uint8_t> buffer) override {
        return packets_ ? packets_->readPacket(buffer) : std::nullopt;
    }
    bool writePacket(std::span<const std::uint8_t> packet) override {
        return packets_ && packets_->writePacket(packet);
    }

private:
    std::wstring dll_;
    std::string peer_;
    std::uint16_t port_;
    HANDLE cancel_;
    std::atomic_bool& ready_;
    std::atomic_bool& published_;
    const ProcessTarget* target_; // Owned by resolver_, never reopened under SYSTEM.
    ProcessKey identity_;
    traffic::TcpSelectionResolver resolver_;
    traffic::SocketConnectGuard unsupported_;
    std::unique_ptr<traffic::SocketConnectGuard> startup_;
    std::unique_ptr<traffic::PacketCapture> capture_;
    std::unique_ptr<SelectedSessionPackets> packets_;
};
} // namespace
void runSelectedServiceTunnel(const std::wstring& dll, std::unique_ptr<ProcessTarget> target,
                              TunnelControl& control, const QString& peer, std::uint16_t control_port,
                              HANDLE cancel, RoutingSignals& state) {
    if (!target || !target->running() || !control_port) {
        throw std::invalid_argument("Selected runtime requires a live authorized target and control port");
    }
    std::atomic_bool transport_ready{};
    Runtime runtime(dll, std::move(target), peer.toStdString(), control_port, cancel, transport_ready,
                    state.ready);
    try {
        runPairedTunnel(runtime, control, peer, cancel, transport_ready, nullptr, &runtime);
    } catch (...) {
        const auto error = std::current_exception();
        state.ready = false;
        state.blocked = true;
        runtime.block();
        // Tunnel failure must not close interception. Continue independent
        // Direct decisions until explicit Stop or the pinned process exits.
        while (WaitForSingleObject(cancel, 2) == WAIT_TIMEOUT && runtime.running()) {
            try {
                runtime.poll();
            } catch (...) {
                // If attribution itself is unavailable, keep interception and
                // report Blocked rather than guessing that packets are unrelated.
                WaitForSingleObject(cancel, 25);
            }
        }
        std::rethrow_exception(error);
    }
}
} // namespace skewer::windows
