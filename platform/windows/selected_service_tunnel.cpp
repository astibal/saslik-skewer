#include "selected_service_tunnel.hpp"
#include "selected_session_packets.hpp"
#include "socket_connect_guard.hpp"
#include "selected_owner_resolver.hpp"
#include <algorithm>
#include <exception>

namespace skewer::windows {
namespace {
class Runtime final : public PacketDevice, public TunnelPacketWorker {
public:
    Runtime(const std::wstring& dll, std::unique_ptr<ProcessTarget> target, std::string peer,
            std::uint16_t port, HANDLE cancel, std::atomic_bool& ready, std::atomic_bool& published,
            std::atomic_bool& blocked, std::atomic<RoutingStage>& stage,
            std::atomic<std::shared_ptr<const std::string>>& retry_error)
        : dll_(dll), peer_(std::move(peer)), port_(port), cancel_(cancel), ready_(ready),
          published_(published), blocked_(blocked), stage_(stage), retry_error_(retry_error),
          target_(target.get()), identity_(target->key()),
          resolver_(dll, std::move(target)),
          unsupported_(dll, *target_, traffic::SocketConnectGuard::Mode::UnsupportedForIpv4TcpUdp, peer_,
                       port_) {
        startup_ = std::make_unique<traffic::SocketConnectGuard>(dll, *target_,
                                                                 traffic::SocketConnectGuard::Mode::All);
    }
    bool running() const { return target_->running(); }
    void prepare(const Tuntom::Endpoint& endpoint) override {
        stage_ = RoutingStage::Intercepting;
        if (packets_ && !packets_->blocked()) {
            throw std::logic_error("Selected runtime already has a live packet generation");
        }
        packets_.reset();
        if (!capture_) {
            // The startup SOCKET guard already blocks the selected process, so
            // do not capture unrelated host packets during the first control
            // handshake. Once opened, keep interception across all reconnects.
            capture_ = std::make_unique<traffic::PacketCapture>(
                dll_, "outbound and ip and ((ip.DstAddr == " + peer_ +
                          " and ((udp.DstPort >= 40001 and udp.DstPort <= 40255) or tcp.DstPort == " +
                          std::to_string(port_) + ")) ? false : true)");
        }
        packets_ = std::make_unique<SelectedSessionPackets>(
            *capture_,
            [&](auto tuple) {
                const auto result = resolver_.resolve(tuple, cancel_);
                using From = traffic::SelectedOwnerResolver::Disposition;
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
            stage_ = RoutingStage::StartingSession;
        } catch (...) {
            // Persistent capture and the startup guard retain fail-closed
            // behavior. A later lease may create a fresh packet generation.
            packets_.reset();
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
                blocked_ = false;
                stage_ = RoutingStage::None;
                retry_error_.store({});
            }
        } else if (capture_) {
            // A failed packet-generation setup must not strand unrelated host
            // traffic behind the persistent capture handle. Unknown and
            // selected packets remain dropped while recovery is Blocked.
            auto packet = capture_->next(cancel_, 0);
            if (packet.packet) {
                const auto tuple = skewer::traffic::parsePacketTuple(packet.packet->bytes);
                if (tuple.tuple &&
                    resolver_.resolve(*tuple.tuple, cancel_).disposition ==
                        traffic::SelectedOwnerResolver::Disposition::Direct) {
                    capture_->reinject(std::move(*packet.packet));
                }
            }
        }
    }
    void block() noexcept override {
        published_ = false;
        blocked_ = true;
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
    std::atomic_bool& blocked_;
    std::atomic<RoutingStage>& stage_;
    std::atomic<std::shared_ptr<const std::string>>& retry_error_;
    const ProcessTarget* target_; // Owned by resolver_, never reopened under SYSTEM.
    ProcessKey identity_;
    traffic::SelectedOwnerResolver resolver_;
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
    state.stage = RoutingStage::Preparing;
    std::atomic_bool transport_ready{};
    Runtime runtime(dll, std::move(target), peer.toStdString(), control_port, cancel, transport_ready,
                    state.ready, state.blocked, state.stage, state.retry_error);
    state.stage = RoutingStage::Connecting;
    unsigned failures{};
    for (;;) {
        try {
            runPairedTunnel(runtime, control, peer, cancel, transport_ready, nullptr, &runtime,
                            &state.blocked);
            return;
        } catch (...) {
            const auto failure = std::current_exception();
            try {
                std::rethrow_exception(failure);
            } catch (const std::exception& error) {
                state.retry_error = std::make_shared<const std::string>(error.what());
            } catch (...) {
                state.retry_error =
                    std::make_shared<const std::string>("Tunnel retry failed with an unknown exception");
            }
            state.stage = RoutingStage::Connecting;
            transport_ready = false;
            state.ready = false;
            state.blocked = true;
            runtime.block();
            if (WaitForSingleObject(cancel, 0) == WAIT_OBJECT_0) return;
            if (!runtime.running()) std::rethrow_exception(failure);
            // Preserve capture while backing off. Direct decisions for other
            // processes are still reinjected; selected/unknown packets drop.
            const auto shift = std::min(failures, 4U);
            if (failures < 4U) ++failures;
            const auto delay = static_cast<DWORD>(250U << shift);
            const auto deadline = GetTickCount64() + delay;
            while (GetTickCount64() < deadline && runtime.running() &&
                   WaitForSingleObject(cancel, 0) == WAIT_TIMEOUT) {
                try {
                    runtime.poll();
                } catch (...) {
                    // Attribution failure is not permission to release capture.
                }
                WaitForSingleObject(cancel, 25);
            }
            if (WaitForSingleObject(cancel, 0) == WAIT_OBJECT_0) return;
            if (!runtime.running()) std::rethrow_exception(failure);
            // A successful generation clears Blocked from Runtime::poll().
            // Until then the authoritative service phase remains Blocked.
        }
    }
}
} // namespace skewer::windows
