#include "selected_service_tunnel.hpp"
#include "selected_session_packets.hpp"
#include "socket_connect_guard.hpp"
#include "selected_group_resolver.hpp"
#include "tcp_owners.hpp"
#include <QScopedValueRollback>
#include <algorithm>
#include <exception>
#include <vector>

namespace skewer::windows {
namespace {
class Runtime final : public PacketDevice, public TunnelPacketWorker {
public:
    Runtime(const std::wstring& dll, std::unique_ptr<ProcessTarget> target, const ServiceOwner& owner,
            std::string peer, std::uint16_t port, HANDLE cancel, std::atomic_bool& ready,
            std::atomic_bool& published,
            std::atomic_bool& blocked, std::atomic<RoutingStage>& stage,
            std::atomic<std::shared_ptr<const std::string>>& retry_error, RoutingSignals& control_state)
        : dll_(dll), peer_(std::move(peer)), port_(port), cancel_(cancel), ready_(ready),
          published_(published), blocked_(blocked), stage_(stage), retry_error_(retry_error),
          owner_(owner), signals_(control_state),
          resolver_(dll, std::move(target), owner, [this](const ProcessTarget& member) {
              unsupported_.push_back({member.key(), std::make_unique<traffic::SocketConnectGuard>(
                  dll_, member, traffic::SocketConnectGuard::Mode::UnsupportedForIpv4TcpUdp,
                  peer_, port_)});
              // Active descendants already traverse persistent packet capture.
              // Briefly denying connect here races their first socket and turns
              // healthy traffic into WSAEACCES. Keep the full guard for initial
              // enrollment, explicit Attach and transport recovery only.
              if (enrolling_root_ || !published_.load()) {
                  startup_.push_back({member.key(), std::make_unique<traffic::SocketConnectGuard>(
                      dll_, member, traffic::SocketConnectGuard::Mode::All)});
              }
          }) {
        // ProcessGroup has already adopted the live descendant tree. Drain its
        // notifications so every member is guarded before old IPv4 TCP sockets
        // are reset. Fresh attempts remain blocked until packet interception is
        // ready; launched suspended processes normally have nothing to reset.
        traffic::resetOwnedIpv4Tcp(resolver_.memberKeys());
        signals_.selection_supported = true;
        signals_.pause_supported = true;
        publishSelection();
        enrolling_root_ = false;
    }
    bool running() const { return resolver_.running(); }
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
                dll_, "outbound and (ip or ipv6) and ((ip and ip.DstAddr == " + peer_ +
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
                return resolver_.contains(flow.process) && running();
            },
            cancel_, ready_);
        try {
            packets_->setPaused(signals_.paused.load());
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
        applySelectionChange();
        applyPauseChange();
        if (GetTickCount64() >= next_membership_refresh_) publishSelection();
        if (!running()) {
            throw std::runtime_error("Selected process exited");
        }
        if (packets_) {
            packets_->poll();
            if (ready_.load()) {
                if (packets_->blocked()) {
                    throw std::runtime_error("Selected packet path retired while transport remained ready");
                }
                const bool paused = signals_.paused.load();
                if (!paused) startup_.clear();
                // Publish only after interception and removal of the startup
                // socket block, not merely after the transport handshake.
                published_ = !paused;
                blocked_ = paused;
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
    void applyPauseChange() {
        const auto request = signals_.pause_change.load();
        if (!request || !request->claim()) return;
        try {
            // The same worker owns capture, packet queues and tunnel I/O.
            // Acknowledge only after both directions have adopted the gate.
            if (packets_) packets_->setPaused(request->paused);
            signals_.paused = request->paused;
            if (request->paused) {
                published_ = false;
                blocked_ = true;
            }
            // Resume does not publish readiness here: poll() still verifies
            // transport health, and recovery carries pause intent to prepare().
            request->complete();
        } catch (const std::exception& error) {
            block();
            request->complete(error.what());
        }
    }
    void publishSelection() {
        // This runs only on the packet worker. Refresh installs guards before
        // exposing new members; readers receive an immutable coherent snapshot.
        SelectionSnapshot snapshot;
        snapshot.members = resolver_.memberKeys();
        snapshot.roots = resolver_.roots();
        const auto order = [](ProcessKey a, ProcessKey b) {
            return a.pid < b.pid || (a.pid == b.pid && a.created < b.created);
        };
        std::ranges::sort(snapshot.members, order);
        const auto previous = signals_.selection_snapshot.load();
        if (!previous || *previous != snapshot) {
            signals_.selection_snapshot = std::make_shared<const SelectionSnapshot>(std::move(snapshot));
        }
        next_membership_refresh_ = GetTickCount64() + 250;
    }
    void applySelectionChange() {
        const auto request = signals_.selection_change.load();
        if (!request || !request->claim()) return;
        try {
            if (request->operation == SelectionOperation::Add) {
                const QScopedValueRollback<bool> enrolling(enrolling_root_, true);
                const auto before = resolver_.memberKeys();
                resolver_.add(std::make_unique<ProcessTarget>(request->process, owner_));
                auto added = resolver_.memberKeys();
                std::erase_if(added, [&](auto key) { return std::ranges::find(before, key) != before.end(); });
                // Never reset sockets of an application that was already selected.
                traffic::resetOwnedIpv4Tcp(added);
                if (ready_.load() && !signals_.paused.load() && packets_ && !packets_->blocked())
                    startup_.clear();
            } else {
                const auto removed = resolver_.remove(request->process);
                for (const auto key : removed) {
                    if (packets_) packets_->releaseProcess({key.pid, key.created});
                }
                // Include guards from an enrollment that failed before its
                // observer was installed. Their Job membership is authoritative.
                const auto released = [&](const Guard& guard) { return !resolver_.covers(guard.process); };
                std::erase_if(startup_, released);
                std::erase_if(unsupported_, released);
            }
            publishSelection();
            request->complete();
        } catch (const std::exception& error) {
            publishSelection();
            request->complete(error.what());
        } catch (...) {
            request->complete("Selection change failed with an unknown exception");
        }
    }
    struct Guard {
        ProcessKey process;
        std::unique_ptr<traffic::SocketConnectGuard> handle;
    };
    std::wstring dll_;
    std::string peer_;
    std::uint16_t port_;
    HANDLE cancel_;
    std::atomic_bool& ready_;
    std::atomic_bool& published_;
    std::atomic_bool& blocked_;
    std::atomic<RoutingStage>& stage_;
    std::atomic<std::shared_ptr<const std::string>>& retry_error_;
    ServiceOwner owner_;
    RoutingSignals& signals_;
    ULONGLONG next_membership_refresh_{};
    std::vector<Guard> unsupported_;
    std::vector<Guard> startup_;
    // Initialized before resolver_: its constructor synchronously enrolls root.
    bool enrolling_root_{true};
    traffic::SelectedGroupResolver resolver_;
    std::unique_ptr<traffic::PacketCapture> capture_;
    std::unique_ptr<SelectedSessionPackets> packets_;
};
} // namespace
void runSelectedServiceTunnel(const std::wstring& dll, std::unique_ptr<ProcessTarget> target,
                              const ServiceOwner& owner, TunnelControl& control, const QString& peer,
                              std::uint16_t control_port,
                              HANDLE cancel, RoutingSignals& state) {
    if (!target || !target->running() || !control_port) {
        throw std::invalid_argument("Selected runtime requires a live authorized target and control port");
    }
    state.stage = RoutingStage::Preparing;
    std::atomic_bool transport_ready{};
    Runtime runtime(dll, std::move(target), owner, peer.toStdString(), control_port, cancel, transport_ready,
                    state.ready, state.blocked, state.stage, state.retry_error, state);
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
