#include "selected_session_packets.hpp"

namespace skewer::windows {
SelectedSessionPackets::SelectedSessionPackets(traffic::PacketCapture& capture,
                                               SelectedCaptureBridge::Resolver resolver,
                                               SelectedTunnelDevice::Live live, HANDLE cancel,
                                               std::atomic_bool& ready)
    : capture_(capture), resolver_(std::move(resolver)), live_(std::move(live)), cancel_(cancel),
      ready_(ready) {
    if (!resolver_ || !live_ || !cancel_ || cancel_ == INVALID_HANDLE_VALUE) {
        throw std::invalid_argument("Invalid selected packet session");
    }
}
void SelectedSessionPackets::prepare(const Tuntom::Endpoint& endpoint) {
    if (prepared_ || blocked_) {
        throw std::logic_error("Selected packet session cannot be reused");
    }
    prepared_ = true;
    std::array<std::uint8_t, 4> address{};
    if (!endpoint.clientAddress.endsWith("/30") ||
        InetPtonA(AF_INET, endpoint.clientAddress.chopped(3).toLatin1().constData(), address.data()) != 1 ||
        !address[0] || address[0] >= 224) {
        throw std::invalid_argument("Invalid selected tunnel IPv4 address");
    }
    const auto healthy = [this] {
        return !blocked_ && ready_.load() && WaitForSingleObject(cancel_, 0) == WAIT_TIMEOUT;
    };
    device_ = std::make_unique<SelectedTunnelDevice>(address, live_, healthy);
    bridge_ = std::make_unique<SelectedCaptureBridge>(capture_, *device_, resolver_, live_, healthy);
}
void SelectedSessionPackets::poll() {
    if (!bridge_) {
        throw std::logic_error("Selected packet session has not been prepared");
    }
    // A zero timeout leaves lease renewal/health checks in control of the loop.
    bridge_->step(cancel_, 0);
}
void SelectedSessionPackets::releaseProcess(skewer::traffic::ProcessIdentity process) {
    if (bridge_) bridge_->releaseProcess(process);
    else if (device_) device_->releaseProcess(process);
}
void SelectedSessionPackets::block() noexcept {
    blocked_ = true;
    if (bridge_) {
        bridge_->blockTunnel();
    } else if (device_) {
        device_->stop();
    }
}
HANDLE SelectedSessionPackets::readEvent() const {
    return device_ ? device_->readEvent() : nullptr;
}
std::optional<std::size_t> SelectedSessionPackets::readPacket(std::span<std::uint8_t> buffer) {
    return device_ ? device_->readPacket(buffer) : std::nullopt;
}
bool SelectedSessionPackets::writePacket(std::span<const std::uint8_t> packet) {
    return device_ && device_->writePacket(packet);
}
} // namespace skewer::windows
