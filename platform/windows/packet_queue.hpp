#pragma once
#include "packet_device.hpp"
#include "processes.hpp"
#include <algorithm>
#include <deque>
#include <stdexcept>
#include <vector>

namespace skewer::windows {
// Single-worker packet bridge for a policy/capture owner and TunnelPump.
// No ownership inference or direct-network fallback. The caller must authorize
// outbound packets and validate inbound tuples before injecting them anywhere.
class PacketQueue final : public PacketDevice {
public:
    explicit PacketQueue(std::size_t capacity = 64, std::size_t mtu = 1280)
        : capacity_(capacity), mtu_(mtu), event_(CreateEventW(nullptr, TRUE, FALSE, nullptr)) {
        if (!capacity || capacity > 4096 || !mtu || mtu > 65535 || !event_) {
            throw std::invalid_argument("Invalid packet queue bounds or event");
        }
    }
    bool enqueue(std::span<const std::uint8_t> packet) {
        if (!append(outgoing_, packet)) {
            return false;
        }
        if (!SetEvent(event_.get())) {
            stop();
            throw std::runtime_error("Packet queue event failed");
        }
        return true;
    }
    std::optional<std::vector<std::uint8_t>> takeReceived() {
        if (incoming_.empty()) {
            return std::nullopt;
        }
        auto packet = std::move(incoming_.front());
        incoming_.pop_front();
        return packet;
    }
    std::optional<std::size_t> readPacket(std::span<std::uint8_t> buffer) override {
        if (outgoing_.empty()) {
            return std::nullopt;
        }
        if (buffer.size() < outgoing_.front().size()) {
            throw std::invalid_argument("Packet queue output buffer too small");
        }
        const auto size = outgoing_.front().size();
        std::copy(outgoing_.front().begin(), outgoing_.front().end(), buffer.begin());
        outgoing_.pop_front();
        if (outgoing_.empty() && !ResetEvent(event_.get())) {
            stop();
            throw std::runtime_error("Packet queue event reset failed");
        }
        return size;
    }
    bool writePacket(std::span<const std::uint8_t> packet) override { return append(incoming_, packet); }
    HANDLE readEvent() const override { return event_.get(); }
    // Terminal, including queued replies. No packet survives a retired epoch.
    void stop() {
        stopped_ = true;
        outgoing_.clear();
        incoming_.clear();
        ResetEvent(event_.get());
    }

private:
    bool append(std::deque<std::vector<std::uint8_t>>& queue, std::span<const std::uint8_t> packet) {
        if (stopped_ || packet.empty() || packet.size() > mtu_ || queue.size() >= capacity_) {
            return false;
        }
        queue.emplace_back(packet.begin(), packet.end());
        return true;
    }
    const std::size_t capacity_, mtu_;
    Handle event_;
    bool stopped_{};
    std::deque<std::vector<std::uint8_t>> outgoing_, incoming_;
};
} // namespace skewer::windows
