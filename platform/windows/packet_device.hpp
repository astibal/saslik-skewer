#pragma once

#include <windows.h>
#include <cstdint>
#include <optional>
#include <span>

namespace skewer::windows {

// A single worker owns packet I/O. The event is borrowed for the device lifetime.
class PacketDevice {
public:
    virtual ~PacketDevice() = default;
    virtual std::optional<size_t> readPacket(std::span<uint8_t> buffer) = 0;
    virtual bool writePacket(std::span<const uint8_t> packet) = 0;
    virtual HANDLE readEvent() const = 0;
};

} // namespace skewer::windows
