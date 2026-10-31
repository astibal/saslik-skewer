#pragma once
#include "processes.hpp"
#include <memory>
#include <optional>
#include <vector>
#include "windivert_api.hpp"

namespace skewer::windows::traffic {

// A worker-owned NETWORK handle. Not an application ownership or routing policy.
// Stop/join the consumer before destruction. No thread is created internally.
class PacketCapture final {
public:
    struct Packet {
        std::vector<std::uint8_t> bytes;
        WINDIVERT_ADDRESS address{};
    };
    enum class Status { Packet, Timeout, Cancelled };
    struct Result {
        Status status;
        std::optional<Packet> packet;
    };
    struct Stats {
        std::uint64_t captured_packets{}, captured_bytes{};
        std::uint64_t injected_packets{}, injected_bytes{};
    };
    // Only a trusted backend may construct the filter. Never expose raw filter
    // language through GUI/IPC. DLL must reside in a trusted local directory.
    PacketCapture(const std::wstring& dll, const std::string& filter);
    ~PacketCapture();
    PacketCapture(const PacketCapture&) = delete;
    PacketCapture& operator=(const PacketCapture&) = delete;

    // Timeout preserves pending I/O. Cancellation retires it and is terminal;
    // the handle remains open (still intercepting) until object destruction.
    Result next(HANDLE cancellation, DWORD timeout_ms);
    // Borrowed completion event. Consume with next(); never reset externally.
    // A completed read stays signalled until the next read is armed, allowing
    // the owner to interleave packet processing with transport/lease checks.
    HANDLE readEvent() const;
    // Explicit send only; neither timeout nor destruction forwards packets.
    // Capture metadata is preserved; this is reinjection, not tunnel routing.
    void reinject(Packet packet);
    Stats stats() const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

// Build an already-restored reply for a retained outbound capture. Require the
// entire reverse tuple, not just a port, before reusing its interface metadata.
// This does not authorize delivery: the caller must recheck the pinned owner
// and tunnel epoch immediately before reinjection.
PacketCapture::Packet restoredReply(const PacketCapture::Packet& original,
                                     std::vector<std::uint8_t> restored);
} // namespace skewer::windows::traffic
