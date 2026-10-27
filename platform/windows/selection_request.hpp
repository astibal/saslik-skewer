#pragma once
#include "processes.hpp"
#include "../traffic/routing_scope.hpp"
#include <algorithm>
#include <array>
#include <span>
#include <stdexcept>

namespace skewer::windows {
// One message-mode pipe request, explicitly little-endian; never transmit a
// native C++ structure (padding and ABI are not part of the wire protocol).
// Version 1 only validates a selection. It does not enable routing.
using SelectionRequest = std::array<std::uint8_t, 20>;

// Deliberately no "routed" status: this operation only verifies identity.
enum class SelectionStatus : std::uint8_t {
    Verified = 0,
    InvalidRequest = 1,
    Denied = 2,
    ScopeUnsupported = 3
};
using SelectionReply = std::array<std::uint8_t, 8>;

inline SelectionReply encodeSelectionReply(SelectionStatus status) {
    if (static_cast<unsigned>(status) > static_cast<unsigned>(SelectionStatus::ScopeUnsupported)) {
        throw std::invalid_argument("Unknown selection status");
    }
    return {'S', 'K', 'W', 'A', 1, 0, static_cast<std::uint8_t>(status), 0};
}

inline SelectionStatus decodeSelectionReply(std::span<const std::uint8_t> bytes) {
    if (bytes.size() != SelectionReply{}.size() || bytes[0] != 'S' || bytes[1] != 'K' || bytes[2] != 'W' ||
        bytes[3] != 'A' || bytes[4] != 1 || bytes[5] != 0 ||
        bytes[6] > static_cast<unsigned>(SelectionStatus::ScopeUnsupported) || bytes[7] != 0) {
        throw std::invalid_argument("Invalid selection reply");
    }
    return static_cast<SelectionStatus>(bytes[6]);
}

inline SelectionRequest encodeSelectionRequest(ProcessKey key) {
    if (!key.pid || !key.created) {
        throw std::invalid_argument("Selection requires a complete process identity");
    }
    SelectionRequest result{'S', 'K', 'W', 'R', 1, 0, 1, 0};
    for (unsigned i = 0; i < 4; ++i) {
        result[8 + i] = static_cast<std::uint8_t>(key.pid >> (8 * i));
    }
    for (unsigned i = 0; i < 8; ++i) {
        result[12 + i] = static_cast<std::uint8_t>(key.created >> (8 * i));
    }
    return result;
}

inline ProcessKey decodeSelectionRequest(std::span<const std::uint8_t> bytes) {
    // Reject extensions, partial messages and reserved fields rather than
    // guessing what a newer or malformed client meant to authorize.
    constexpr std::array<std::uint8_t, 8> header{'S', 'K', 'W', 'R', 1, 0, 1, 0};
    if (bytes.size() != SelectionRequest{}.size()) {
        throw std::invalid_argument("Invalid selection request length");
    }
    for (unsigned i = 0; i < header.size(); ++i) {
        if (bytes[i] != header[i]) {
            throw std::invalid_argument("Unsupported selection request header");
        }
    }
    ProcessKey key{};
    for (unsigned i = 0; i < 4; ++i) {
        key.pid |= static_cast<DWORD>(bytes[8 + i]) << (8 * i);
    }
    for (unsigned i = 0; i < 8; ++i) {
        key.created |= static_cast<std::uint64_t>(bytes[12 + i]) << (8 * i);
    }
    if (!key.pid || !key.created) {
        throw std::invalid_argument("Selection requires a complete process identity");
    }
    return key;
}
// Operation 2 probes scope support; it never activates routing. Authenticate
// the supplied caller identity against the pipe token before answering.
inline SelectionRequest encodeScopeProbe(ProcessKey caller, skewer::traffic::RoutingScope scope) {
    if (scope != skewer::traffic::RoutingScope::Applications &&
        scope != skewer::traffic::RoutingScope::WholeHost) {
        throw std::invalid_argument("Invalid routing scope");
    }
    auto request = encodeSelectionRequest(caller);
    request[6] = 2;
    request[7] = scope == skewer::traffic::RoutingScope::WholeHost ? 1 : 0;
    return request;
}
struct ScopeProbe {
    ProcessKey caller;
    skewer::traffic::RoutingScope scope;
};
inline ScopeProbe decodeScopeProbe(std::span<const std::uint8_t> bytes) {
    if (bytes.size() != SelectionRequest{}.size() || bytes[6] != 2 || bytes[7] > 1) {
        throw std::invalid_argument("Invalid scope probe");
    }
    SelectionRequest normalized{};
    std::copy(bytes.begin(), bytes.end(), normalized.begin());
    normalized[6] = 1;
    normalized[7] = 0;
    return {decodeSelectionRequest(normalized), bytes[7] == 1 ? skewer::traffic::RoutingScope::WholeHost
                                                              : skewer::traffic::RoutingScope::Applications};
}
} // namespace skewer::windows
