#pragma once
#include "selection_transport.hpp"
#include <array>
#include <string>

namespace skewer::windows {
// Memory-only envelope. Endpoint semantics are validated by PairedControl
// before use; this transport grants neither routing nor startup permission.
struct PairingHandoff final {
    std::string endpoint;
    std::string identity;
    std::array<std::uint8_t, 32> key{};
    PairingHandoff() = default;
    ~PairingHandoff() { SecureZeroMemory(key.data(), key.size()); }
    PairingHandoff(const PairingHandoff&) = delete;
    PairingHandoff& operator=(const PairingHandoff&) = delete;
};

// Dedicated message-mode connection, one handoff only. Server authenticates
// the actual pipe client and binds it to an administrator-selected owner token
// BEFORE requesting the secret. Client pins the SCM server before any writes.
// Acknowledgement means validated delivery only, never "routing started".
void sendPairingHandoff(HANDLE pipe, const std::wstring& service_name, const PairingHandoff& value,
                        HANDLE cancel, DWORD timeout_ms);
std::unique_ptr<PairingHandoff> receivePairingHandoff(HANDLE pipe, HANDLE owner_token, HANDLE cancel,
                                                      DWORD timeout_ms);
} // namespace skewer::windows
