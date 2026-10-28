#pragma once
#include "routing_control.hpp"
#include "pairing_handoff.hpp"

namespace skewer::windows {
// The installed service selects its owner token and pipe name. Neither can be
// supplied by a connecting client. Pairing remains memory-only and immutable
// throughout a routing generation; closing the client never stops that generation.
using PairedRoutingRunner = std::function<void(const PairingHandoff&, HANDLE, RoutingSignals&)>;
using SelectedRoutingRunner = std::function<void(const PairingHandoff&, std::unique_ptr<ProcessTarget>,
                                                HANDLE, RoutingSignals&)>;
void serveRoutingService(const std::wstring& name, HANDLE owner_token, HANDLE stop,
                         PairedRoutingRunner runner);
void serveRoutingService(const std::wstring& name, const ServiceOwner& owner, HANDLE stop,
                         PairedRoutingRunner runner, SelectedRoutingRunner selected = {});
} // namespace skewer::windows
