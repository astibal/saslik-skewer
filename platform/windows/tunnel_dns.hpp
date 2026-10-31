#pragma once
#include <winsock2.h>
#include <netioapi.h>
#include <string>

namespace skewer::windows {
// Exclusively owned ephemeral Wintun adapter only. Adapter deletion removes
// its DNS configuration and explicit interface metric; physical adapters and
// global resolver policy are untouched.
void configureTunnelDns(NET_LUID adapter, const std::wstring& server);
} // namespace skewer::windows
