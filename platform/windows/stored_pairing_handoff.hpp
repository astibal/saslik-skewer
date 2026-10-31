#pragma once
#include "pairing_handoff.hpp"
#include <QUrl>

namespace skewer::windows {
// Runs as the desktop user, never SYSTEM. The connected pipe is authenticated
// against the installed SCM service before credentials leave this process.
void sendStoredPairing(HANDLE pipe, const std::wstring& service_name, const QUrl& endpoint, HANDLE cancel,
                       DWORD timeout_ms);
} // namespace skewer::windows
