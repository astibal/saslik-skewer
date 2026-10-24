#pragma once

#include <QByteArray>
#include <QMessageAuthenticationCode>
#include <stdexcept>

namespace Tuntom {
// Matches saslik.tuntom.tunnel_key: HKDF-SHA256, domain-separated from TLS.
// Context is public session metadata, never a replacement for the paired PSK.
inline QByteArray deriveKey(const QByteArray& psk, const QByteArray& context)
{
    if (psk.size() != 32 || context.size() != 64)
        throw std::invalid_argument("Invalid tuntom key context");
    for (const char c : context)
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            throw std::invalid_argument("Invalid tuntom key context");
    const auto prk = QMessageAuthenticationCode::hash(psk, QByteArray::fromHex(context), QCryptographicHash::Sha256);
    return QMessageAuthenticationCode::hash(QByteArray("saslik-skewer/tuntom/psk/v1") + char(1),
                                            prk, QCryptographicHash::Sha256).left(16);
}

enum class Mode { Auto, DirectOnly, TunnelOnly };
enum class Route { Direct, WaitForTunnel, Tunnel, Blocked };

// Once traffic entered a tunnel, losing it must not silently select direct
// routing. Explicit mode changes are handled by the privileged route owner.
inline Route selectRoute(Mode mode, bool directNextHop, bool tunnelReady, bool tunnelWasActive)
{
    if (mode == Mode::DirectOnly) return directNextHop ? Route::Direct : Route::Blocked;
    if (mode == Mode::TunnelOnly) return tunnelReady ? Route::Tunnel : Route::WaitForTunnel;
    if (tunnelWasActive) return tunnelReady ? Route::Tunnel : Route::Blocked;
    if (directNextHop) return Route::Direct;
    return tunnelReady ? Route::Tunnel : Route::WaitForTunnel;
}
} // namespace Tuntom
