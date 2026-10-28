#pragma once
#include <QStringList>
#include <QJsonObject>
#include <QUrl>
#include "tuntom_control.hpp"
#include <memory>
#include <functional>
struct PairedTunnel {
    Tuntom::Endpoint endpoint;
    QByteArray key; // Derived transport key; never serialize into logs or argv.
};

// One credential snapshot for the complete control lifetime. No persistence,
// argv serialization or logging. A service must authenticate its IPC peer
// before constructing this from handed-off credentials. Calls are sequential.
class PairedControl final {
public:
    PairedControl(QUrl endpoint, QByteArray identity, QByteArray key, QString connect_host = {});
    ~PairedControl();
    PairedControl(const PairedControl&) = delete;
    PairedControl& operator=(const PairedControl&) = delete;
    static std::unique_ptr<PairedControl> load(const QUrl& endpoint, const QString& connect_host = {});
    // Synchronous, borrowed snapshot for an authenticated service handoff only.
    // The consumer must not retain references, log credentials or persist them.
    using CredentialConsumer = std::function<void(const QUrl&, const QByteArray&, const QByteArray&)>;
    void withCredentials(const CredentialConsumer& consumer) const;
    PairedTunnel open();
    void renew(const Tuntom::Endpoint& tunnel);
    void close(const Tuntom::Endpoint& tunnel);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
PairedTunnel openPairedTunnel(const QUrl& endpoint, const QString& connect_host = {});
void heartbeatPairedTunnel(const QUrl& endpoint, const Tuntom::Endpoint& tunnel, const QString& connect_host = {});
void closePairedTunnel(const QUrl& endpoint, const Tuntom::Endpoint& tunnel, const QString& connect_host = {});
int pairingCommand(const QStringList& arguments);
int tuntomClientCommand(const QStringList& arguments);
QJsonObject pairedStatus(const QUrl& endpoint);
QJsonObject pairedRequest(const QUrl& endpoint, const QJsonObject& request);
