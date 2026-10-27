#pragma once
#include <QStringList>
#include <QJsonObject>
#include <QUrl>
#include "tuntom_control.hpp"
struct PairedTunnel {
    Tuntom::Endpoint endpoint;
    QByteArray key; // Derived transport key; never serialize into logs or argv.
};
PairedTunnel openPairedTunnel(const QUrl& endpoint, const QString& connect_host = {});
void heartbeatPairedTunnel(const QUrl& endpoint, const Tuntom::Endpoint& tunnel, const QString& connect_host = {});
void closePairedTunnel(const QUrl& endpoint, const Tuntom::Endpoint& tunnel, const QString& connect_host = {});
int pairingCommand(const QStringList& arguments);
int tuntomClientCommand(const QStringList& arguments);
QJsonObject pairedStatus(const QUrl& endpoint);
QJsonObject pairedRequest(const QUrl& endpoint, const QJsonObject& request);
