#pragma once
#include <QStringList>
#include <QJsonObject>
#include <QUrl>
int pairingCommand(const QStringList& arguments);
QJsonObject pairedStatus(const QUrl& endpoint);
QJsonObject pairedRequest(const QUrl& endpoint, const QJsonObject& request);
