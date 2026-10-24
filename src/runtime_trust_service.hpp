#pragma once
#include <QByteArray>
#include <QString>
#include <QVector>

struct RuntimeResult { QString runtime, version, source, location, state, detail; };
QVector<RuntimeResult> discoverRuntimeTrust(const QByteArray& pem);
QString runtimeTrustDirectory(const QByteArray& pem);
QString prepareRuntimeTrust(const QByteArray& pem);
QString removeRuntimeTrust(const QByteArray& pem);
QString runtimeTrustEnvironment(const QByteArray& pem);
