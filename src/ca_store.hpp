#pragma once
#include <QSslCertificate>
#include <QStringList>
#include <QVector>
struct CaStore {
    QString key, label, path;
    QStringList matches;
    bool system{}, available{}, installed{};
    QString detail;
    QString snap_name, snap_revision, snap_state;
};
// Every operation is bound to immutable certificate bytes, never a workspace name.
class CaStoreManager {
public:
    explicit CaStoreManager(QSslCertificate certificate);
    static QSslCertificate parse(const QByteArray& pem);
    [[nodiscard]] QString fingerprint() const;
    [[nodiscard]] QVector<CaStore> stores() const;
    [[nodiscard]] bool install(const CaStore& store, QString& error) const;
    [[nodiscard]] bool remove(const CaStore& store, QString& error) const;
private:
    QSslCertificate certificate_;
};
