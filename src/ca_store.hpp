#pragma once

#include <QString>
#include <QStringList>
#include <QVector>

struct CaStore {
    QString key;
    QString label;
    QStringList databases;
    bool system{};
    bool available{};
    bool installed{};
};

class CaStoreManager {
public:
    explicit CaStoreManager(QString identity);

    [[nodiscard]] QVector<CaStore> stores() const;
    [[nodiscard]] bool install(const QString& key, const QString& certificate, QString& error) const;
    [[nodiscard]] bool remove(const QString& key, QString& error) const;

private:
    [[nodiscard]] QString nickname() const;
    [[nodiscard]] QVector<CaStore> discovered() const;
    [[nodiscard]] bool modifyNss(const CaStore& store, const QString& certificate,
                                 bool remove, QString& error) const;
    [[nodiscard]] bool modifySystem(const QString& certificate, bool remove,
                                    QString& error) const;
    QString identity_;
};
