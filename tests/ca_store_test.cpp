#include "ca_store.hpp"

#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QTemporaryDir>

int main(int argc, char** argv)
{
    QTemporaryDir home;
    if (!home.isValid()) return 1;
    qputenv("HOME", home.path().toUtf8());
    QCoreApplication app(argc, argv);
    const QString profile = home.path() + QStringLiteral("/.mozilla/firefox/test.default");
    if (!QDir().mkpath(profile)) return 2;
    QFile database(profile + QStringLiteral("/cert9.db"));
    if (!database.open(QIODevice::WriteOnly)) return 3;
    database.close();

    const auto stores = CaStoreManager(QStringLiteral("lab1")).stores();
    for (const CaStore& store : stores) {
        if (store.key == QStringLiteral("firefox"))
            return store.databases == QStringList{profile} ? 0 : 4;
    }
    return 5;
}
