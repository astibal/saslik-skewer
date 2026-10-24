#ifdef SKEWER_TEST_RELEASE_POLICY
#undef SKEWER_DEVELOPMENT_BINARY
#define SKEWER_DEVELOPMENT_BINARY 0
#endif
#include "tuntom_binary.hpp"
#include <QCoreApplication>
#include <QFile>
#include <QTemporaryDir>

int main(int argc, char** argv)
{
    QCoreApplication app(argc, argv);
    QTemporaryDir directory;
    if (!directory.isValid()) return 1;
    QFile binary(directory.path() + "/tuntom");
    if (!binary.open(QIODevice::WriteOnly)) return 2;
    binary.write("test fixture, never executed");
    binary.close();
    binary.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner);
    QString error;
    if (!Tuntom::checkedBinary(binary.fileName(), error).isEmpty()) return 3;
    const auto relaxed = Tuntom::checkedBinary(binary.fileName(), error, true);
    if (relaxed.isEmpty() == Tuntom::developmentBinaryAllowed) return 4;
    binary.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner);
    if (!Tuntom::checkedBinary(binary.fileName(), error, true).isEmpty()) return 5;
    if (!Tuntom::checkedBinary(directory.path(), error, true).isEmpty()) return 6;
    if (!Tuntom::checkedBinary("relative/tuntom", error, true).isEmpty()) return 7;
    if (!Tuntom::checkedBinary(directory.path()+"/missing", error, true).isEmpty()) return 8;
}
