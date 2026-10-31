#include "diagnostic_log.hpp"

#include <QCoreApplication>
#include <QFile>
#include <QStandardPaths>

#include <cstdio>

#define CHECK(condition) do { \
    if (!(condition)) { \
        std::fprintf(stderr, "Check failed at line %d: %s\n", __LINE__, #condition); \
        return 1; \
    } \
} while (0)

int main(int argc, char** argv)
{
    QCoreApplication application(argc, argv);
    QCoreApplication::setOrganizationName("SkewerTest");
    QCoreApplication::setApplicationName("DiagnosticLog");
    QStandardPaths::setTestModeEnabled(true);

    DiagnosticLog::component = "app";
    const QString secret = QStringLiteral("DO_NOT_EXPORT_THIS_TOKEN");
    CHECK(DiagnosticLog::write("windows-test", "token=" + secret));

    QFile log(DiagnosticLog::directory() + "/app.log");
    CHECK(log.open(QIODevice::ReadOnly));
    const QByteArray contents = log.readAll();
    CHECK(contents.contains("windows-test"));
    CHECK(!contents.contains(secret.toUtf8()));
    return 0;
}
