#include "main_window.hpp"

#include <QApplication>
#include <QLabel>
#include <QLineEdit>
#include <QSettings>
#include <QTcpServer>
#include <QTcpSocket>
#include <QTemporaryDir>
#include <QTest>

int main(int argc, char** argv)
{
    QApplication app(argc, argv);
    QTemporaryDir config;
    QSettings::setDefaultFormat(QSettings::IniFormat);
    QSettings::setPath(QSettings::IniFormat, QSettings::UserScope, config.path());
    QCoreApplication::setOrganizationName("SkewerTest");
    QCoreApplication::setApplicationName("Status");
    QTcpServer server;
    if (!server.listen(QHostAddress::LocalHost)) return 1;
    bool malformed = false;
    bool correct_path = false;
    QObject::connect(&server, &QTcpServer::newConnection, [&] {
        auto* socket = server.nextPendingConnection();
        QObject::connect(socket, &QTcpSocket::readyRead, socket, [&, socket] {
            correct_path = socket->readAll().startsWith("GET /api/status ");
            const QByteArray body = malformed ? QByteArray("bad json") : QByteArray(R"({
                "identity":"lab-test", "runtime_state":"degraded",
                "services":{"smithproxy":{"state":"running","pid":123}},
                "health":{"end_to_end":{"stale":true,"sampled_at":1700000000,
                    "checks":{"tls":{"state":"ok"}}}}, "endpoints":{}})");
            socket->write("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
                          + QByteArray::number(body.size()) + "\r\nConnection: close\r\n\r\n" + body);
            socket->disconnectFromHost();
        });
        QObject::connect(socket, &QTcpSocket::disconnected, socket, &QObject::deleteLater);
    });
    MainWindow window;
    auto* input = window.findChild<QLineEdit*>("saslikInfoUrl");
    auto* text = window.findChild<QLabel*>("saslikInfoText");
    if (!input || !text) return 2;
    input->setText(QString("http://127.0.0.1:%1/api/skewer").arg(server.serverPort()));
    const auto wait_for = [&](const QString& needle) {
        for (int i = 0; i < 100 && !text->text().contains(needle); ++i) QTest::qWait(20);
        return text->text().contains(needle);
    };
    QMetaObject::invokeMethod(input, "editingFinished");
    if (!wait_for("Updated:") || !correct_path || !text->text().contains("lab-test")
        || !text->text().contains("stale") || !text->text().contains("tls: ok")) return 3;
    malformed = true;
    QMetaObject::invokeMethod(input, "editingFinished");
    if (!wait_for("Unavailable") || !text->text().contains("lab-test")) return 4;
    server.close();
    QMetaObject::invokeMethod(input, "editingFinished");
    QTest::qWait(200);
    if (!text->text().contains("Unavailable")) return 5;
    return 0;
}
