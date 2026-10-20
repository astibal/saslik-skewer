#include "main_window.hpp"

#include <QApplication>
#include <QAction>
#include <QSystemTrayIcon>
#include <QLabel>
#include <QLineEdit>
#include <QSettings>
#include <QTcpServer>
#include <QTcpSocket>
#include <QTemporaryDir>
#include <QTest>
#include <QTabWidget>
#include <QPushButton>
#include <QCheckBox>
#include <QTableWidget>
#include <QHeaderView>

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
    const auto* tray = window.findChild<QSystemTrayIcon*>("skewerTray");
    if (!tray || !tray->toolTip().contains("Routing inactive")) return 11;
    auto* close_to_tray = window.findChild<QAction*>("closeToTray");
    if (!close_to_tray || !close_to_tray->isCheckable() || !close_to_tray->isChecked()) return 8;
    close_to_tray->setChecked(false);
    if (QSettings().value("window/closeToTray", true).toBool()) return 9;
    close_to_tray->setChecked(true);
    const auto* current = window.findChild<QCheckBox*>("caOnlyCurrentSnap");
    const auto* applicable = window.findChild<QCheckBox*>("caOnlyApplicable");
    const auto* stores = window.findChild<QTableWidget*>("caStores");
    if (!current || !current->isChecked() || !applicable || applicable->isChecked()
        || !stores || !stores->isSortingEnabled() || stores->columnCount() != 5
        || stores->wordWrap() || stores->iconSize() != QSize(24, 24)) return 7;
    const auto* tabs = window.findChild<QTabWidget*>();
    const auto* install_ca = window.findChild<QPushButton*>("caInstallSelected");
    const auto* remove_all_ca = window.findChild<QPushButton*>("caRemoveAll");
    if (!tabs || tabs->count() != 2 || tabs->tabText(1) != "CA Trust"
        || !install_ca || install_ca->isEnabled() || !remove_all_ca || remove_all_ca->isEnabled()) return 6;
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
    // Without a tray host, closing must not strand an invisible application.
    if (!QSystemTrayIcon::isSystemTrayAvailable()) {
        window.show();
        if (!window.close() || window.isVisible()) return 10;
    }
    return 0;
}
