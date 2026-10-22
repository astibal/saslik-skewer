#include "main_window.hpp"
#include "interface_routing.hpp"
#include "application_model.hpp"
#include "routing_guard.hpp"

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
#include <QTreeView>
#include <QTreeWidget>
#include <QScrollArea>

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
            correct_path |= socket->readAll().startsWith("GET /api/status ");
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
    auto* connections = window.findChild<QTableWidget*>("connectionsTable");
    auto* show_cgroup = window.findChild<QCheckBox*>("connectionsShowCgroup");
    if (!connections || !show_cgroup || !connections->isColumnHidden(6)
        || connections->horizontalHeader()->visualIndex(7) != 0
        || connections->horizontalHeaderItem(7)->text() != "Application") return 31;
    show_cgroup->setChecked(true);
    if (connections->isColumnHidden(6) || !QSettings().value("connections/showCgroup").toBool()) return 32;
    show_cgroup->setChecked(false);
    const auto* tree = window.findChild<QTreeView*>();
    if (!tree) return 20;
    for (int col = 0; col < tree->model()->columnCount(); ++col)
        if (tree->header()->sectionResizeMode(col) != QHeaderView::Interactive) return 21;
    const auto* tray = window.findChild<QSystemTrayIcon*>("skewerTray");
    // QSettings is isolated, but root-owned interface selections survive GUI
    // restarts. Never clear the user's live routing merely to run a UI test.
    const auto live_interfaces = InterfaceRouting::state(getuid());
    auto* application_model = window.findChild<ApplicationModel*>();
    const QString expected_routing = application_model && application_model->hasAttachedProcesses()
        ? (RoutingGuard::installed(getuid()) ? "Dropped" : "Unprotected")
        : live_interfaces["selections"].toObject().isEmpty()
        ? "Routing inactive" : "Interface ingress configured via " + live_interfaces["gateway"].toString();
    for (int attempt = 0; tray && attempt < 50 && !tray->toolTip().contains(expected_routing); ++attempt)
        QTest::qWait(20);
    if (!tray || !tray->toolTip().contains(expected_routing)) return 11;
    auto* close_to_tray = window.findChild<QAction*>("closeToTray");
    if (!close_to_tray || !close_to_tray->isCheckable() || !close_to_tray->isChecked()) return 8;
    close_to_tray->setChecked(false);
    if (QSettings().value("window/closeToTray", true).toBool()) return 9;
    close_to_tray->setChecked(true);
    const auto* current = window.findChild<QCheckBox*>("caOnlyCurrentSnap");
    const auto* applicable = window.findChild<QCheckBox*>("caOnlyApplicable");
    const auto* stores = window.findChild<QTreeWidget*>("caStores");
    const auto* runtime_stores = window.findChild<QTableWidget*>("runtimeTrustTable");
    const auto* runtime_prepare = window.findChild<QPushButton*>("runtimeTrustPrepare");
    const auto* runtime_copy = window.findChild<QPushButton*>("runtimeTrustCopyEnvironment");
    if (!current || !current->isChecked() || !applicable || applicable->isChecked()
        || !stores || !stores->isSortingEnabled() || stores->columnCount() != 5
        || stores->wordWrap() || stores->iconSize() != QSize(24, 24)
        || !runtime_stores || runtime_stores->columnCount() != 6
        || !runtime_prepare || runtime_prepare->isEnabled()
        || !runtime_copy || runtime_copy->isEnabled()) return 7;
    const auto* tabs = window.findChild<QTabWidget*>();
    const auto* install_ca = window.findChild<QPushButton*>("caInstallSelected");
    const auto* remove_all_ca = window.findChild<QPushButton*>("caRemoveAll");
    if (!tabs || tabs->count() != 4 || tabs->tabText(3) != "Connections" || tabs->tabText(1) != "CA Trust"
        || tabs->tabText(2) != "Runtime Trust"
        || !install_ca || install_ca->isEnabled() || !remove_all_ca || remove_all_ca->isEnabled()) return 6;
    auto* input = window.findChild<QLineEdit*>("saslikInfoUrl");
    auto* text = window.findChild<QLabel*>("saslikInfoText");
    if (!input || !text) return 2;
    auto* status_box = window.findChild<QScrollArea*>("saslikStatusBox");
    if (!status_box || status_box->minimumHeight() != status_box->maximumHeight()
        || status_box->widget() != text) return 28;
    const int status_height = status_box->height();
    text->setText(QString(40, '\n') + QString(1000, 'x'));
    QApplication::processEvents();
    if (status_box->height() != status_height) return 29;
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
    // Our own URI scheme must use pairing, not HTTP validation or fallback.
    input->setText("skewer://unpaired-skewer-test.invalid:8766/pair");
    QMetaObject::invokeMethod(input, "editingFinished");
    if (!wait_for("No pairing for this endpoint")
        || text->text().contains("Enter a valid HTTP")) return 22;
    auto* connection = window.findChild<QPushButton*>("saslikConnection");
    if (!connection) return 23;
    connection->click();
    if (connection->text() != "Reconnect" || !QSettings().value("saslik/disconnected").toBool()
        || !text->text().contains("Disconnected")) return 24;
    if (!server.listen(QHostAddress::LocalHost)) return 27;
    input->setText(QString("http://127.0.0.1:%1/").arg(server.serverPort()));
    correct_path = false;
    malformed = false;
    QMetaObject::invokeMethod(input, "editingFinished");
    QTest::qWait(200);
    if (correct_path || !text->text().contains("Disconnected")) return 25;
    connection->click();
    if (!wait_for("Updated:") || !correct_path
        || QSettings().value("saslik/disconnected").toBool()) {
        qWarning() << "Reconnect failed:" << text->text() << correct_path
                   << QSettings().value("saslik/disconnected") << connection->text();
        return 26;
    }
    // Missing process routing must take priority over configured interface ingress.
    ProcessInfo attached;
    attached.pid = 98765432;
    attached.name = "guard-test";
    attached.cgroup = "/skewer-routed.slice/test.scope";
    application_model->setProcesses({attached});
    QMetaObject::invokeMethod(&window, "updateRoutingStatus");
    auto* alarm = window.findChild<QTimer*>("routingAlarm");
    for (int i = 0; i < 40 && (!alarm || !alarm->isActive()); ++i) {
        QTest::qWait(20);
        alarm = window.findChild<QTimer*>("routingAlarm");
    }
    if (!alarm || !alarm->isActive()) return 40;
    auto* routing_label = window.findChild<QLabel*>("routingStatus");
    if (!routing_label || !(routing_label->text().contains("Dropped")
        || routing_label->text().contains("Unprotected"))) return 41;
    const QString previous_color = routing_label->styleSheet();
    QMetaObject::invokeMethod(alarm, "timeout");
    const QString first_color = routing_label->styleSheet();
    QMetaObject::invokeMethod(alarm, "timeout");
    if (first_color == previous_color && routing_label->styleSheet() == previous_color) return 42;
    // Without a tray host, closing must not strand an invisible application.
    if (!QSystemTrayIcon::isSystemTrayAvailable()) {
        window.show();
        if (!window.close() || window.isVisible()) return 10;
    }
    return 0;
}
