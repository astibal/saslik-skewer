#include "routing_panel.hpp"
#include <QApplication>
#include <QSettings>
#include <QLabel>
#include <QGroupBox>
#include <QLineEdit>
#include <QComboBox>
#include <QPushButton>
#include <QElapsedTimer>
#include <QThread>
#include <iostream>

int main(int argc, char** argv) {
    QApplication app(argc, argv);
    app.setOrganizationName("SkewerTests");
    app.setApplicationName("RoutingPanel-" + QString::number(GetCurrentProcessId()));
    QSettings settings;
    settings.clear();
    settings.sync();
    settings.setValue("windows/routingService", "SkewerMissing-" + QString::number(GetCurrentProcessId()));
    int result = 0;
    try {
        if (argc == 4 && std::string(argv[1]) == "--live") {
            settings.setValue("windows/routingService", QString::fromLocal8Bit(argv[2]));
            settings.setValue("windows/saslikEndpoint", QString::fromLocal8Bit(argv[3]));
            // Model an upgrade from the former Auto policy: a saved gateway
            // must not make Windows silently choose Direct.
            settings.setValue("windows/routingTransport", 2);
            settings.setValue("windows/directGateway", "198.51.100.1");
            auto panel = std::make_unique<skewer::windows::RoutingPanel>();
            panel->show();
            auto* status = panel->findChild<QLabel*>("routingStatus");
            auto* service = panel->findChild<QLineEdit*>("routingService");
            auto* endpoint = panel->findChild<QLineEdit*>("routingEndpoint");
            auto* transport = panel->findChild<QComboBox*>("routingTransport");
            auto* gateway = panel->findChild<QLineEdit*>("routingGateway");
            auto* pair = panel->findChild<QPushButton*>("routingPair");
            auto* start = panel->findChild<QPushButton*>("routingStart");
            auto* stop = panel->findChild<QPushButton*>("routingStop");
            auto* install = panel->findChild<QPushButton*>("routingInstall");
            auto wait = [&](const QString& text) {
                QElapsedTimer timer; timer.start();
                while (!status->text().startsWith(text) && timer.elapsed() < 30000) {
                    app.processEvents(); QThread::msleep(10);
                }
                if (!status->text().startsWith(text)) {
                    throw std::runtime_error(("Unexpected panel state: " + status->text()).toStdString());
                }
            };
            wait("Idle");
            if (!transport || transport->currentIndex() != 2 || !gateway || gateway->isEnabled() ||
                !pair->isEnabled() || start->isEnabled() || stop->isEnabled() ||
                !service->isEnabled() || !endpoint->isEnabled()) {
                throw std::runtime_error("Legacy Auto did not require paired Tuntom");
            }
            pair->click(); wait("Pairing delivered");
            if (!start->isEnabled()) {
                throw std::runtime_error("Paired Idle did not enable routing");
            }
            start->click(); wait("Active");
            if (!status->text().contains("encrypted tunnel")) {
                throw std::runtime_error("Windows Auto did not activate Tuntom");
            }
            if (stop->text() != "Release host" || !stop->toolTip().contains("not a protected pause")) {
                throw std::runtime_error("Whole-host release is mislabeled as protected pause");
            }
            if (pair->isEnabled() || start->isEnabled() || !stop->isEnabled() ||
                service->isEnabled() || endpoint->isEnabled() || install->isEnabled()) {
                throw std::runtime_error("Incorrect Active controls");
            }
            panel.reset();
            settings.clear(); settings.sync();
            std::cout << "PASS: saved-gateway Auto chose Tuntom; GUI closed without Stop\n";
            return 0;
        }
        if (argc == 4 && std::string(argv[1]) == "--live-direct") {
            settings.setValue("windows/routingService", QString::fromLocal8Bit(argv[2]));
            settings.setValue("windows/routingTransport", 1);
            settings.setValue("windows/directGateway", QString::fromLocal8Bit(argv[3]));
            // A stale tunnel endpoint must not interfere with a Direct
            // activation, which intentionally needs no pairing.
            settings.setValue("windows/routingEndpoint", "skewer://192.0.2.1:8766/pair");
            auto panel = std::make_unique<skewer::windows::RoutingPanel>();
            panel->show();
            auto* status = panel->findChild<QLabel*>("routingStatus");
            auto* service = panel->findChild<QLineEdit*>("routingService");
            auto* endpoint = panel->findChild<QLineEdit*>("routingEndpoint");
            auto* transport = panel->findChild<QComboBox*>("routingTransport");
            auto* gateway = panel->findChild<QLineEdit*>("routingGateway");
            auto* pair = panel->findChild<QPushButton*>("routingPair");
            auto* start = panel->findChild<QPushButton*>("routingStart");
            auto* stop = panel->findChild<QPushButton*>("routingStop");
            auto* install = panel->findChild<QPushButton*>("routingInstall");
            auto wait = [&](const QString& text) {
                QElapsedTimer timer; timer.start();
                while (!status->text().startsWith(text) && timer.elapsed() < 30000) {
                    app.processEvents(); QThread::msleep(10);
                }
                if (!status->text().startsWith(text)) {
                    throw std::runtime_error(("Unexpected direct panel state: " + status->text()).toStdString());
                }
            };
            wait("Idle");
            if (transport->currentIndex() != 1 || gateway->text() != QString::fromLocal8Bit(argv[3]) ||
                !status->text().contains("Direct-only") || pair->isEnabled() ||
                !start->isEnabled() || stop->isEnabled() || !service->isEnabled() ||
                !endpoint->isEnabled()) {
                throw std::runtime_error("Explicit Direct did not admit the valid unpaired gateway");
            }
            start->click();
            wait("Active");
            if (!status->text().contains("direct gateway") || start->isEnabled() || !stop->isEnabled() ||
                service->isEnabled() || endpoint->isEnabled() || install->isEnabled()) {
                throw std::runtime_error("Explicit Direct did not publish authoritative state");
            }
            const auto active_endpoint = endpoint->text();
            const QString replacement = "skewer://198.51.100.10:8766/pair";
            panel->setPairedEndpoint(replacement);
            if (endpoint->text() != active_endpoint) {
                throw std::runtime_error("Active generation adopted a different paired endpoint");
            }
            stop->click();
            wait("Idle");
            if (endpoint->text() != replacement || !endpoint->isEnabled()) {
                throw std::runtime_error("Idle panel did not adopt the deferred paired endpoint");
            }
            start->click();
            wait("Active");
            panel.reset();
            settings.clear(); settings.sync();
            std::cout << "PASS: explicit GUI Direct remained available and panel closed without Stop\n";
            return 0;
        }
        if (argc != 1) {
            throw std::invalid_argument("Expected no args, --live SERVICE ENDPOINT, or "
                                        "--live-direct SERVICE GATEWAY");
        }
        auto panel = std::make_unique<skewer::windows::RoutingPanel>();
        panel->show();
        const auto endpoint = panel->findChild<QLineEdit*>("routingEndpoint");
        const auto gateway = panel->findChild<QLineEdit*>("routingGateway");
        const auto transport = panel->findChild<QComboBox*>("routingTransport");
        const auto start = panel->findChild<QPushButton*>("routingStart");
        const auto stop = panel->findChild<QPushButton*>("routingStop");
        const auto status = panel->findChild<QLabel*>("routingStatus");
        const auto policy = panel->findChild<QGroupBox*>("routingPolicy");
        const auto details = panel->findChild<QLabel*>("routingPolicyDetails");
        if (!policy || !details || policy->isChecked() || !details->isHidden()) {
            throw std::runtime_error("Routing policy must start collapsed");
        }
        policy->setChecked(true);
        if (details->isHidden() || !details->text().contains("More-specific") ||
            !details->text().contains("DHCPv4") || !details->text().contains("service crash")) {
            throw std::runtime_error("Routing exceptions and limitations are not visible");
        }
        policy->setChecked(false);
        if (!details->isHidden()) throw std::runtime_error("Routing policy did not collapse");
        if (!endpoint || !gateway || !transport || !start || !stop || !status ||
            start->isEnabled() || stop->isEnabled()) {
            throw std::runtime_error("Unknown service enabled routing controls");
        }
        if (!stop->toolTip().contains("not a protected pause")) {
            throw std::runtime_error("Release control omits its routing consequence");
        }
        if (transport->count() != 3 || transport->itemData(2).toInt() != -1 ||
            !transport->itemText(2).startsWith("Auto") || transport->currentIndex() != 0 ||
            !transport->itemText(0).contains("recommended") || gateway->isEnabled()) {
            throw std::runtime_error("Windows routing does not default to recommended Tuntom");
        }
        transport->setCurrentIndex(1);
        gateway->setText("not-an-address");
        if (start->isEnabled()) {
            throw std::runtime_error("Invalid direct gateway enabled routing");
        }
        panel->setPairedEndpoint("  skewer://192.0.2.10:8766/pair  ");
        if (endpoint->text() != "skewer://192.0.2.10:8766/pair") {
            throw std::runtime_error("Paired endpoint did not propagate into routing controls");
        }
        QElapsedTimer time;
        time.start();
        unsigned ticks{};
        while (!status->text().startsWith("Service unavailable") && time.elapsed() < 5000) {
            app.processEvents();
            QThread::msleep(10);
            ++ticks;
        }
        if (ticks < 5 || time.elapsed() >= 5000 || start->isEnabled() || stop->isEnabled()) {
            throw std::runtime_error("Unavailable service blocked UI or enabled controls");
        }
        panel.reset();
        const auto saved_service = settings.value("windows/routingService").toString();
        panel = std::make_unique<skewer::windows::RoutingPanel>(
            nullptr, QStringLiteral("SkewerRouting-Test-0123456789abcdef0123456789abcdef"));
        const auto override_service = panel->findChild<QLineEdit*>("routingService");
        if (!override_service || override_service->text() !=
                                     QStringLiteral("SkewerRouting-Test-0123456789abcdef0123456789abcdef") ||
            override_service->isEnabled()) {
            throw std::runtime_error("Process-local routing service override is not isolated");
        }
        panel.reset();
        if (settings.value("windows/routingService").toString() != saved_service) {
            throw std::runtime_error("Process-local service override changed user preferences");
        }
        panel = std::make_unique<skewer::windows::RoutingPanel>();
        time.restart();
        panel.reset();
        if (time.elapsed() > 1000) {
            throw std::runtime_error("Closing panel did not cancel local IPC promptly");
        }
        std::cout
            << "PASS: asynchronous unavailable status, isolated service override and bounded local close\n";
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        result = 1;
    }
    settings.clear();
    settings.sync();
    return result;
}
