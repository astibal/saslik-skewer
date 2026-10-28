#include "routing_panel.hpp"
#include <QApplication>
#include <QSettings>
#include <QLabel>
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
            auto panel = std::make_unique<skewer::windows::RoutingPanel>();
            panel->show();
            auto* status = panel->findChild<QLabel*>("routingStatus");
            auto* pair = panel->findChild<QPushButton*>("routingPair");
            auto* start = panel->findChild<QPushButton*>("routingStart");
            auto* stop = panel->findChild<QPushButton*>("routingStop");
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
            if (!pair->isEnabled() || start->isEnabled() || stop->isEnabled()) {
                throw std::runtime_error("Unpaired Idle enabled routing");
            }
            pair->click(); wait("Pairing delivered");
            if (!start->isEnabled()) {
                throw std::runtime_error("Paired Idle did not enable routing");
            }
            start->click(); wait("Active");
            if (pair->isEnabled() || start->isEnabled() || !stop->isEnabled()) {
                throw std::runtime_error("Incorrect Active controls");
            }
            panel.reset();
            settings.clear(); settings.sync();
            std::cout << "PASS: GUI pairing and Start reached Active; panel closed without Stop\n";
            return 0;
        }
        if (argc == 4 && std::string(argv[1]) == "--live-direct") {
            settings.setValue("windows/routingService", QString::fromLocal8Bit(argv[2]));
            settings.setValue("windows/routingTransport", 2);
            settings.setValue("windows/directGateway", QString::fromLocal8Bit(argv[3]));
            // A stale tunnel endpoint must not interfere with a Direct
            // activation, which intentionally needs no pairing.
            settings.setValue("windows/routingEndpoint", "skewer://192.0.2.1:8766/pair");
            auto panel = std::make_unique<skewer::windows::RoutingPanel>();
            panel->show();
            auto* status = panel->findChild<QLabel*>("routingStatus");
            auto* transport = panel->findChild<QComboBox*>("routingTransport");
            auto* gateway = panel->findChild<QLineEdit*>("routingGateway");
            auto* pair = panel->findChild<QPushButton*>("routingPair");
            auto* start = panel->findChild<QPushButton*>("routingStart");
            auto* stop = panel->findChild<QPushButton*>("routingStop");
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
            if (transport->currentIndex() != 2 || gateway->text() != QString::fromLocal8Bit(argv[3]) ||
                !status->text().contains("Direct-only") || pair->isEnabled() ||
                !start->isEnabled() || stop->isEnabled()) {
                throw std::runtime_error("Auto did not admit the valid unpaired direct gateway");
            }
            start->click();
            wait("Active");
            if (!status->text().contains("direct gateway") || start->isEnabled() || !stop->isEnabled()) {
                throw std::runtime_error("Auto did not publish authoritative Direct state");
            }
            panel.reset();
            settings.clear(); settings.sync();
            std::cout << "PASS: GUI Auto selected Direct; panel closed without Stop\n";
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
        if (!endpoint || !gateway || !transport || !start || !stop || !status ||
            start->isEnabled() || stop->isEnabled()) {
            throw std::runtime_error("Unknown service enabled routing controls");
        }
        if (transport->count() != 3 || transport->itemData(2).toInt() != -1 ||
            !transport->itemText(2).startsWith("Auto")) {
            throw std::runtime_error("Windows routing does not expose explicit Auto transport");
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
        panel = std::make_unique<skewer::windows::RoutingPanel>();
        time.restart();
        panel.reset();
        if (time.elapsed() > 1000) {
            throw std::runtime_error("Closing panel did not cancel local IPC promptly");
        }
        std::cout
            << "PASS: asynchronous unavailable status, disabled unknown-state actions, bounded local close\n";
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        result = 1;
    }
    settings.clear();
    settings.sync();
    return result;
}
