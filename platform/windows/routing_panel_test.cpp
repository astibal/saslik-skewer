#include "routing_panel.hpp"
#include <QApplication>
#include <QSettings>
#include <QLabel>
#include <QPushButton>
#include <QElapsedTimer>
#include <QThread>
#include <iostream>

int main(int argc, char** argv) {
    QApplication app(argc, argv);
    app.setOrganizationName("SkewerTests");
    app.setApplicationName("RoutingPanel-" + QString::number(GetCurrentProcessId()));
    QSettings settings;
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
            if (!pair->isEnabled() || !start->isEnabled() || stop->isEnabled()) {
                throw std::runtime_error("Incorrect Idle controls");
            }
            pair->click(); wait("Pairing delivered");
            start->click(); wait("Active");
            if (pair->isEnabled() || start->isEnabled() || !stop->isEnabled()) {
                throw std::runtime_error("Incorrect Active controls");
            }
            panel.reset();
            settings.clear(); settings.sync();
            std::cout << "PASS: GUI pairing and Start reached Active; panel closed without Stop\n";
            return 0;
        }
        if (argc != 1) { throw std::invalid_argument("Expected no args or --live SERVICE ENDPOINT"); }
        auto panel = std::make_unique<skewer::windows::RoutingPanel>();
        panel->show();
        const auto start = panel->findChild<QPushButton*>("routingStart");
        const auto stop = panel->findChild<QPushButton*>("routingStop");
        const auto status = panel->findChild<QLabel*>("routingStatus");
        if (!start || !stop || !status || start->isEnabled() || stop->isEnabled()) {
            throw std::runtime_error("Unknown service enabled routing controls");
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
