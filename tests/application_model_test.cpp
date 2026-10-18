#include "application_model.hpp"
#include "desktop_catalog.hpp"
#include "process_scanner.hpp"

#include <QAbstractItemModelTester>
#include <QApplication>

#include <iostream>
#include <unistd.h>

int main(int argc, char** argv)
{
    QApplication application(argc, argv);

    ProcessScanner scanner;
    const QVector<ProcessInfo> processes = scanner.scan(getuid());
    const auto self = std::find_if(processes.begin(), processes.end(), [](const auto& process) {
        return process.pid == getpid();
    });
    if (self == processes.end() || self->cgroup.isEmpty()) {
        std::cerr << "scanner did not discover its own process and cgroup\n";
        return 1;
    }

    DesktopCatalog catalog;
    if (catalog.entries().isEmpty()) {
        std::cerr << "desktop application catalog is empty\n";
        return 2;
    }

    ApplicationModel model;
    QAbstractItemModelTester tester(&model, QAbstractItemModelTester::FailureReportingMode::Fatal);
    if (model.rowCount() == 0 || model.launcherSuggestions().isEmpty()) {
        std::cerr << "application model is empty\n";
        return 3;
    }
    model.refresh();
    return 0;
}
