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

    ProcessInfo manager, browser, child, terminal;
    manager.pid = 10; manager.name = QStringLiteral("systemd");
    manager.cgroup = QStringLiteral("/user.slice/user-1000.slice/user@1000.service");
    browser.pid = 20; browser.parent_pid = 10; browser.cgroup = manager.cgroup;
    child.pid = 21; child.parent_pid = 20; child.cgroup = manager.cgroup;
    terminal.pid = 30; terminal.parent_pid = 10; terminal.cgroup = manager.cgroup;
    QHash<pid_t, const ProcessInfo*> tree{{10, &manager}, {20, &browser},
                                         {21, &child}, {30, &terminal}};
    if (ApplicationModel::applicationKey(browser, tree) != QStringLiteral("tree:20")
        || ApplicationModel::applicationKey(child, tree) != QStringLiteral("tree:20")
        || ApplicationModel::applicationKey(terminal, tree) != QStringLiteral("tree:30")) return 4;
    browser.cgroup += QStringLiteral("/snap.firefox.scope/subgroup");
    if (!ApplicationModel::applicationKey(browser, tree).endsWith(QStringLiteral("/snap.firefox.scope"))) return 5;

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
