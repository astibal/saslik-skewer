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
    ProcessInfo first, second, helper, unrelated;
    first.pid = 100; first.name = QStringLiteral("skewer-test-app");
    first.executable = QStringLiteral("/opt/test-one/skewer-test-app");
    first.cgroup = QStringLiteral("/app-first.scope");
    second = first; second.pid = 200;
    second.cgroup = QStringLiteral("/skewer-routed.slice/app-second.scope");
    helper = first; helper.pid = 101; helper.parent_pid = 100;
    unrelated = first; unrelated.pid = 300;
    unrelated.executable = QStringLiteral("/opt/test-two/skewer-test-app");
    unrelated.cgroup = QStringLiteral("/app-third.scope");
    model.setProcesses({first, helper, second, unrelated});
    const auto section = model.index(0, 0);
    if (model.rowCount(section) != 2) return 6;
    QModelIndex group;
    for (int row = 0; row < model.rowCount(section); ++row) {
        const auto candidate = model.index(row, 0, section);
        if (candidate.data(ApplicationModel::ProcessIdsRole).toList().size() == 3)
            group = candidate;
    }
    if (!group.isValid() || model.rowCount(group) != 2
        || !group.data(ApplicationModel::PartiallyRoutedRole).toBool()) return 7;
    const QString stable_id = group.data(ApplicationModel::StableIdRole).toString();
    for (int row = 0; row < model.rowCount(group); ++row) {
        const auto instance = model.index(row, 0, group);
        if (model.parent(instance) != group) return 8;
    }
    first.cgroup = second.cgroup + QStringLiteral("/separate.scope");
    helper.cgroup = first.cgroup;
    model.setProcesses({unrelated, second, first, helper});
    bool found = false;
    for (int row = 0; row < model.rowCount(model.index(0, 0)); ++row) {
        const auto candidate = model.index(row, 0, model.index(0, 0));
        if (candidate.data(ApplicationModel::StableIdRole).toString() != stable_id) continue;
        found = true;
        if (!candidate.data(ApplicationModel::RoutedRole).toBool()
            || candidate.data(ApplicationModel::PartiallyRoutedRole).toBool()) return 9;
    }
    if (!found) return 10;
    return 0;
}
