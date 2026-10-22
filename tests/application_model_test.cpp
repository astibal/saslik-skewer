#include "application_model.hpp"
#include "desktop_catalog.hpp"
#include "process_scanner.hpp"

#include <QAbstractItemModelTester>
#include <QApplication>
#include <QPersistentModelIndex>
#include <QSignalSpy>
#include <QTemporaryDir>
#include <QDir>
#include <QFile>
#include <QBrush>

#include <iostream>
#include <unistd.h>

int main(int argc, char** argv)
{
    QTemporaryDir desktop_root;
    qputenv("XDG_DATA_HOME", desktop_root.path().toUtf8());
    QDir().mkpath(desktop_root.path() + "/applications");
    QFile desktop(desktop_root.path() + "/applications/skewer-fixture.desktop");
    if (!desktop.open(QIODevice::WriteOnly)) return 25;
    desktop.write("[Desktop Entry]\nType=Application\nName=Fixture Browser\nExec=/opt/fixture-browser\n");
    desktop.close();
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
    const auto section_index = model.index(0,0);
    const auto badge = model.index(0, ApplicationModel::ConnectionsColumn, section_index);
    const auto pids = badge.data(ApplicationModel::ProcessIdsRole).toList();
    if (pids.isEmpty()) return 11;
    ConnectionSnapshot sockets;
    sockets.complete = true;
    sockets.rows.push_back({"tcp", "ESTAB", "127.0.0.1:1", "127.0.0.1:2", "/other.scope", "123", {pids.first().toInt()}});
    model.setConnections(sockets);
    if (!badge.data().toString().contains("1 out")) return 12;
    // Repeated paints must reuse the same snapshot; an unchanged poll must not
    // invalidate the view. A changed socket group below must invalidate it.
    int updates = 0;
    QObject::connect(&model, &QAbstractItemModel::dataChanged, [&updates] { ++updates; });
    model.setConnections(sockets);
    if (updates != 0 || !badge.data().toString().contains("1 out")) return 15;
    sockets.rows[0].group = "/skewer-routed.slice/test.scope";
    model.setConnections(sockets);
    if (!badge.data().toString().contains("All")) return 13;
    sockets.unreadable_pids.insert(99999999);
    model.setConnections(sockets);
    if (!badge.data().toString().contains("All")) return 16;
    sockets.unreadable_pids.insert(pids.first().toInt());
    model.setConnections(sockets);
    if (!badge.data().toString().contains("Unknown")) return 17;
    sockets.unreadable_pids.clear();
    sockets.complete = false;
    model.setConnections(sockets);
    if (!badge.data().toString().contains("Unknown")) return 14;
    QSignalSpy resets(&model, &QAbstractItemModel::modelReset);
    const auto findPid = [&](const auto& self, int pid, const QModelIndex& parent) -> QModelIndex {
        for (int row = 0; row < model.rowCount(parent); ++row) {
            auto current = model.index(row, 0, parent);
            if (current.data(ApplicationModel::StableIdRole).toString() == QString("pid:%1").arg(pid))
                return current;
            auto child = self(self, pid, current);
            if (child.isValid()) return child;
        }
        return {};
    };
    model.setProcesses({first, helper});
    QPersistentModelIndex kept(findPid(findPid, first.pid, {}));
    QPersistentModelIndex keptChild(findPid(findPid, helper.pid, {}));
    model.setProcesses({first, helper, second, unrelated});
    if (!kept.isValid() || !keptChild.isValid()) return 18;
    // Moving to a different scope changes application grouping, not PID identity.
    first.cgroup = "/skewer-routed.slice/moved.scope";
    helper.cgroup = first.cgroup;
    first.name = "renamed-app";
    model.setProcesses({first, helper, unrelated});
    if (!kept.isValid() || !keptChild.isValid() || kept.data().toString() != first.name) return 19;
    model.setProcesses({first, unrelated});
    if (!kept.isValid() || keptChild.isValid() || resets.count()) return 20;
    model.setProcesses({});
    if (kept.isValid() || model.rowCount() || resets.count()) return 21;
    ProcessInfo shell = first;
    shell.pid = 501; shell.name = "bash"; shell.executable = "/bin/bash";
    shell.cgroup = "/app-shell.scope"; shell.arguments = {"bash"};
    auto other_shell = shell;
    other_shell.pid = 502; other_shell.cgroup = "/app-shell-two.scope";
    auto script = shell;
    script.pid = 503; script.cgroup = "/app-script.scope";
    script.arguments = {"/bin/bash", "/opt/test scripts/skewer-browser"};
    script.command_line = script.arguments.join(' ');
    model.setProcesses({shell, other_shell, script});
    if (model.rowCount(model.index(0, 0)) != 2) return 22;
    const auto script_app = findPid(findPid, script.pid, {}).parent();
    if (script_app.data().toString() != "skewer-browser"
        || script_app.parent().data(ApplicationModel::NodeTypeRole).toInt()
            != int(ApplicationModel::NodeType::Section)) return 23;
    if (findPid(findPid, shell.pid, {}).parent().parent()
        != findPid(findPid, other_shell.pid, {}).parent().parent()) return 24;
    auto gui = shell;
    gui.pid = 504; gui.parent_pid = shell.pid;
    gui.name = "fixture-browser"; gui.executable = "/opt/fixture-browser";
    gui.arguments = {gui.executable};
    model.setProcesses({shell, gui});
    const auto physical = findPid(findPid, gui.pid, {});
    if (physical.parent().data(ApplicationModel::StableIdRole) != "pid:501"
        || !physical.data(Qt::ToolTipRole).toString().contains("Also shown in Applications")) return 26;
    if (physical.data(Qt::ForegroundRole).value<QBrush>().color()
        != QApplication::palette().color(QPalette::Disabled, QPalette::Text)) return 27;
    const auto apps = model.index(0, 0);
    if (model.rowCount(apps) != 2 || apps.data(ApplicationModel::ProcessIdsRole).toList().size() != 2) return 28;
    bool promoted = false;
    for (int row = 0; row < model.rowCount(apps); ++row) {
        const auto item = model.index(row, 0, apps);
        if (item.data().toString() == "Fixture Browser") {
            promoted = item.data(ApplicationModel::ProcessIdsRole).toList() == QVariantList{gui.pid};
        }
    }
    if (!promoted) return 29;
    // A separate scope must keep the real parent edge too.
    gui.cgroup = "/app-browser.scope";
    model.setProcesses({shell, gui});
    const auto shell_node = findPid(findPid, shell.pid, {});
    if (model.rowCount(shell_node) != 1
        || !model.index(0, 0, shell_node).data(Qt::ToolTipRole).toString().contains("PPID 501")) return 30;
    return 0;
}
