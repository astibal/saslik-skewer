#include "process_browser.hpp"
#include <QAbstractItemModelTester>
#include <QApplication>
#include <QPersistentModelIndex>
#include <QSignalSpy>
#include <stdexcept>
#include <iostream>

using namespace skewer::ui;
void require(bool value, const char* message) {
    if (!value) {
        throw std::runtime_error(message);
    }
}
int main(int argc, char** argv) {
    QApplication application(argc, argv);
    try {
        ProcessBrowser browser;
        QAbstractItemModelTester tester(browser.model(),
                                        QAbstractItemModelTester::FailureReportingMode::Fatal);
        QVector<ProcessRecord> records{
            {1, 10, 0, "shell", "shell.exe", {}},
            {2, 20, 1, "Browser", "browser.exe", {"First window"}},
            {3, 30, 2, "renderer", "browser.exe", {}},
            {4, 40, 2, "Browser", "browser.exe", {"Second window"}},
            {5, 50, 99, "orphan", "orphan.exe", {}},
        };
        browser.setProcesses(records);
        auto* apps = browser.model()->item(0);
        require(apps->rowCount() == 2, "Separate window-bearing instances were merged");
        require(apps->child(0)->rowCount() == 1, "Renderer missing from application tree");
        require(browser.model()->item(1)->rowCount() == 2, "Background roots missing");
        require(browser.launchSuggestions().count("browser.exe") == 1, "Duplicate launch suggestions");
        browser.setFilterText("renderer");
        require(!browser.tree()->isRowHidden(0, apps->index()), "Filter hid matching descendant's parent");
        require(browser.tree()->isRowHidden(1, apps->index()), "Filter retained nonmatching instance");
        browser.setFilterText({});
        require(!browser.tree()->isRowHidden(1, apps->index()), "Clearing filter did not restore instance");
        auto index = apps->child(0)->index();
        browser.tree()->expand(index);
        browser.tree()->setCurrentIndex(index);
        QPersistentModelIndex stable(index);
        QSignalSpy removed(browser.model(), &QAbstractItemModel::rowsRemoved);
        browser.setProcesses(records);
        require(stable.isValid() && removed.isEmpty(), "Unchanged poll rebuilt the tree");
        records[0].name = "updated shell";
        browser.setProcesses(records);
        index = browser.model()->item(0)->child(0)->index();
        require(browser.tree()->isExpanded(index), "Refresh lost expansion");
        require(browser.tree()->currentIndex() == index, "Refresh lost selection");
        records[1].created = 25;
        browser.setProcesses(records);
        require(!browser.tree()->currentIndex().isValid(), "Reused PID inherited old selection");
        browser.setProcesses({{10, 10, 11, "cycle-a", "a", {}},
                              {11, 10, 10, "cycle-b", "b", {}},
                              {12, 5, 10, "old-child", "c", {}},
                              {0, 0, 0, "invalid", {}, {}}});
        require(browser.model()->item(1)->rowCount() == 2, "Cycle/reused-parent handling failed");

        // Bad snapshot entries must not duplicate rows or create a PID-zero root.
        const ProcessRecord duplicate{20, 20, 0, "duplicate", "duplicate.exe", {}};
        browser.setProcesses({duplicate, duplicate, {0, 0, 0, "invalid", {}, {}}});
        require(browser.model()->item(1)->rowCount() == 1, "Duplicate PID created multiple rows");
        browser.setFilterText("missing");
        browser.setProcesses({{21, 21, 0, "different", "different.exe", {}}});
        require(browser.tree()->isRowHidden(0, browser.model()->item(1)->index()),
                "Snapshot refresh discarded the active filter");
        browser.setFilterText({});
        browser.setProcesses({});
        require(browser.model()->item(0)->rowCount() == 0 && browser.model()->item(1)->rowCount() == 0,
                "Empty snapshot retained stale processes");
        std::cout << "PASS: Qt model contract, application boundaries, ancestry, refresh, PID reuse, cycles, "
                     "launcher paths\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
