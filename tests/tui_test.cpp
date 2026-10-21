#include "tui.hpp"
#include <QApplication>

class TuiTest {
public:
    static int run()
    {
        Tui tui;
        ProcessInfo process;
        process.pid = 101;
        process.parent_pid = 1;
        process.name = "skewer-tui-test";
        process.executable = "/opt/skewer-tui-test";
        process.cgroup = "/app-tui-test.scope";
        tui.model_.setProcesses({process});
        tui.expanded_.insert("section:applications");
        tui.expanded_.insert("section:other");
        tui.rebuildRows();
        for (int row = 0; row < tui.rows_.size(); ++row)
            if (tui.rows_[row].index.data(ApplicationModel::NodeTypeRole).toInt()
                == static_cast<int>(ApplicationModel::NodeType::Application)) tui.selected_ = row;
        const QString selected = tui.rows_.at(tui.selected_).stable_id;
        for (int iteration = 0; iteration < 100; ++iteration) {
            process.command_line = QString("test %1").arg(iteration);
            tui.model_.setProcesses({process});
            // Incremental updates preserve the selection's persistent index.
            if (!tui.rows_.at(tui.selected_).index.isValid()
                || tui.rows_.at(tui.selected_).index.data(ApplicationModel::StableIdRole).toString() != selected)
                return 1;
            tui.rebuildRows();
            if (tui.rows_.at(tui.selected_).stable_id != selected) return 2;
        }
        tui.model_.setProcesses({});
        tui.rebuildRows();
        tui.moveSelection(1);
        tui.toggleExpanded();
        return 0;
    }
};

int main(int argc, char** argv)
{
    QApplication app(argc, argv);
    return TuiTest::run();
}
