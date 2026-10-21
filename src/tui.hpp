#pragma once

#include "application_model.hpp"
#include "cgroup_manager.hpp"
#include "routing_controller.hpp"

#include <QPersistentModelIndex>
#include <QSet>

class Tui {
public:
    int run();

private:
    friend class TuiTest;
    struct Row {
        QPersistentModelIndex index;
        int depth{};
        QString stable_id;
    };

    void rebuildRows();
    void draw();
    void moveSelection(int delta);
    void toggleExpanded();
    void changeRouting(bool routed);
    void launch();
    void shell();
    void configureRouting();
    void disableRouting();
    [[nodiscard]] QString prompt(const QString& label);
    [[nodiscard]] QVector<pid_t> selectedPids() const;

    ApplicationModel model_;
    CgroupManager cgroups_;
    RoutingController routing_;
    QVector<Row> rows_;
    QSet<QString> expanded_;
    int selected_{};
    bool routing_active_{};
    QString routing_next_hop_;
    QString status_{QStringLiteral("Ready")};
};
