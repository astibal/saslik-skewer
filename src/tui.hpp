#pragma once

#include "application_model.hpp"
#include "cgroup_manager.hpp"
#include "routing_controller.hpp"

#include <QModelIndex>
#include <QSet>

class Tui {
public:
    int run();

private:
    struct Row {
        QModelIndex index;
        int depth{};
    };

    void rebuildRows();
    void draw();
    void moveSelection(int delta);
    void toggleExpanded();
    void changeRouting(bool routed);
    void launch();
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
    QString status_{QStringLiteral("Ready")};
};
