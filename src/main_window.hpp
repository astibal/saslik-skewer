#pragma once

#include "cgroup_manager.hpp"
#include "routing_controller.hpp"

#include <QMainWindow>
#include <QSet>

class ApplicationModel;
class QLineEdit;
class QLabel;
class QPushButton;
class QSortFilterProxyModel;
class QStringListModel;
class QTreeView;
class QCloseEvent;

class MainWindow final : public QMainWindow {
    Q_OBJECT

public:
    explicit MainWindow(QWidget* parent = nullptr);

protected:
    void closeEvent(QCloseEvent* event) override;

private slots:
    void launchCommand();
    void rememberExpandedItems();
    void restoreExpandedItems();
    void updateLauncherSuggestions(const QStringList& suggestions);
    void updateSelection();
    void routeSelection();
    void releaseSelection();
    void browseExecutable();
    void activateRouting();
    void deactivateRouting();
    void updateRoutingStatus();

private:
    ApplicationModel* model_{};
    QSortFilterProxyModel* filtered_model_{};
    QTreeView* tree_{};
    QLineEdit* search_{};
    QLineEdit* command_{};
    QStringListModel* launcher_model_{};
    QPushButton* route_button_{};
    QPushButton* release_button_{};
    QLabel* action_status_{};
    QLineEdit* next_hop_{};
    QPushButton* routing_up_{};
    QPushButton* routing_down_{};
    QLabel* routing_status_{};
    QSet<QString> expanded_items_;
    QString selected_item_;
    bool restored_once_{};
    CgroupManager cgroups_;
    RoutingController routing_;
};
