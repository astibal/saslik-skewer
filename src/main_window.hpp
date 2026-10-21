#pragma once

#include "cgroup_manager.hpp"
#include "routing_controller.hpp"

#include <QMainWindow>
#include <QJsonObject>
#include <QSet>

class ApplicationModel;
class CaTrustPanel;
class QLineEdit;
class QLabel;
class QPushButton;
class QComboBox;
class QNetworkAccessManager;
class QNetworkReply;
class QSortFilterProxyModel;
class QStringListModel;
class QTreeView;
class QCloseEvent;
class QTimer;
class QSystemTrayIcon;
class QAction;

class MainWindow final : public QMainWindow {
    Q_OBJECT

public:
    explicit MainWindow(const QString& connect_url = {}, QWidget* parent = nullptr);

protected:
    void closeEvent(QCloseEvent* event) override;
    void changeEvent(QEvent* event) override;

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
    void updateRoutingSource();
    void pollSaslik();
    void receiveSaslik(QNetworkReply* reply);
    void applyDiscovery(const QByteArray& payload, bool request_ok);

private:
    void renderRoutingStatus(bool active, bool reachable);
    [[nodiscard]] QString currentNextHop() const;
    [[nodiscard]] bool usesSaslikUrl() const;
    void sendTrustReport();
    void updateTrayIcon();
    QSystemTrayIcon* tray_{};
    QAction* close_to_tray_{};
    bool quitting_{};
    ApplicationModel* model_{};
    CaTrustPanel* ca_panel_{};
    QSortFilterProxyModel* filtered_model_{};
    QTreeView* tree_{};
    QLineEdit* search_{};
    QLineEdit* command_{};
    QStringListModel* launcher_model_{};
    QPushButton* route_button_{};
    QPushButton* release_button_{};
    QLabel* action_status_{};
    QLineEdit* next_hop_{};
    QLineEdit* saslik_url_{};
    QComboBox* routing_source_{};
    QPushButton* routing_up_{};
    QPushButton* routing_down_{};
    QLabel* routing_status_{};
    QLabel* routing_status_bar_{};
    QTimer* routing_watchdog_{};
    QNetworkAccessManager* network_{};
    QNetworkAccessManager* report_network_{};
    QJsonObject trust_report_;
    qint64 last_trust_report_ms_{};
    QSet<QString> expanded_items_;
    QString selected_item_;
    bool restored_once_{};
    int saved_tree_scroll_{};
    int saved_tree_horizontal_scroll_{};
    bool routing_requested_{};
    bool routing_check_pending_{};
    bool trust_report_pending_{};
    bool discovery_request_pending_{};
    bool saslik_reachable_{};
    bool saslik_disconnected_{};
    quint64 saslik_epoch_{};
    bool discovery_online_{};
    QString discovery_gateway_;
    QString discovery_interface_;
    QString discovery_generation_;
    QString discovery_warning_;
    CgroupManager cgroups_;
    RoutingController routing_;
};
