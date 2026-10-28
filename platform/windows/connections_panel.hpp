#pragma once
#include "routing_control.hpp"
#include "tcp_owners.hpp"
#include <QFutureWatcher>
#include <QTimer>
#include <QWidget>

class QLabel;
class QLineEdit;
class QTableWidget;

namespace skewer::ui { class ProcessBrowser; }

namespace skewer::windows {
class ConnectionsPanel final : public QWidget {
public:
    explicit ConnectionsPanel(skewer::ui::ProcessBrowser* processes, QWidget* parent = nullptr);
    ~ConnectionsPanel() override;
    void setRoutingState(bool known, const RoutingReply& state);

private:
    void refresh();
    void render(const traffic::TcpOwnerSnapshot& snapshot);
    skewer::ui::ProcessBrowser* processes_{};
    QLineEdit* filter_{};
    QLabel* status_{};
    QTableWidget* table_{};
    QTimer timer_;
    QFutureWatcher<traffic::TcpOwnerSnapshot> watcher_;
    RoutingReply routing_{};
    bool routing_known_{};
};
} // namespace skewer::windows
