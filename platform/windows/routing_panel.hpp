#pragma once
#include "routing_control.hpp"
#include "service_installer.hpp"
#include <QWidget>
#include <QFutureWatcher>
#include <QTimer>
#include <functional>
#include <optional>
class QLineEdit;
class QComboBox;
class QLabel;
class QPushButton;

namespace skewer::windows {
class RoutingPanel final : public QWidget {
public:
    using StateCallback = std::function<void(bool, const RoutingReply&)>;
    explicit RoutingPanel(QWidget* parent = nullptr, QString service_override = {});
    ~RoutingPanel() override;
    void setStateCallback(StateCallback callback);
    void setServiceName(const QString& service);
    QString serviceName() const;
    void setPairedEndpoint(const QString& endpoint);
    void startSelected(ProcessKey process);
    void releaseSelected(ProcessKey process);
    bool actionPending() const { return action_busy_; }
    void stopCurrent();

private:
    struct Request {
        int action{};
        QString service, endpoint, gateway;
        std::uint64_t generation{};
        std::optional<ProcessKey> selected;
        unsigned epoch{};
    };
    struct Result {
        Request request;
        RoutingReply reply{};
        QString error;
    };
    void submit(int action);
    void dispatch(Request request);
    void updateControls();
    bool validDirectGateway() const;
    bool nextStartUsesDirect() const;
    bool nextStartRequiresPairing() const;
    QLineEdit* service_{};
    QLineEdit* endpoint_{};
    QLineEdit* gateway_{};
    QComboBox* transport_{};
    QLabel* status_{};
    QPushButton* pair_{};
    QPushButton* start_{};
    QPushButton* stop_{};
    QPushButton* install_{};
    QPushButton* remove_{};
    QTimer timer_;
    QFutureWatcher<Result> watcher_;
    QFutureWatcher<InstallerResult> install_watcher_;
    QFutureWatcher<InstallerResult> remove_watcher_;
    std::shared_ptr<Handle> cancel_;
    std::optional<Request> pending_;
    RoutingReply state_{};
    unsigned epoch_{};
    bool known_{};
    bool action_busy_{};
    bool automatic_pairing_attempted_{};
    bool service_overridden_{};
    QString pending_endpoint_;
    StateCallback state_callback_;
};
} // namespace skewer::windows
