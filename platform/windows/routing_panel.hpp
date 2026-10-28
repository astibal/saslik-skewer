#pragma once
#include "routing_control.hpp"
#include <QWidget>
#include <QFutureWatcher>
#include <QTimer>
#include <functional>
#include <optional>
class QLineEdit;
class QLabel;
class QPushButton;

namespace skewer::windows {
class RoutingPanel final : public QWidget {
public:
    using StateCallback = std::function<void(bool, const RoutingReply&)>;
    explicit RoutingPanel(QWidget* parent = nullptr);
    ~RoutingPanel() override;
    void setStateCallback(StateCallback callback);
    void setServiceName(const QString& service);
    void startSelected(ProcessKey process);
    void stopCurrent();

private:
    struct Request {
        int action{};
        QString service, endpoint;
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
    QLineEdit* service_{};
    QLineEdit* endpoint_{};
    QLabel* status_{};
    QPushButton* pair_{};
    QPushButton* start_{};
    QPushButton* stop_{};
    QTimer timer_;
    QFutureWatcher<Result> watcher_;
    std::shared_ptr<Handle> cancel_;
    std::optional<Request> pending_;
    RoutingReply state_{};
    unsigned epoch_{};
    bool known_{};
    bool action_busy_{};
    StateCallback state_callback_;
};
} // namespace skewer::windows
