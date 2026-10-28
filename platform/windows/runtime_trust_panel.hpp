#pragma once
#include "processes.hpp"
#include <QByteArray>
#include <QFutureWatcher>
#include <QWidget>

class QLabel;
class QPushButton;

namespace skewer::windows {
struct RuntimeTrustResult {
    QString message;
    QString ca_path;
    QString bundle_path;
};

EnvironmentOverrides managedRuntimeEnvironment();

class RuntimeTrustPanel final : public QWidget {
public:
    explicit RuntimeTrustPanel(QWidget* parent = nullptr);
    ~RuntimeTrustPanel() override;
    void setCertificate(const QByteArray& pem);

private:
    void prepare();
    void remove();
    void updateControls();
    QByteArray certificate_;
    QLabel* certificate_status_{};
    QLabel* status_{};
    QPushButton* prepare_{};
    QPushButton* remove_{};
    QPushButton* copy_{};
    QFutureWatcher<RuntimeTrustResult> watcher_;
};
} // namespace skewer::windows
