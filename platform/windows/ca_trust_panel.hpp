#pragma once

#include <QFutureWatcher>
#include <QWidget>
#include <functional>

class QLabel;
class QLineEdit;
class QPushButton;

namespace skewer::windows {
class CaTrustPanel final : public QWidget {
public:
    struct Result {
        QByteArray pem;
        QString message;
        bool present{};
    };
    using CertificateCallback = std::function<void(const QByteArray&)>;
    explicit CaTrustPanel(QWidget* parent = nullptr);
    void setPairedEndpoint(const QString& endpoint);
    void setCertificateCallback(CertificateCallback callback);

private:
    void download();
    void store(bool remove);
    void applyCertificate(const QByteArray& pem);
    void updateControls();

    QLabel* details_{};
    QLineEdit* endpoint_{};
    QLabel* status_{};
    QPushButton* download_{};
    QPushButton* install_{};
    QPushButton* remove_{};
    QByteArray certificate_;
    QFutureWatcher<Result> watcher_;
    CertificateCallback certificate_callback_;
};
} // namespace skewer::windows
