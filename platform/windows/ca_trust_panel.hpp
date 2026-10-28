#pragma once

#include <QFutureWatcher>
#include <QWidget>

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
    explicit CaTrustPanel(QWidget* parent = nullptr);

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
};
} // namespace skewer::windows
