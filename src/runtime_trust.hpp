#pragma once
#include <QByteArray>
#include <QWidget>
class QLabel;
class QPushButton;
class QTableWidget;
class RuntimeTrustPanel final : public QWidget {
    Q_OBJECT
public:
    explicit RuntimeTrustPanel(QWidget* parent = nullptr);
public slots:
    void setCertificate(const QByteArray& pem);
signals:
    void selectCertificateRequested();
private:
    void refresh();
    void prepareBundle();
    void removeBundle();
    void copyEnvironment() const;
    QString managedDirectory() const;
    QString managedCaPath() const;
    QString managedBundlePath() const;
    void updateActions();
    QByteArray certificate_;
    QLabel* summary_{};
    QPushButton* refresh_{};
    QPushButton* prepare_{};
    QPushButton* remove_{};
    QPushButton* copy_{};
    QTableWidget* table_{};
    bool working_{};
};
