#pragma once
#include "ca_store.hpp"
#include <QJsonObject>
#include <QWidget>
#include <QUrl>
class QLabel;
class QLineEdit;
class QTreeWidget;
class QPushButton;
class QProgressBar;
class QCheckBox;
class QComboBox;
class CaTrustPanel final : public QWidget {
    Q_OBJECT
public:
    explicit CaTrustPanel(QWidget* parent = nullptr);
    void setSource(const QUrl& url);
    void setRemoteCertificate(const QByteArray& pem);
    void setRemoteDisconnected();
    void disconnectAndOfferRemoval();
signals:
    void certificateChanged(const QByteArray& pem);
    void caStatusChanged(const QHash<QString, QString>& statuses, const QString& fingerprint);
    void trustReportReady(const QJsonObject& report);
private:
    void loadCertificate(const QByteArray& pem, bool remove_all = false);
    void removeWhenIdle(const QByteArray& pem);
    quint64 remote_epoch_{};
    void refreshKnownCertificates();
    QComboBox* known_certificates_{};
    QString active_fingerprint_;
    QString last_remote_fingerprint_;
    void scan(bool remove_all = false);
    void modify(QVector<CaStore> targets, bool remove);
    void busy(bool value);
    void selectionChanged();
    void applyFilters();
    int selectedStore() const;
    QSslCertificate certificate_;
    QVector<CaStore> stores_;
    QLineEdit* source_{};
    QLabel* certificate_info_{};
    QLabel* status_{};
    QProgressBar* progress_{};
    QTreeWidget* table_{};
    QCheckBox *applicable_{}, *current_snap_{};
    QPushButton *fetch_{}, *load_{}, *save_{}, *scan_{}, *install_{}, *remove_{}, *remove_all_{};
    bool working_{};
};
