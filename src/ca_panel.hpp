#pragma once
#include "ca_store.hpp"
#include <QJsonObject>
#include <QWidget>
#include <QUrl>
class QLabel;
class QLineEdit;
class QTableWidget;
class QPushButton;
class QProgressBar;
class QCheckBox;
class CaTrustPanel final : public QWidget {
    Q_OBJECT
public:
    explicit CaTrustPanel(QWidget* parent = nullptr);
    void setSource(const QUrl& url);
signals:
    void caStatusChanged(const QHash<QString, QString>& statuses, const QString& fingerprint);
    void trustReportReady(const QJsonObject& report);
private:
    void loadCertificate(const QByteArray& pem);
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
    QTableWidget* table_{};
    QCheckBox *applicable_{}, *current_snap_{};
    QPushButton *fetch_{}, *load_{}, *save_{}, *scan_{}, *install_{}, *remove_{}, *remove_all_{};
    bool working_{};
};
