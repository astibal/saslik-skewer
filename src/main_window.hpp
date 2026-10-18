#pragma once

#include <QMainWindow>
#include <QSet>

class ApplicationModel;
class QLineEdit;
class QSortFilterProxyModel;
class QStringListModel;
class QTreeView;

class MainWindow final : public QMainWindow {
    Q_OBJECT

public:
    explicit MainWindow(QWidget* parent = nullptr);

private slots:
    void launchCommand();
    void rememberExpandedItems();
    void restoreExpandedItems();
    void updateLauncherSuggestions(const QStringList& suggestions);

private:
    ApplicationModel* model_{};
    QSortFilterProxyModel* filtered_model_{};
    QTreeView* tree_{};
    QLineEdit* search_{};
    QLineEdit* command_{};
    QStringListModel* launcher_model_{};
    QSet<QString> expanded_items_;
    bool restored_once_{};
};
