#pragma once

#include <QMainWindow>

class ApplicationModel;
class QLineEdit;
class QSortFilterProxyModel;
class QTreeView;

class MainWindow final : public QMainWindow {
    Q_OBJECT

public:
    explicit MainWindow(QWidget* parent = nullptr);

private slots:
    void launchCommand();

private:
    ApplicationModel* model_{};
    QSortFilterProxyModel* filtered_model_{};
    QTreeView* tree_{};
    QLineEdit* search_{};
    QLineEdit* command_{};
};
