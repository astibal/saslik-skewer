#pragma once

#include "process_browser.hpp"
#include <QCompleter>
#include <QStandardItemModel>

namespace skewer::ui {

// An in-memory history, not an executable-name resolver or a command shell.
// Display labels are never passed to the operating system as commands.
class LaunchCatalog final : public QStandardItemModel {
public:
    enum Role { ExecutableRole = Qt::UserRole + 1 };
    explicit LaunchCatalog(QObject* parent = nullptr, int capacity = 256);
    void remember(const QVector<ProcessRecord>& records);

private:
    struct Entry {
        QString name;
        QString executable;
        bool has_window{};
        bool operator==(const Entry&) const = default;
    };

    int capacity_;
    QVector<Entry> history_;
};

class ApplicationCompleter final : public QCompleter {
public:
    explicit ApplicationCompleter(LaunchCatalog* catalog, QObject* parent = nullptr);
    QString pathFromIndex(const QModelIndex& index) const override;
};

} // namespace skewer::ui
