#include "launch_catalog.hpp"
#include <QHash>
#include <algorithm>

namespace skewer::ui {

LaunchCatalog::LaunchCatalog(QObject* parent, int capacity)
    : QStandardItemModel(parent), capacity_(std::max(1, capacity)) {}

void LaunchCatalog::remember(const QVector<ProcessRecord>& records) {
    QHash<QString, Entry> current;
    for (const auto& record : records) {
        if (!record.pid || record.executable.isEmpty()) {
            continue;
        }
        Entry entry{record.name, record.executable, !record.windows.isEmpty()};
        auto existing = current.find(entry.executable);
        // Prefer the visible application's label over its renderer/helper label.
        if (existing == current.end() || (!existing->has_window && entry.has_window)) {
            current.insert(record.executable, std::move(entry));
        }
    }

    QVector<Entry> next;
    next.reserve(current.size() + history_.size());
    for (const auto& entry : current) {
        next.append(entry);
    }
    std::sort(next.begin(), next.end(), [](const Entry& left, const Entry& right) {
        if (left.has_window != right.has_window) {
            return left.has_window;
        }
        const int by_name = QString::compare(left.name, right.name, Qt::CaseInsensitive);
        return by_name == 0 ? left.executable < right.executable : by_name < 0;
    });
    // Keep previously observed paths without persisting potentially sensitive
    // application history. Bound memory even during long-running sessions.
    for (const auto& entry : history_) {
        if (!current.contains(entry.executable)) {
            next.append(entry);
        }
    }
    if (next.size() > capacity_) {
        next.resize(capacity_);
    }
    if (next == history_) {
        return;
    }
    history_ = std::move(next);
    clear();
    for (const auto& entry : history_) {
        const auto label =
            entry.name.isEmpty() ? entry.executable : entry.name + QStringLiteral(" — ") + entry.executable;
        auto* item = new QStandardItem(label);
        item->setData(entry.executable, ExecutableRole);
        item->setToolTip(entry.executable);
        item->setEditable(false);
        appendRow(item);
    }
}

ApplicationCompleter::ApplicationCompleter(LaunchCatalog* catalog, QObject* parent)
    : QCompleter(catalog, parent) {
    setCompletionRole(Qt::DisplayRole);
    setCaseSensitivity(Qt::CaseInsensitive);
    setFilterMode(Qt::MatchContains);
}

QString ApplicationCompleter::pathFromIndex(const QModelIndex& index) const {
    return index.data(LaunchCatalog::ExecutableRole).toString();
}

} // namespace skewer::ui
