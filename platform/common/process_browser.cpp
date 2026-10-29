#include "process_browser.hpp"
#include <QHeaderView>
#include <QColor>
#include <QScrollBar>
#include <QSet>
#include <QVBoxLayout>
#include <algorithm>
#include <functional>

namespace skewer::ui {
QString ProcessRecord::identity() const {
    return QString::number(pid) + QLatin1Char(':') + QString::number(created);
}

ProcessBrowser::ProcessBrowser(QWidget* parent, QTreeView* view)
    : QWidget(parent), tree_(view ? view : new QTreeView(this)) {
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->addWidget(tree_);
    model_.setHorizontalHeaderLabels(
        {tr("Application / process"), tr("PID"), tr("Routing"), tr("Executable / windows")});
    tree_->setModel(&model_);
    tree_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    tree_->setSelectionBehavior(QAbstractItemView::SelectRows);
    tree_->setUniformRowHeights(true);
    tree_->setAlternatingRowColors(true);
    tree_->setColumnWidth(0, 300);
    tree_->setColumnWidth(1, 85);
    tree_->setColumnWidth(2, 120);
    tree_->header()->setStretchLastSection(true);
}

QStringList ProcessBrowser::launchSuggestions() const {
    QStringList paths;
    for (const auto& record : records_) {
        if (!record.executable.isEmpty()) {
            paths.append(record.executable);
        }
    }
    paths.removeDuplicates();
    paths.sort(Qt::CaseInsensitive);
    return paths;
}

std::optional<ProcessRecord> ProcessBrowser::selectedProcess() const {
    QModelIndex index;
    const auto selected_rows = tree_->selectionModel()->selectedRows(0);
    if (!selected_rows.isEmpty()) {
        index = selected_rows.front();
    } else {
        const auto selected_indexes = tree_->selectionModel()->selectedIndexes();
        if (!selected_indexes.isEmpty()) {
            index = selected_indexes.front().siblingAtColumn(0);
        } else {
            index = tree_->currentIndex();
        }
    }
    if (!index.isValid()) {
        return std::nullopt;
    }
    const auto identity = index.siblingAtColumn(0).data(IdentityRole).toString();
    const auto found = std::find_if(records_.cbegin(), records_.cend(), [&](const auto& record) {
        return record.identity() == identity;
    });
    return found == records_.cend() ? std::nullopt : std::optional<ProcessRecord>(*found);
}

void ProcessBrowser::setFilterText(const QString& text) {
    filter_ = text;
    std::function<bool(const QModelIndex&)> visit = [&](const QModelIndex& parent) {
        bool any = false;
        for (int row = 0; row < model_.rowCount(parent); ++row) {
            const auto index = model_.index(row, 0, parent);
            const bool child_match = visit(index);
            bool matches = filter_.isEmpty();
            for (int column = 0; column < model_.columnCount(); ++column) {
                const auto cell = index.siblingAtColumn(column);
                matches |= cell.data().toString().contains(filter_, Qt::CaseInsensitive) ||
                           cell.data(Qt::ToolTipRole).toString().contains(filter_, Qt::CaseInsensitive);
            }
            const bool visible = matches || child_match;
            tree_->setRowHidden(row, parent, !visible);
            if (!filter_.isEmpty() && child_match) {
                tree_->expand(index);
            }
            any |= visible;
        }
        return any;
    };
    visit({});
}

void ProcessBrowser::setProcesses(QVector<ProcessRecord> records) {
    std::sort(records.begin(), records.end(), [](const auto& a, const auto& b) { return a.pid < b.pid; });
    // Idle polling must not disturb selection or invalidate model indexes.
    if (initialized_ && records == records_) {
        return;
    }
    const auto state = captureViewState();
    records_ = std::move(records);
    rebuildModel();
    restoreViewState(state);
    initialized_ = true;
    setFilterText(filter_);
}

void ProcessBrowser::setRoutingState(bool available, const QString& routed_identity) {
    setRoutingSelections(available, routed_identity.isEmpty() ? QStringList{} : QStringList{routed_identity});
}
void ProcessBrowser::setRoutingSelections(bool available, const QStringList& identities) {
    setRoutingDisplay(!available ? RoutingDisplay::Unavailable : identities.isEmpty()
        ? RoutingDisplay::Direct : RoutingDisplay::Selected, identities);
}
void ProcessBrowser::setRoutingDisplay(RoutingDisplay display, const QStringList& identities) {
    auto normalized = display == RoutingDisplay::Unavailable ? QStringList{} : identities;
    normalized.removeDuplicates();
    normalized.sort();
    if (routing_display_ == display && routed_identities_ == normalized) {
        return;
    }
    const auto state = captureViewState();
    routing_display_ = display;
    routed_identities_ = normalized;
    rebuildModel();
    restoreViewState(state);
    setFilterText(filter_);
}

ProcessBrowser::ViewState ProcessBrowser::captureViewState() const {
    ViewState state;
    const auto current = tree_->currentIndex();
    if (current.isValid()) {
        state.selected = current.siblingAtColumn(0).data(IdentityRole).toString();
    }
    std::function<void(const QModelIndex&)> remember = [&](const QModelIndex& parent) {
        for (int row = 0; row < model_.rowCount(parent); ++row) {
            const auto index = model_.index(row, 0, parent);
            const auto id = index.data(IdentityRole).toString();
            state.seen.insert(id);
            if (tree_->isExpanded(index)) {
                state.expanded.insert(id);
            }
            remember(index);
        }
    };
    remember({});
    state.scroll = tree_->verticalScrollBar()->value();
    return state;
}

void ProcessBrowser::rebuildModel() {
    model_.removeRows(0, model_.rowCount());
    auto section = [&](const QString& title, const QString& id) {
        auto* item = new QStandardItem(title);
        item->setData(id, IdentityRole);
        auto font = item->font();
        font.setBold(true);
        item->setFont(font);
        model_.appendRow(item);
        return item;
    };
    auto* applications = section(tr("Applications with windows"), QStringLiteral("applications"));
    auto* background = section(tr("Other user processes"), QStringLiteral("background"));
    QHash<quint64, const ProcessRecord*> by_pid;
    QHash<quint64, QStandardItem*> items;
    for (const auto& record : records_) {
        // A malformed or duplicated record must not create an ambiguous tree.
        if (!record.pid || by_pid.contains(record.pid)) {
            continue;
        }
        by_pid.insert(record.pid, &record);
        auto* item = new QStandardItem(record.name.isEmpty() ? QString::number(record.pid) : record.name);
        item->setData(record.identity(), IdentityRole);
        item->setData(record.executable, ExecutableRole);
        item->setToolTip(record.windows.join(QLatin1Char('\n')));
        items.insert(record.pid, item);
    }
    QHash<quint64, quint64> parents;
    for (auto it = by_pid.cbegin(); it != by_pid.cend(); ++it) {
        const auto& record = *it.value();
        const auto parent = by_pid.value(record.parent);
        // A window-bearing child is a separate application, not part of its launcher.
        const bool valid_parent = parent && parent->created <= record.created && parent->pid != record.pid;
        parents.insert(record.pid, record.windows.isEmpty() && valid_parent ? parent->pid : 0);
    }
    // Defensively cut cycles (including equal timestamps), never recurse forever.
    QSet<quint64> checked;
    for (const auto& record : records_) {
        QSet<quint64> path;
        auto pid = record.pid;
        while (pid && !checked.contains(pid)) {
            if (path.contains(pid)) {
                parents[pid] = 0;
                break;
            }
            path.insert(pid);
            pid = parents.value(pid);
        }
        checked.unite(path);
    }
    QSet<quint64> attached;
    for (const auto& record : records_) {
        if (!items.contains(record.pid) || attached.contains(record.pid)) {
            continue;
        }
        attached.insert(record.pid);
        auto* parent = items.value(parents.value(record.pid));
        if (!parent) {
            parent = record.windows.isEmpty() ? background : applications;
        }
        auto* details = new QStandardItem(record.executable);
        details->setToolTip(record.executable + QLatin1Char('\n') + record.windows.join(QLatin1Char('\n')));
        auto* routing = new QStandardItem;
        const bool selected = routed_identities_.contains(record.identity());
        switch (routing_display_) {
        case RoutingDisplay::Unavailable: routing->setText(tr("Unavailable")); break;
        case RoutingDisplay::Direct: routing->setText(tr("Direct")); break;
        case RoutingDisplay::WholeHost: routing->setText(tr("Host policy")); break;
        case RoutingDisplay::BlockedHost: routing->setText(tr("Host blocked")); break;
        case RoutingDisplay::Transition: routing->setText(tr("Transitioning")); break;
        case RoutingDisplay::Selected:
            routing->setText(selected ? tr("Routed") : tr("Unconfirmed")); break;
        case RoutingDisplay::BlockedSelected:
            routing->setText(selected ? tr("Blocked") : tr("Unconfirmed")); break;
        }
        // A process-tree snapshot is not authoritative Job membership. An
        // unlisted child may still be selected, even after its parent exits.
        routing->setToolTip(tr("Selected roots and reported live members are confirmed by the service. Membership is not inferred. "
                               "Host policy includes configured exemptions; routing currently covers IPv4."));
        if (selected && routing_display_ == RoutingDisplay::Selected) {
            auto font = routing->font();
            font.setBold(true);
            routing->setFont(font);
            routing->setForeground(QColor(61, 194, 126));
        }
        parent->appendRow({items.value(record.pid), new QStandardItem(QString::number(record.pid)),
                           routing, details});
    }
}

void ProcessBrowser::restoreViewState(const ViewState& state) {
    // PID plus creation time prevents selection from jumping to a reused PID.
    std::function<void(const QModelIndex&)> restore = [&](const QModelIndex& parent) {
        for (int row = 0; row < model_.rowCount(parent); ++row) {
            const auto index = model_.index(row, 0, parent);
            const auto id = index.data(IdentityRole).toString();
            if (state.expanded.contains(id) || (!state.seen.contains(id) && !parent.isValid())) {
                tree_->expand(index);
            }
            if (id == state.selected) {
                tree_->setCurrentIndex(index);
            }
            restore(index);
        }
    };
    restore({});
    tree_->verticalScrollBar()->setValue(state.scroll);
}
} // namespace skewer::ui
