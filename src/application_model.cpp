#include "application_model.hpp"

#include <QFileIconProvider>
#include <QFileInfo>
#include <QHash>

#include <algorithm>
#include <unistd.h>

ApplicationModel::ApplicationModel(QObject* parent)
    : QAbstractItemModel(parent)
{
    refresh_timer_.setInterval(2000);
    connect(&refresh_timer_, &QTimer::timeout, this, &ApplicationModel::refresh);
    refresh_timer_.start();
    refresh();
}

QModelIndex ApplicationModel::index(int row, int column, const QModelIndex& parent_index) const
{
    Node* parent_node = node(parent_index);
    const auto& children = parent_node ? parent_node->children : roots_;
    if (row < 0 || static_cast<std::size_t>(row) >= children.size()
        || column < 0 || column >= ColumnCount) {
        return {};
    }
    return createIndex(row, column, children.at(row).get());
}

QModelIndex ApplicationModel::parent(const QModelIndex& child) const
{
    Node* child_node = node(child);
    if (!child_node || !child_node->parent) {
        return {};
    }
    Node* parent_node = child_node->parent;
    const auto& siblings = parent_node->parent ? parent_node->parent->children : roots_;
    for (std::size_t row = 0; row < siblings.size(); ++row) {
        if (siblings.at(row).get() == parent_node) {
            return createIndex(static_cast<int>(row), 0, parent_node);
        }
    }
    return {};
}

int ApplicationModel::rowCount(const QModelIndex& parent_index) const
{
    if (parent_index.column() > 0) {
        return 0;
    }
    Node* parent_node = node(parent_index);
    return static_cast<int>(parent_node ? parent_node->children.size() : roots_.size());
}

int ApplicationModel::columnCount(const QModelIndex&) const
{
    return ColumnCount;
}

QVariant ApplicationModel::data(const QModelIndex& model_index, int role) const
{
    Node* item = node(model_index);
    if (!item) {
        return {};
    }
    if (role == Qt::DisplayRole) {
        switch (model_index.column()) {
        case NameColumn: return item->process.name;
        case ProcessIdColumn: return item->process.pid;
        case CommandColumn:
            return item->process.command_line.isEmpty() ? item->process.executable
                                                        : item->process.command_line;
        default: return {};
        }
    }
    if (role == Qt::DecorationRole && model_index.column() == NameColumn
        && !item->process.executable.isEmpty()) {
        static QFileIconProvider icons;
        return icons.icon(QFileInfo(item->process.executable));
    }
    if (role == Qt::ToolTipRole) {
        return item->process.command_line;
    }
    return {};
}

QVariant ApplicationModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (orientation != Qt::Horizontal || role != Qt::DisplayRole) {
        return {};
    }
    switch (section) {
    case NameColumn: return tr("Application / process");
    case ProcessIdColumn: return tr("PID");
    case CommandColumn: return tr("Command");
    default: return {};
    }
}

void ApplicationModel::refresh()
{
    const QVector<ProcessInfo> processes = scanner_.scan(getuid());
    beginResetModel();
    roots_.clear();
    QHash<pid_t, Node*> nodes;
    for (const ProcessInfo& process : processes) {
        auto item = std::make_unique<Node>();
        item->process = process;
        nodes.insert(process.pid, item.get());
        roots_.push_back(std::move(item));
    }

    for (int index = static_cast<int>(roots_.size()) - 1; index >= 0; --index) {
        auto& item = roots_[index];
        Node* parent_node = nodes.value(item->process.parent_pid, nullptr);
        if (!parent_node || parent_node == item.get()) {
            continue;
        }
        item->parent = parent_node;
        parent_node->children.push_back(std::move(item));
        roots_.erase(roots_.begin() + index);
    }

    const auto order = [](const std::unique_ptr<Node>& left,
                          const std::unique_ptr<Node>& right) {
        const bool left_app = isLikelyApplication(left->process);
        const bool right_app = isLikelyApplication(right->process);
        if (left_app != right_app) {
            return left_app > right_app;
        }
        return left->process.name.localeAwareCompare(right->process.name) < 0;
    };
    std::sort(roots_.begin(), roots_.end(), order);
    endResetModel();
}

ApplicationModel::Node* ApplicationModel::node(const QModelIndex& index) const
{
    return index.isValid() ? static_cast<Node*>(index.internalPointer()) : nullptr;
}

bool ApplicationModel::isLikelyApplication(const ProcessInfo& process)
{
    return !process.executable.isEmpty() && process.parent_pid > 1
        && !process.name.startsWith(QLatin1Char('('));
}
