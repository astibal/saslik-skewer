#include "application_model.hpp"

#include <QApplication>
#include <QBrush>
#include <QFileIconProvider>
#include <QFileInfo>
#include <QFont>
#include <QHash>
#include <QPalette>
#include <QFutureWatcher>
#include <QtConcurrent>

#include <algorithm>
#include <unistd.h>

ApplicationModel::ApplicationModel(QObject* parent) : QAbstractItemModel(parent)
{
    refresh_timer_.setInterval(5000);
    auto* scan = new QFutureWatcher<QVector<ProcessInfo>>(this);
    connect(scan, &QFutureWatcher<QVector<ProcessInfo>>::finished, this, [this, scan] {
        if (scan->property("revision").toULongLong() == process_revision_)
            setProcesses(scan->result());
    });
    connect(&refresh_timer_, &QTimer::timeout, this, [this, scan] {
        if (scan->isRunning()) return;
        // A hidden GUI needs no process-tree refresh. TUI has no QWidget.
        const auto windows = QApplication::topLevelWidgets();
        if (!windows.isEmpty() && std::none_of(windows.begin(), windows.end(),
                [](const QWidget* window) { return window->isVisible(); })) return;
        scan->setProperty("revision", QVariant::fromValue(process_revision_));
        scan->setFuture(QtConcurrent::run([] { return ProcessScanner().scan(getuid()); }));
    });
    refresh_timer_.start();
    refresh();
}

QModelIndex ApplicationModel::index(int row, int column, const QModelIndex& parent_index) const
{
    Node* parent_node = node(parent_index);
    const auto& children = parent_node ? parent_node->children : roots_;
    if (row < 0 || static_cast<std::size_t>(row) >= children.size()
        || column < 0 || column >= ColumnCount) return {};
    return createIndex(row, column, children.at(row).get());
}

QModelIndex ApplicationModel::parent(const QModelIndex& child) const
{
    Node* child_node = node(child);
    if (!child_node || !child_node->parent) return {};
    Node* parent_node = child_node->parent;
    const auto& siblings = parent_node->parent ? parent_node->parent->children : roots_;
    for (std::size_t row = 0; row < siblings.size(); ++row) {
        if (siblings.at(row).get() == parent_node)
            return createIndex(static_cast<int>(row), 0, parent_node);
    }
    return {};
}

int ApplicationModel::rowCount(const QModelIndex& parent_index) const
{
    if (parent_index.column() > 0) return 0;
    Node* parent_node = node(parent_index);
    return static_cast<int>(parent_node ? parent_node->children.size() : roots_.size());
}

int ApplicationModel::columnCount(const QModelIndex&) const { return ColumnCount; }

QVariant ApplicationModel::data(const QModelIndex& model_index, int role) const
{
    Node* item = node(model_index);
    if (!item) return {};
    if (model_index.column() == ConnectionsColumn && item->type != NodeType::Section
        && (role == Qt::DisplayRole || role == Qt::ForegroundRole || role == Qt::ToolTipRole)) {
        if (!item->connections_cached) {
            QSet<int> pids;
            const auto collect = [&pids](const auto& self, const Node& current) -> void {
                if (current.type == NodeType::Process) pids.insert(current.process.pid);
                for (const auto& child : current.children) self(self, *child);
            };
            collect(collect, *item);
            int outside = 0, total = 0;
            bool unknown = !connections_.complete || connections_.unreadable_pids.intersects(pids);
            for (const auto& socket : connections_.rows) {
                if (!socket.pids.intersects(pids)) continue;
                ++total;
                if (socket.group.isEmpty()) unknown = true;
                else if (!socket.group.split('/').contains("skewer-routed.slice")) ++outside;
            }
            item->sockets_total = total;
            item->sockets_outside = outside;
            item->sockets_unknown = unknown;
            item->connections_cached = true;
        }
        const int total = item->sockets_total;
        const int outside = item->sockets_outside;
        const bool unknown = item->sockets_unknown;
        if (role == Qt::DisplayRole)
            return outside ? tr("● %1 out").arg(outside) : unknown ? tr("? Unknown") : total ? tr("● All") : QStringLiteral("—");
        if (role == Qt::ForegroundRole)
            return QBrush(QColor(outside ? "#dda844" : unknown || !total ? "#999999" : "#48c988"));
        if (role == Qt::ToolTipRole)
            return tr("%1 observed sockets; %2 outside Skewer. %3\nSocket cgroup membership only, not proof of routing or interception. TCP and connected UDP, current network namespace.")
                .arg(total).arg(outside).arg(unknown ? tr("Incomplete / unverified snapshot.") : tr("No known collection errors."));
    }
    if (role == StableIdRole) return item->id;
    if (role == NodeTypeRole) return static_cast<int>(item->type);
    if (role == LaunchCommandRole) return item->launch_command;
    if (role == RoutedRole) return item->routed;
    if (role == PartiallyRoutedRole) return item->partially_routed;
    if (role == ProcessIdsRole) {
        QVariantList pids;
        const auto collect = [&pids](const auto& self, const Node& current) -> void {
            if (current.type == NodeType::Process) pids.push_back(current.process.pid);
            for (const auto& child : current.children) self(self, *child);
        };
        collect(collect, *item);
        return pids;
    }
    if (role == Qt::DisplayRole) {
        if (model_index.column() == CaColumn && item->type == NodeType::Application)
            return ca_fingerprint_.isEmpty() ? QStringLiteral("-")
                : ca_statuses_.value(item->identity, QStringLiteral("-"));
        if (model_index.column() == NameColumn) return item->title;
        if (model_index.column() == ProcessIdColumn && item->type == NodeType::Process)
            return item->process.pid;
        if (model_index.column() == CommandColumn) return item->subtitle;
        if (model_index.column() == RoutingColumn && item->type == NodeType::Application)
            return item->partially_routed ? tr("◐ Partially attached")
                : item->routed ? tr("● Attached") : QString{};
    }
    if (role == Qt::DecorationRole && model_index.column() == NameColumn && !item->icon.isNull())
        return item->icon;
    if (role == Qt::ToolTipRole && model_index.column() == CaColumn)
        return tr("Selected CA: %1\nLast scan of mapped profiles only; this does not verify the application's active TLS connections.")
            .arg(ca_fingerprint_.isEmpty() ? tr("none") : ca_fingerprint_);
    if (role == Qt::ForegroundRole && model_index.column() == CaColumn
        && ca_statuses_.value(item->identity).contains("missing", Qt::CaseInsensitive))
        return QBrush(QColor("#dc9930"));
    if (role == Qt::ToolTipRole)
        return item->type == NodeType::Process ? item->process.command_line : item->subtitle;
    if (role == Qt::FontRole && item->type != NodeType::Process
        && model_index.column() == NameColumn) {
        QFont font;
        font.setBold(true);
        return font;
    }
    if (role == Qt::ForegroundRole && item->type == NodeType::Section)
        return QBrush(QApplication::palette().color(QPalette::Active, QPalette::Text));
    return {};
}

QVariant ApplicationModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (orientation != Qt::Horizontal || role != Qt::DisplayRole) return {};
    switch (section) {
    case NameColumn: return tr("Application / process");
    case ProcessIdColumn: return tr("PID");
    case RoutingColumn: return tr("Routing");
    case CaColumn: return tr("CA trust · profiles");
    case ConnectionsColumn: return tr("Conn.");
    case CommandColumn: return tr("Identity / command");
    default: return {};
    }
}

QStringList ApplicationModel::launcherSuggestions() const
{
    QStringList result = launch_commands_.keys();
    result.sort(Qt::CaseInsensitive);
    return result;
}

void ApplicationModel::setConnections(const ConnectionSnapshot& snapshot)
{
    if (connections_ == snapshot) return;
    connections_ = snapshot;
    const auto update = [this](const auto& self, const QModelIndex& parent) -> void {
        for (int row=0; row<rowCount(parent); ++row) {
            const auto cell = index(row, ConnectionsColumn, parent);
            node(cell)->connections_cached = false;
            emit dataChanged(cell, cell, {Qt::DisplayRole, Qt::ForegroundRole, Qt::ToolTipRole});
            self(self, index(row, 0, parent));
        }
    };
    update(update, {});
}
void ApplicationModel::setCaStatus(const QHash<QString, QString>& statuses, const QString& fingerprint)
{
    ca_statuses_ = statuses;
    ca_fingerprint_ = fingerprint;
    const auto update = [this](const auto& self, const QModelIndex& parent) -> void {
        for (int row = 0; row < rowCount(parent); ++row) {
            const auto cell = index(row, CaColumn, parent);
            emit dataChanged(cell, cell);
            self(self, index(row, 0, parent));
        }
    };
    update(update, {});
}

QString ApplicationModel::resolveLaunchCommand(const QString& text) const
{
    return launch_commands_.value(text, text);
}

void ApplicationModel::refresh()
{
    const QVector<ProcessInfo> processes = scanner_.scan(getuid());
    setProcesses(processes);
}

void ApplicationModel::setProcesses(const QVector<ProcessInfo>& processes)
{
    ++process_revision_;
    QByteArray snapshot;
    for (const ProcessInfo& process : processes) {
        snapshot += QByteArray::number(process.pid) + ':'
            + QByteArray::number(process.parent_pid) + ':'
            + process.cgroup.toUtf8() + ':' + process.name.toUtf8() + ':'
            + process.executable.toUtf8() + ':' + process.command_line.toUtf8() + '\n';
    }
    if (snapshot == snapshot_) return;
    snapshot_ = std::move(snapshot);

    QHash<pid_t, const ProcessInfo*> by_pid;
    for (const ProcessInfo& process : processes) by_pid.insert(process.pid, &process);
    QHash<QString, QVector<ProcessInfo>> groups;
    for (const ProcessInfo& process : processes)
        groups[applicationKey(process, by_pid)].push_back(process);

    auto foreground = std::make_unique<Node>();
    foreground->type = NodeType::Section;
    foreground->id = QStringLiteral("section:applications");
    foreground->title = tr("Applications");
    auto background = std::make_unique<Node>();
    background->type = NodeType::Section;
    background->id = QStringLiteral("section:other");
    background->title = tr("Other user processes");

    launch_commands_.clear();
    for (const DesktopEntry& entry : catalog_.entries())
        launch_commands_.insert(entry.name, entry.launch_command);
    for (auto it = groups.begin(); it != groups.end(); ++it) {
        const bool is_foreground = foregroundGroup(it.key());
        auto application = buildApplication(it.key(), it.value(), is_foreground);
        application->parent = is_foreground ? foreground.get() : background.get();
        (is_foreground ? foreground->children : background->children).push_back(std::move(application));
    }
    groupInstances(*foreground);
    groupInstances(*background);

    std::vector<std::unique_ptr<Node>> desired;
    if (!foreground->children.empty()) desired.push_back(std::move(foreground));
    if (!background->children.empty()) desired.push_back(std::move(background));

    // Index existing objects first. A process moving between applications must
    // keep its persistent index, just like an unchanged process does.
    QHash<QString, Node*> existing;
    const auto inventory = [&existing](const auto& self, auto& items) -> void {
        for (auto& item : items) {
            existing.insert(item->id, item.get());
            self(self, item->children);
        }
    };
    inventory(inventory, roots_);
    const auto modelIndex = [this](Node* item) -> QModelIndex {
        if (!item) return {};
        const auto& siblings = item->parent ? item->parent->children : roots_;
        for (std::size_t i = 0; i < siblings.size(); ++i)
            if (siblings[i].get() == item) return createIndex(int(i), 0, item);
        return {};
    };
    QSet<QString> retained;
    QSet<Node*> changedItems;
    const auto processIds = [](const auto& self, const Node& item) -> QSet<int> {
        QSet<int> result;
        if (item.type == NodeType::Process) result.insert(item.process.pid);
        for (const auto& child : item.children) result.unite(self(self, *child));
        return result;
    };
    const auto reconcile = [&](const auto& self, auto& wanted, Node* parent) -> void {
        auto& siblings = parent ? parent->children : roots_;
        for (std::size_t row = 0; row < wanted.size(); ++row) {
            Node& source = *wanted[row];
            Node* item = existing.value(source.id, nullptr);
            if (item) {
                auto& old = item->parent ? item->parent->children : roots_;
                const int from = modelIndex(item).row();
                if (item->parent != parent || from != int(row)) {
                    const int destination = (&old == &siblings && from < int(row))
                        ? int(row) + 1 : int(row);
                    beginMoveRows(modelIndex(item->parent), from, from,
                                  modelIndex(parent), destination);
                    auto owned = std::move(old[from]);
                    old.erase(old.begin() + from);
                    owned->parent = parent;
                    siblings.insert(siblings.begin() + row, std::move(owned));
                    endMoveRows();
                }
            } else {
                beginInsertRows(modelIndex(parent), int(row), int(row));
                auto added = std::make_unique<Node>();
                added->id = source.id;
                added->type = source.type;
                added->parent = parent;
                item = added.get();
                siblings.insert(siblings.begin() + row, std::move(added));
                endInsertRows();
            }
            retained.insert(source.id);
            const bool changed = item->title != source.title || item->subtitle != source.subtitle
                || item->launch_command != source.launch_command || item->routed != source.routed
                || item->partially_routed != source.partially_routed || item->identity != source.identity
                || item->process_count != source.process_count || item->icon.cacheKey() != source.icon.cacheKey()
                || processIds(processIds, *item) != processIds(processIds, source);
            item->title = source.title;
            item->subtitle = source.subtitle;
            item->launch_command = source.launch_command;
            item->icon = source.icon;
            item->routed = source.routed;
            item->partially_routed = source.partially_routed;
            item->identity = source.identity;
            item->process_count = source.process_count;
            item->process = source.process;
            item->connections_cached = false;
            self(self, source.children, item);
            if (changed) changedItems.insert(item);
        }
    };
    reconcile(reconcile, desired, nullptr);
    // Remove obsolete containers only after their surviving descendants have
    // moved to their new parents. Never invalidate unrelated rows wholesale.
    const auto prune = [&](const auto& self, Node* parent) -> void {
        auto& items = parent ? parent->children : roots_;
        for (int row = int(items.size()) - 1; row >= 0; --row) {
            if (!retained.contains(items[row]->id)) {
                beginRemoveRows(modelIndex(parent), row, row);
                items.erase(items.begin() + row);
                endRemoveRows();
            } else self(self, items[row].get());
        }
    };
    prune(prune, nullptr);
    for (Node* item : changedItems)
        emit dataChanged(modelIndex(item), modelIndex(item).siblingAtColumn(ColumnCount - 1));
    emit processesChanged();
    emit launcherSuggestionsChanged(launcherSuggestions());
}

ApplicationModel::Node* ApplicationModel::node(const QModelIndex& index) const
{
    return index.isValid() ? static_cast<Node*>(index.internalPointer()) : nullptr;
}

std::unique_ptr<ApplicationModel::Node>
ApplicationModel::buildApplication(const QString& key, QVector<ProcessInfo> processes,
                                   bool foreground)
{
    auto application = std::make_unique<Node>();
    application->type = NodeType::Application;
    application->id = QStringLiteral("app:") + key;
    application->routed = key.contains(QStringLiteral("skewer-routed"));
    const ProcessInfo* representative = &processes.first();
    QSet<pid_t> members;
    for (const ProcessInfo& process : processes) members.insert(process.pid);
    for (const ProcessInfo& process : processes) {
        // Name an application after its root, never an arbitrary helper child.
        if (!members.contains(process.parent_pid)
            && !process.executable.isEmpty()) { representative = &process; break; }
    }
    // Catalog matching and icon lookup do not change with process churn.
    // Cache misses too, so background processes do not rescan the catalog.
    const QString identity = key + QChar(0) + representative->executable
        + QChar(0) + representative->name;
    if (!desktop_matches_.contains(identity))
        desktop_matches_.insert(identity,
            catalog_.match(key, representative->executable, representative->name));
    const DesktopEntry* entry = desktop_matches_.value(identity);
    if (entry) {
        application->identity = QStringLiteral("desktop:") + entry->id;
        application->title = entry->name;
        if (!application_icons_.contains(entry->id))
            application_icons_.insert(entry->id, entry->icon());
        application->icon = application_icons_.value(entry->id);
        application->launch_command = entry->launch_command;
        launch_commands_.insert(entry->name, entry->launch_command);
    } else {
        // A display name alone must never merge unrelated executables.
        application->identity = representative->executable.isEmpty()
            ? QStringLiteral("unknown:") + key
            : QStringLiteral("exe:") + representative->executable;
        application->title = representative->name;
        application->launch_command = representative->executable;
        if (!representative->executable.isEmpty()) {
            static QFileIconProvider icons;
            const QString icon_key = representative->executable;
            if (!application_icons_.contains(icon_key))
                application_icons_.insert(icon_key, icons.icon(QFileInfo(icon_key)));
            application->icon = application_icons_.value(icon_key);
            launch_commands_.insert(application->title, representative->executable);
        }
    }
    application->subtitle = tr("%1 processes · %2")
                                .arg(processes.size())
                                .arg(foreground ? tr("desktop application") : key);
    application->process_count = processes.size();
    buildProcessTree(*application, std::move(processes));
    return application;
}

void ApplicationModel::groupInstances(Node& section)
{
    std::vector<std::unique_ptr<Node>> grouped;
    QHash<QString, Node*> identities;
    for (auto& instance : section.children) {
        Node* group = identities.value(instance->identity, nullptr);
        if (!group) {
            auto item = std::make_unique<Node>();
            item->type = NodeType::Application;
            item->id = section.id + QStringLiteral(":group:") + instance->identity;
            item->title = instance->title;
            item->identity = instance->identity;
            item->icon = instance->icon;
            item->launch_command = instance->launch_command;
            item->parent = &section;
            group = item.get();
            identities.insert(instance->identity, group);
            grouped.push_back(std::move(item));
        }
        group->process_count += instance->process_count;
        instance->parent = group;
        group->children.push_back(std::move(instance));
    }
    const auto order = [](const auto& left, const auto& right) {
        const int comparison = left->title.localeAwareCompare(right->title);
        return comparison == 0 ? left->id < right->id : comparison < 0;
    };
    for (auto& group : grouped) {
        // Keep single-instance applications compact, preserving their stable ID.
        if (group->children.size() == 1) {
            auto instance = std::move(group->children.front());
            instance->parent = &section;
            group = std::move(instance);
            continue;
        }
        int attached = 0;
        for (auto& instance : group->children) {
            attached += instance->routed;
            instance->subtitle += QStringLiteral(" · ") + instance->id.mid(4);
        }
        group->routed = attached > 0;
        group->partially_routed = attached > 0
            && attached < static_cast<int>(group->children.size());
        group->subtitle = tr("%1 instances · %2 processes")
            .arg(group->children.size()).arg(group->process_count);
        std::sort(group->children.begin(), group->children.end(), order);
    }
    std::sort(grouped.begin(), grouped.end(), order);
    section.children = std::move(grouped);
}

void ApplicationModel::buildProcessTree(Node& application, QVector<ProcessInfo> processes)
{
    QHash<pid_t, Node*> nodes;
    std::vector<std::unique_ptr<Node>> items;
    for (const ProcessInfo& process : processes) {
        auto item = std::make_unique<Node>();
        item->type = NodeType::Process;
        item->process = process;
        item->id = QStringLiteral("pid:%1").arg(process.pid);
        item->title = process.name;
        item->subtitle = process.command_line.isEmpty() ? process.executable : process.command_line;
        nodes.insert(process.pid, item.get());
        items.push_back(std::move(item));
    }
    for (int index = static_cast<int>(items.size()) - 1; index >= 0; --index) {
        auto& item = items.at(index);
        Node* parent = nodes.value(item->process.parent_pid, nullptr);
        if (!parent || parent == item.get()) continue;
        item->parent = parent;
        parent->children.push_back(std::move(item));
        items.erase(items.begin() + index);
    }
    for (auto& item : items) {
        item->parent = &application;
        application.children.push_back(std::move(item));
    }
}

QString ApplicationModel::applicationKey(
    const ProcessInfo& process, const QHash<pid_t, const ProcessInfo*>& processes)
{
    // Units can live outside app.slice (Snap and Skewer do). Keep the full
    // path so similarly named units in different slices cannot be conflated.
    const auto unitKey = [](const QString& path) -> QString {
        const QStringList parts = path.split(QLatin1Char('/'), Qt::SkipEmptyParts);
        for (int i = parts.size() - 1; i >= 0; --i) {
            const QString& part = parts.at(i);
            if (part.startsWith(QStringLiteral("user@"))
                || part.startsWith(QStringLiteral("session-"))) continue;
            if (part.endsWith(QStringLiteral(".scope")) || part.endsWith(QStringLiteral(".service")))
                return QStringLiteral("/") + parts.mid(0, i + 1).join(QLatin1Char('/'));
        }
        return {};
    };
    const QString unit = unitKey(process.cgroup);
    if (!unit.isEmpty()) return unit;
    const ProcessInfo* root = &process;
    QSet<pid_t> visited{process.pid};
    while (const ProcessInfo* parent = processes.value(root->parent_pid, nullptr)) {
        if (visited.contains(parent->pid)) break;
        // Session infrastructure is an ownership boundary, not an application.
        if (parent->name == QStringLiteral("systemd")
            || parent->name == QStringLiteral("init")
            || parent->name == QStringLiteral("kthreadd")
            || parent->cgroup != root->cgroup) break;
        visited.insert(parent->pid);
        root = parent;
    }
    return QStringLiteral("tree:%1").arg(root->pid);
}

bool ApplicationModel::foregroundGroup(const QString& key)
{
    const QString leaf = key.section(QLatin1Char('/'), -1);
    return leaf.endsWith(QStringLiteral(".scope"))
        || (leaf.startsWith(QStringLiteral("app-")) && !leaf.contains(QStringLiteral("@autostart")))
        || leaf.startsWith(QStringLiteral("snap."));
}
