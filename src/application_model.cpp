#include "application_model.hpp"

#include <QApplication>
#include <QBrush>
#include <QFileIconProvider>
#include <QFileInfo>
#include <QFont>
#include <QHash>
#include <QPalette>

#include <algorithm>
#include <unistd.h>

ApplicationModel::ApplicationModel(QObject* parent) : QAbstractItemModel(parent)
{
    refresh_timer_.setInterval(2500);
    connect(&refresh_timer_, &QTimer::timeout, this, &ApplicationModel::refresh);
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
    if (role == StableIdRole) return item->id;
    if (role == NodeTypeRole) return static_cast<int>(item->type);
    if (role == LaunchCommandRole) return item->launch_command;
    if (role == RoutedRole) return item->routed;
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
        if (model_index.column() == NameColumn) return item->title;
        if (model_index.column() == ProcessIdColumn && item->type == NodeType::Process)
            return item->process.pid;
        if (model_index.column() == CommandColumn) return item->subtitle;
    }
    if (role == Qt::DecorationRole && model_index.column() == NameColumn && !item->icon.isNull())
        return item->icon;
    if (role == Qt::ToolTipRole)
        return item->type == NodeType::Process ? item->process.command_line : item->subtitle;
    if (role == Qt::FontRole && item->type != NodeType::Process) {
        QFont font;
        font.setBold(true);
        return font;
    }
    if (role == Qt::ForegroundRole && item->type == NodeType::Section)
        return QBrush(QApplication::palette().color(QPalette::Mid));
    return {};
}

QVariant ApplicationModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (orientation != Qt::Horizontal || role != Qt::DisplayRole) return {};
    switch (section) {
    case NameColumn: return tr("Application / process");
    case ProcessIdColumn: return tr("PID");
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

QString ApplicationModel::resolveLaunchCommand(const QString& text) const
{
    return launch_commands_.value(text, text);
}

void ApplicationModel::refresh()
{
    const QVector<ProcessInfo> processes = scanner_.scan(getuid());
    QByteArray snapshot;
    for (const ProcessInfo& process : processes) {
        snapshot += QByteArray::number(process.pid) + ':'
            + QByteArray::number(process.parent_pid) + ':'
            + process.cgroup.toUtf8() + ':' + process.name.toUtf8() + '\n';
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
    const auto order = [](const auto& left, const auto& right) {
        return left->title.localeAwareCompare(right->title) < 0;
    };
    std::sort(foreground->children.begin(), foreground->children.end(), order);
    std::sort(background->children.begin(), background->children.end(), order);

    beginResetModel();
    roots_.clear();
    if (!foreground->children.empty()) roots_.push_back(std::move(foreground));
    if (!background->children.empty()) roots_.push_back(std::move(background));
    endResetModel();
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
    const DesktopEntry* entry = catalog_.match(key, representative->executable, representative->name);
    if (entry) {
        application->title = entry->name;
        application->icon = entry->icon();
        application->launch_command = entry->launch_command;
        launch_commands_.insert(entry->name, entry->launch_command);
    } else {
        application->title = representative->name;
        application->launch_command = representative->executable;
        if (!representative->executable.isEmpty()) {
            static QFileIconProvider icons;
            application->icon = icons.icon(QFileInfo(representative->executable));
            launch_commands_.insert(application->title, representative->executable);
        }
    }
    application->subtitle = tr("%1 processes · %2%3")
                                .arg(processes.size())
                                .arg(foreground ? tr("desktop application") : key)
                                .arg(application->routed ? tr(" · routed") : QString{});
    buildProcessTree(*application, std::move(processes));
    return application;
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
