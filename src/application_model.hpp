#pragma once

#include "desktop_catalog.hpp"
#include "process_scanner.hpp"

#include <QAbstractItemModel>
#include <QTimer>

#include <memory>
#include <vector>

class ApplicationModel final : public QAbstractItemModel {
    Q_OBJECT

public:
    enum Column { NameColumn, ProcessIdColumn, CommandColumn, ColumnCount };
    enum Role {
        StableIdRole = Qt::UserRole + 1,
        NodeTypeRole,
        LaunchCommandRole,
        ProcessIdsRole,
        RoutedRole
    };
    enum class NodeType { Section, Application, Process };

    explicit ApplicationModel(QObject* parent = nullptr);
    [[nodiscard]] QModelIndex index(int row, int column,
                                    const QModelIndex& parent = {}) const override;
    [[nodiscard]] QModelIndex parent(const QModelIndex& child) const override;
    [[nodiscard]] int rowCount(const QModelIndex& parent = {}) const override;
    [[nodiscard]] int columnCount(const QModelIndex& parent = {}) const override;
    [[nodiscard]] QVariant data(const QModelIndex& index,
                                int role = Qt::DisplayRole) const override;
    [[nodiscard]] QVariant headerData(int section, Qt::Orientation orientation,
                                      int role) const override;
    [[nodiscard]] QStringList launcherSuggestions() const;
    [[nodiscard]] QString resolveLaunchCommand(const QString& text) const;

signals:
    void launcherSuggestionsChanged(const QStringList& suggestions);

public slots:
    void refresh();

private:
    struct Node {
        NodeType type{NodeType::Process};
        QString id;
        QString title;
        QString subtitle;
        QString launch_command;
        QIcon icon;
        bool routed{};
        ProcessInfo process;
        Node* parent{};
        std::vector<std::unique_ptr<Node>> children;
    };

    [[nodiscard]] Node* node(const QModelIndex& index) const;
    [[nodiscard]] std::unique_ptr<Node> buildApplication(const QString& key,
                                                         QVector<ProcessInfo> processes,
                                                         bool foreground);
    static void buildProcessTree(Node& application, QVector<ProcessInfo> processes);
    [[nodiscard]] static QString applicationKey(
        const ProcessInfo& process, const QHash<pid_t, const ProcessInfo*>& processes);
    [[nodiscard]] static bool foregroundGroup(const QString& key);

    ProcessScanner scanner_;
    DesktopCatalog catalog_;
    std::vector<std::unique_ptr<Node>> roots_;
    QHash<QString, QString> launch_commands_;
    QTimer refresh_timer_;
};
