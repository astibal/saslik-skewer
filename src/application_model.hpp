#pragma once

#include "desktop_catalog.hpp"
#include "process_scanner.hpp"
#include "connections.hpp"

#include <QAbstractItemModel>
#include <QByteArray>
#include <QTimer>
#include <QMap>

#include <memory>
#include <vector>

class ApplicationModel final : public QAbstractItemModel {
    Q_OBJECT

public:
    enum Column { NameColumn, ProcessIdColumn, RoutingColumn, CaColumn, ConnectionsColumn, CommandColumn, ColumnCount };
    enum Role {
        StableIdRole = Qt::UserRole + 1,
        NodeTypeRole,
        LaunchCommandRole,
        ProcessIdsRole,
        RoutedRole,
        PartiallyRoutedRole,
        InterfaceNameRole, InterfaceIndexRole
    };
    enum class NodeType { Section, Application, Process, Interface };

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
    bool hasAttachedProcesses() const;
    void setRoutingState(bool active, bool protected_slice);
    [[nodiscard]] QString resolveLaunchCommand(const QString& text) const;
    [[nodiscard]] static QString applicationKey(
        const ProcessInfo& process, const QHash<pid_t, const ProcessInfo*>& processes);

signals:
    void processesChanged();
    void launcherSuggestionsChanged(const QStringList& suggestions);

public slots:
    void setConnections(const ConnectionSnapshot& snapshot);
    void refresh();
    void setProcesses(const QVector<ProcessInfo>& processes);
    void setCaStatus(const QHash<QString, QString>& statuses, const QString& fingerprint);

private:
    struct Node {
        NodeType type{NodeType::Process};
        QString id;
        QString title;
        QString subtitle;
        QString launch_command;
        QIcon icon;
        bool routed{};
        bool partially_routed{};
        QString identity;
        int process_count{};
        bool application_reference{};
        // Computed once per socket snapshot, never once per paint role.
        bool connections_cached{};
        int sockets_total{};
        int sockets_outside{};
        int sockets_inside{};
        bool sockets_unknown{};
        ProcessInfo process;
        Node* parent{};
        std::vector<std::unique_ptr<Node>> children;
    };

    [[nodiscard]] Node* node(const QModelIndex& index) const;
    [[nodiscard]] std::unique_ptr<Node> buildApplication(const QString& key,
                                                         QVector<ProcessInfo> processes,
                                                         bool foreground);
    static void buildProcessTree(Node& application, QVector<ProcessInfo> processes);
    static void groupInstances(Node& section);
    [[nodiscard]] static bool foregroundGroup(const QString& key);

    ProcessScanner scanner_;
    DesktopCatalog catalog_;
    std::vector<std::unique_ptr<Node>> roots_;
    QHash<QString, QString> launch_commands_;
    QHash<QString, const DesktopEntry*> desktop_matches_;
    QHash<QString, const DesktopEntry*> exact_desktop_matches_;
    QHash<QString, QIcon> application_icons_;
    QByteArray snapshot_;
    quint64 process_revision_{};
    QTimer refresh_timer_;
    QTimer vm_timer_;
    QMap<QString, QString> discovered_vms_;
    QHash<QString, QString> ca_statuses_;
    QString ca_fingerprint_;
    ConnectionSnapshot connections_;
    bool routing_active_{};
    bool routing_protected_{};
};
