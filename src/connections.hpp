#pragma once
#include <QSet>
#include <QString>
#include <QVector>
#include <QWidget>

struct Connection {
    QString protocol, state, local, remote, group, inode;
    QSet<int> pids;
    bool operator==(const Connection&) const = default;
};
struct ConnectionSnapshot {
    QVector<Connection> rows;
    bool complete = false;
    QString error;
    QSet<int> unreadable_pids;
    bool operator==(const ConnectionSnapshot&) const = default;
};
ConnectionSnapshot readConnections();
class ApplicationModel;
class ConnectionsPanel final : public QWidget {
public:
    explicit ConnectionsPanel(ApplicationModel* model, QWidget* parent = nullptr);
};
