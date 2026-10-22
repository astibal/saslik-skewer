#pragma once

#include <QString>
#include <QStringList>
#include <QVector>

#include <sys/types.h>

struct RoutingCommand {
    QString program;
    QStringList arguments;
    bool allow_failure{};
};

struct RoutingPlan {
    bool valid{};
    QString error;
    QString nft_table;
    QString nft_rules;
    QVector<RoutingCommand> prepare;
    QVector<RoutingCommand> cleanup;
};

class RoutingPlanner {
public:
    static QString guardRules(uid_t uid, int level, const QString& gateway = {},
                              const QString& interface = {}, const QStringList& exemptions = {},
                              const QString& local_control = {}, quint16 local_control_port = 0);
    [[nodiscard]] static RoutingPlan create(uid_t uid, const QString& next_hop,
                                            const QString& interface_name,
                                            int cgroup_level = 5,
                                            const QStringList& exemptions = {},
                                            const QString& local_control = {},
                                            quint16 local_control_port = 0);
    static bool normalizeExemptions(const QStringList& input, QStringList& output, QString& error);
    static QString exemptionUpdate(uid_t uid, const QStringList& normalized);
    [[nodiscard]] static QString tableName(uid_t uid);
    [[nodiscard]] static quint32 mark(uid_t uid);
    [[nodiscard]] static quint32 routeTable(uid_t uid);
    [[nodiscard]] static quint32 rulePriority(uid_t uid);
};
