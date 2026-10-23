#pragma once

#include <QString>
#include <QStringList>
#include <QVector>
#include <sys/types.h>

struct RoutingResult {
    bool ok{};
    QString detail;
};

class RoutingController {
public:
    enum class Authorization { Desktop, Terminal };
    [[nodiscard]] RoutingResult interfaceChange(const QString& name, int index, const QString& gateway,
                                                bool attach, Authorization authorization) const;
    [[nodiscard]] RoutingResult cleanupTcp(const QVector<pid_t>& pids, Authorization authorization, bool preview = false) const;

    [[nodiscard]] RoutingResult activate(const QString& next_hop,
                                         Authorization authorization) const;
    [[nodiscard]] RoutingResult deactivate(Authorization authorization) const;
    [[nodiscard]] RoutingResult resume(Authorization authorization) const;
    [[nodiscard]] RoutingResult updateExemptions(const QStringList& destinations, Authorization authorization) const;
    [[nodiscard]] bool active(const QString& next_hop) const;
    [[nodiscard]] bool nextHopReachable(const QString& next_hop) const;
    [[nodiscard]] QString directInterface(const QString& next_hop) const;

private:
    [[nodiscard]] static QString helperPath();
    [[nodiscard]] static RoutingResult invoke(const QStringList& helper_arguments,
                                              Authorization authorization);
};
