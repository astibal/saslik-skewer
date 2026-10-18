#pragma once

#include <QString>

struct RoutingResult {
    bool ok{};
    QString detail;
};

class RoutingController {
public:
    enum class Authorization { Desktop, Terminal };

    [[nodiscard]] RoutingResult activate(const QString& next_hop,
                                         Authorization authorization) const;
    [[nodiscard]] RoutingResult deactivate(Authorization authorization) const;
    [[nodiscard]] bool active() const;

private:
    [[nodiscard]] static QString helperPath();
    [[nodiscard]] static RoutingResult invoke(const QStringList& helper_arguments,
                                              Authorization authorization);
};
