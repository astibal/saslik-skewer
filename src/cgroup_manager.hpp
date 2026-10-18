#pragma once

#include <QString>
#include <QVector>

#include <sys/types.h>

struct CgroupResult {
    bool ok{};
    QString detail;
    QString unit;
};

class CgroupManager {
public:
    [[nodiscard]] CgroupResult route(const QVector<pid_t>& pids,
                                     const QString& application_name) const;
    [[nodiscard]] CgroupResult release(const QVector<pid_t>& pids,
                                       const QString& application_name) const;

    [[nodiscard]] static QStringList routedLaunchPrefix(const QString& application_name);

private:
    [[nodiscard]] CgroupResult moveToScope(const QVector<pid_t>& pids,
                                           const QString& application_name,
                                           bool routed) const;
    [[nodiscard]] static QString safeName(QString value);
};
