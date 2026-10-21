#pragma once

#include <QIcon>
#include <QString>
#include <QVector>

struct DesktopEntry {
    QString id;
    QString source;
    QString name;
    QString generic_name;
    QString icon_name;
    QString executable;
    QString launch_command;
    QStringList keywords;
    QString match_id;
    QString match_binary;
    bool terminal{};

    [[nodiscard]] QIcon icon() const;
};

class DesktopCatalog {
public:
    DesktopCatalog();

    void reload();
    [[nodiscard]] const QVector<DesktopEntry>& entries() const { return entries_; }
    [[nodiscard]] const DesktopEntry* match(const QString& cgroup,
                                            const QString& executable,
                                            const QString& process_name) const;

private:
    [[nodiscard]] static QString normalized(QString value);
    [[nodiscard]] static QString executableFrom(QString command);

    QVector<DesktopEntry> entries_;
};
