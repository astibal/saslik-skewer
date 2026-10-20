#include "desktop_catalog.hpp"

#include <QDir>
#include <QFileInfo>
#include <QProcess>
#include <QRegularExpression>
#include <QSettings>
#include <QSet>
#include <QStandardPaths>

#include <algorithm>

namespace {
QString cleanExec(QString command)
{
    // Desktop-entry field codes are expanded by desktop launchers. Skewer does
    // not supply a file or URL here, therefore those placeholders are removed.
    command.remove(QRegularExpression(QStringLiteral("\\s+%[fFuUdDnNickvm]")));
    command.replace(QStringLiteral("%%"), QStringLiteral("%"));
    return command.trimmed();
}
}

QIcon DesktopEntry::icon() const
{
    QIcon value = QIcon::fromTheme(icon_name);
    if (value.isNull() && QFileInfo::exists(icon_name)) value = QIcon(icon_name);
    return value;
}

DesktopCatalog::DesktopCatalog() { reload(); }

void DesktopCatalog::reload()
{
    entries_.clear();
    QSet<QString> seen;
    QStringList roots = QStandardPaths::standardLocations(QStandardPaths::ApplicationsLocation);
    // A launcher started outside a desktop session may lack Snap's XDG path.
    roots << QStringLiteral("/var/lib/snapd/desktop/applications");
    roots.removeDuplicates();
    for (const QString& root : roots) {
        const auto files = QDir(root).entryInfoList({QStringLiteral("*.desktop")}, QDir::Files);
        for (const QFileInfo& file : files) {
            if (seen.contains(file.fileName())) continue;
            QSettings settings(file.absoluteFilePath(), QSettings::IniFormat);
            settings.beginGroup(QStringLiteral("Desktop Entry"));
            if (settings.value(QStringLiteral("Type")).toString() != QStringLiteral("Application")
                || settings.value(QStringLiteral("NoDisplay")).toBool()
                || settings.value(QStringLiteral("Hidden")).toBool()) continue;
            DesktopEntry entry;
            entry.id = file.completeBaseName();
            entry.name = settings.value(QStringLiteral("Name")).toString();
            entry.generic_name = settings.value(QStringLiteral("GenericName")).toString();
            entry.icon_name = settings.value(QStringLiteral("Icon")).toString();
            entry.launch_command = cleanExec(settings.value(QStringLiteral("Exec")).toString());
            entry.executable = executableFrom(entry.launch_command);
            entry.match_id = normalized(entry.id);
            entry.match_binary = normalized(QFileInfo(entry.executable).fileName());
            entry.keywords = settings.value(QStringLiteral("Keywords")).toStringList();
            entry.terminal = settings.value(QStringLiteral("Terminal")).toBool();
            if (entry.name.isEmpty() || entry.launch_command.isEmpty()) continue;
            seen.insert(file.fileName());
            entries_.push_back(std::move(entry));
        }
    }
    std::sort(entries_.begin(), entries_.end(), [](const auto& left, const auto& right) {
        return left.name.localeAwareCompare(right.name) < 0;
    });
}

const DesktopEntry* DesktopCatalog::match(const QString& cgroup, const QString& executable,
                                          const QString& process_name) const
{
    const QString group = normalized(cgroup.section(QLatin1Char('/'), -1));
    const QString binary = normalized(QFileInfo(executable).fileName());
    const QString process = normalized(process_name);
    const DesktopEntry* best = nullptr;
    int best_score = 0;
    for (const DesktopEntry& entry : entries_) {
        const QString& id = entry.match_id;
        const QString& entry_binary = entry.match_binary;
        int score = 0;
        if (!id.isEmpty() && group.contains(id)) score += 100;
        if (!entry_binary.isEmpty() && entry_binary == binary) score += 60;
        if (!entry_binary.isEmpty() && entry_binary == process) score += 45;
        if (!entry_binary.isEmpty() && group.contains(entry_binary)) score += 30;
        if (score > best_score) {
            best = &entry;
            best_score = score;
        }
    }
    return best_score >= 45 ? best : nullptr;
}

QString DesktopCatalog::normalized(QString value)
{
    // Compile these once rather than on every catalog comparison.
    static const QRegularExpression escaped(QStringLiteral("\\\\x[0-9a-fA-F]{2}"));
    static const QRegularExpression punctuation(QStringLiteral("[-_.@{}]"));
    static const QRegularExpression identifier(QStringLiteral("[0-9a-f]{8,}"));
    value = value.toLower();
    value.replace(escaped, QStringLiteral("-"));
    value.remove(punctuation);
    value.remove(identifier);
    return value;
}

QString DesktopCatalog::executableFrom(QString command)
{
    const QStringList words = QProcess::splitCommand(command);
    if (words.isEmpty()) return {};
    int index = 0;
    if (QFileInfo(words.first()).fileName() == QStringLiteral("env")) {
        ++index;
        while (index < words.size() && words.at(index).contains(QLatin1Char('='))) ++index;
    }
    return index < words.size() ? words.at(index) : QString{};
}
