#include "launcher.hpp"
#include "cgroup_manager.hpp"
#include <QApplication>
#include <QCheckBox>
#include <QDir>
#include <QFile>
#include <QFileDialog>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QProcess>
#include <QPushButton>
#include <QSaveFile>
#include <QSignalBlocker>
#include <QStandardPaths>
#include <QVBoxLayout>
#include <QTimer>
#include <QTemporaryFile>
#include <QElapsedTimer>
#include <memory>

namespace {
const QByteArray marker = "# Managed by Skewer Launcher\n";
QString quote(QString value)
{
    value.replace('\\', "\\\\");
    value.replace('"', "\\\"");
    value.replace('`', "\\`");
    value.replace('$', "\\$");
    value.replace('%', "%%");
    return '"' + value + '"';
}
}

QString Launcher::menuPath()
{
    return QStandardPaths::writableLocation(QStandardPaths::GenericDataLocation)
        + "/applications/org.saslik.Skewer.Launcher.desktop";
}

bool Launcher::menuInstalled()
{
    QFile file(menuPath());
    return file.open(QIODevice::ReadOnly) && file.read(marker.size()) == marker;
}

bool Launcher::setMenuInstalled(bool enabled, QString& error)
{
    // Never overwrite or delete a desktop entry owned by someone else.
    if (QFile::exists(menuPath()) && !menuInstalled()) {
        error = tr("A different file already occupies the launcher menu path."); return false;
    }
    if (!enabled) {
        if (!QFile::exists(menuPath()) || QFile::remove(menuPath())) return true;
        error = tr("Could not remove the launcher entry."); return false;
    }
    const QString executable = QApplication::applicationFilePath();
    if (executable.contains('\n') || executable.contains('\r')) {
        error = tr("Unsupported executable path."); return false;
    }
    QDir().mkpath(QFileInfo(menuPath()).absolutePath());
    QSaveFile file(menuPath());
    const QByteArray content = marker + "[Desktop Entry]\nType=Application\nName=Skewer Launcher\n"
        "Comment=Launch applications through Skewer\nIcon=org.saslik.Skewer\nTerminal=false\nCategories=Network;\nExec="
        + quote(executable).toUtf8() + " --launcher\n";
    if (file.open(QIODevice::WriteOnly) && file.write(content) == content.size() && file.commit()) return true;
    error = file.errorString(); return false;
}

Launcher::Launcher(QWidget* parent) : QWidget(parent)
{
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    auto* row = new QHBoxLayout;
    auto* input = new QLineEdit;
    input->setPlaceholderText(tr("Enter a command or executable path…"));
    input->setObjectName("launcherSearch");
    auto* browse = new QPushButton(tr("Browse…"));
    auto* run = new QPushButton(tr("Run"));
    run->setToolTip(tr("Launch in Skewer. Some applications reuse an existing instance; check its routing in the application list."));
    row->addWidget(input, 1); row->addWidget(browse); row->addWidget(run);
    layout->addLayout(row);
    auto* status = new QLabel;
    status->setObjectName("launcherStatus");
    status->setWordWrap(true);
    status->hide();
    layout->addWidget(status);
    auto* status_timeout = new QTimer(this);
    status_timeout->setObjectName("launcherStatusTimeout");
    status_timeout->setSingleShot(true);
    status_timeout->setInterval(5000);
    connect(status_timeout, &QTimer::timeout, status, [status] {
        status->clear();
        status->hide();
    });
    auto* menu = new QCheckBox(tr("Show Skewer Launcher in the applications menu"));
    menu->setChecked(menuInstalled());
    layout->addWidget(menu);
    connect(menu, &QCheckBox::toggled, this, [this, menu](bool enabled) {
        QString error;
        if (!setMenuInstalled(enabled, error)) QMessageBox::warning(this, tr("Skewer Launcher"), error);
        QSignalBlocker blocker(menu); menu->setChecked(menuInstalled());
    });
    connect(browse, &QPushButton::clicked, this, [this, input] {
        const auto path = QFileDialog::getOpenFileName(this, tr("Choose an application"));
        if (!path.isEmpty()) input->setText('"' + path + '"');
    });
    const auto launch = [this, input, run, status, status_timeout] {
        if (!run->isEnabled()) return;
        const QString command = input->text().trimmed();
        auto words = QProcess::splitCommand(command);
        if (words.isEmpty()) return;
        status_timeout->stop();
        status->show();
        const QString executable = QStandardPaths::findExecutable(words.first());
        if (executable.isEmpty()) {
            status->setText(tr("Command not found or not executable: %1").arg(words.first()));
            return;
        }
        words[0] = executable;
        auto invocation = CgroupManager::routedLaunchPrefix(words.first());
        invocation.append(words);
        QString unit;
        for (const auto& argument : invocation)
            if (argument.startsWith("--unit=")) unit = argument.mid(7) + ".scope";
        const QString program = invocation.takeFirst();
        const QString name = QFileInfo(executable).fileName();
        status->setText(tr("Starting %1 — checking attachment…").arg(name));
        auto errors = std::make_shared<QTemporaryFile>();
        if (!errors->open()) { status->setText(tr("Cannot create launch diagnostics.")); return; }
        QProcess launcher;
        launcher.setProgram(program);
        launcher.setArguments(invocation);
        launcher.setStandardOutputFile(QProcess::nullDevice());
        launcher.setStandardErrorFile(errors->fileName());
        // Closing either launcher window must not terminate the launched scope.
        if (!launcher.startDetached()) {
            status->setText(tr("Could not launch %1: %2").arg(name, launcher.errorString()));
            return;
        }
        run->setEnabled(false);
        auto* poll = new QTimer(this);
        auto* query = new QProcess(poll);
        auto elapsed = std::make_shared<QElapsedTimer>();
        elapsed->start();
        const auto finish = [poll, run, status, status_timeout, input, command](const QString& message, bool attached) {
            poll->stop();
            run->setEnabled(true);
            status->setText(message);
            if (attached) {
                if (input->text().trimmed() == command) input->clear();
                status_timeout->start();
            }
            poll->deleteLater();
        };
        connect(query, &QProcess::finished, this, [=](int, QProcess::ExitStatus) {
            const QString group = QString::fromUtf8(query->readAllStandardOutput()).trimmed();
            if (group.startsWith('/') && !group.contains("..") && group.endsWith('/' + unit)) {
                QFile processes("/sys/fs/cgroup" + group + "/cgroup.procs");
                if (processes.open(QIODevice::ReadOnly)) {
                    for (const auto& pid : processes.readAll().split('\n')) {
                        bool valid = false; pid.toInt(&valid); if (!valid) continue;
                        QFile cmd("/proc/" + pid + "/cmdline");
                        if (!cmd.open(QIODevice::ReadOnly)) continue;
                        const auto args = cmd.readAll().split('\0');
                        const QString actual = QFileInfo("/proc/" + pid + "/exe").symLinkTarget();
                        // Do not mistake systemd-run or skewer-session's argv
                        // (which includes the target) for the target itself.
                        if (actual == QFileInfo(executable).canonicalFilePath()
                            || (!args.isEmpty() && QString::fromLocal8Bit(args[0]) == executable)) {
                            finish(tr("%1 started · attached to Skewer").arg(name), true);
                            return;
                        }
                    }
                }
            }
            if (elapsed->elapsed() >= 10000) {
                errors->seek(0);
                const QString detail = QString::fromLocal8Bit(errors->read(4096)).trimmed();
                finish(detail.isEmpty()
                    ? tr("%1: no attached process found. It may have exited or opened in an existing instance. Check the application list.").arg(name)
                    : tr("%1 could not be verified: %2").arg(name, detail), false);
            }
        });
        connect(poll, &QTimer::timeout, this, [=] {
            if (query->state() != QProcess::NotRunning) {
                if (elapsed->elapsed() >= 10000) query->kill();
                return;
            }
            query->start("systemctl", {"--user", "show", unit, "--property=ControlGroup", "--value"});
        });
        connect(query, &QProcess::errorOccurred, this, [=](QProcess::ProcessError error) {
            if (error == QProcess::FailedToStart)
                finish(tr("Cannot verify launch: %1").arg(query->errorString()), false);
        });
        poll->start(300);
    };
    connect(run, &QPushButton::clicked, this, launch);
    connect(input, &QLineEdit::returnPressed, this, launch);
}
