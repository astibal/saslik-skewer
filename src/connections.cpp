#include "connections.hpp"
#include "application_model.hpp"
#include "routing_controller.hpp"
#include <QCheckBox>
#include <QSettings>
#include <QMessageBox>
#include <QPushButton>
#include <QComboBox>
#include <QDir>
#include <QFileInfo>
#include <QFutureWatcher>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QProcess>
#include <QScrollBar>
#include <QRegularExpression>
#include <QTableWidget>
#include <QTimer>
#include <QVBoxLayout>
#include <QtConcurrent>
#include <sys/stat.h>
#include <dirent.h>
#include <memory>
#include <unistd.h>

ConnectionSnapshot readConnections()
{
    ConnectionSnapshot result;
    QProcess ss;
    ss.start("ss", {"-H", "-O", "-n", "-t", "-u", "-e", "--cgroup"});
    if (!ss.waitForFinished(4000)) {
        ss.kill(); ss.waitForFinished(); result.error = "Socket query timed out"; return result;
    }
    const auto diagnostics = ss.readAllStandardError();
    if (ss.exitStatus() != QProcess::NormalExit || ss.exitCode() != 0) {
        result.error = "Socket diagnostics unavailable"; return result;
    }
    QHash<QString, QSet<int>> owners;
    bool complete = true;
    for (const auto& warning : diagnostics.split('\n')) {
        if (!warning.trimmed().isEmpty() && warning.trimmed() != "Failed to open cgroup2 by ID")
            complete = false;
    }
    // Join by socket inode, not by the process's current cgroup.
    for (const auto& name : QDir("/proc").entryList(QDir::Dirs | QDir::NoDotAndDotDot)) {
        bool ok; int pid = name.toInt(&ok); if (!ok) continue;
        const QByteArray path = ("/proc/" + name).toLocal8Bit();
        struct stat st{};
        if (::stat(path.constData(), &st) != 0 || st.st_uid != getuid()) continue;
        // QDir classifies every symlink target. For /proc/fd that adds costly
        // stat calls for files, pipes and sockets we only need to readlink.
        const auto close_directory = [](DIR* directory) { ::closedir(directory); };
        std::unique_ptr<DIR, decltype(close_directory)> fds(::opendir((path + "/fd").constData()), close_directory);
        if (!fds) {
            if (QFileInfo::exists(QString::fromLocal8Bit(path))) result.unreadable_pids.insert(pid);
            continue;
        }
        while (const auto* fd = ::readdir(fds.get())) {
            if (fd->d_name[0] == '.') continue;
            char target[256];
            const auto length = ::readlinkat(::dirfd(fds.get()), fd->d_name, target, sizeof(target));
            if (length <= 0) continue;
            const QString link = QString::fromLocal8Bit(target, length);
            if (link.startsWith("socket:[") && link.endsWith(']')) owners[link.mid(8, link.size()-9)].insert(pid);
        }
    }
    const QRegularExpression inode("(?:^|\\s)ino:(\\d+)");
    const QRegularExpression group("(?:^|\\s)cgroup:(\\S+)");
    for (const auto& line : QString::fromUtf8(ss.readAllStandardOutput()).split('\n', Qt::SkipEmptyParts)) {
        const auto fields = line.simplified().split(' ');
        if (fields.size() < 6) { complete = false; continue; }
        const QString number = inode.match(line).captured(1);
        if (!owners.contains(number)) continue;
        QString socket_group = group.match(line).captured(1);
        // Deleted cgroups may be printed as an unresolved ID. Do not call
        // those sockets routed or outside, and do not discard other sockets.
        if (!socket_group.startsWith('/')) socket_group.clear();
        result.rows.push_back({fields[0], fields[1], fields[4], fields[5], socket_group, number, owners[number]});
    }
    result.complete = complete;
    if (!complete || !result.unreadable_pids.isEmpty() || !diagnostics.isEmpty())
        result.error = "Partial snapshot: some socket cgroups or processes could not be inspected; known connections are shown";
    return result;
}

ConnectionsPanel::ConnectionsPanel(ApplicationModel* model, QWidget* parent) : QWidget(parent)
{
    auto* layout = new QVBoxLayout(this);
    auto* filter = new QLineEdit;
    auto* application = new QComboBox;
    layout->addWidget(application);
    auto* cleanup = new QPushButton(tr("Close old TCP connections…"));
    layout->addWidget(cleanup);
    auto* automatic = new QCheckBox(tr("Close old TCP connections after Attach"));
    automatic->setChecked(QSettings().value("connections/cleanupOnAttach",false).toBool());
    automatic->setToolTip(tr("Interrupts transfers. Applications may not reconnect. TCP only; existing sockets outside Skewer."));
    layout->addWidget(automatic);
    connect(automatic,&QCheckBox::toggled,this,[this,automatic](bool checked) {
        if (checked && QMessageBox::warning(this,tr("Automatic TCP cleanup"),
            tr("After Attach, close existing TCP connections outside Skewer. Transfers will be interrupted and reconnection is NOT guaranteed. Enable?"),
            QMessageBox::Yes|QMessageBox::No,QMessageBox::No) != QMessageBox::Yes) {
            QSignalBlocker blocker(automatic); automatic->setChecked(false); return;
        }
        QSettings().setValue("connections/cleanupOnAttach",checked);
    });
    connect(cleanup,&QPushButton::clicked,this,[this,application,cleanup] {
        if (application->currentIndex() == 0) { QMessageBox::information(this,tr("TCP cleanup"),tr("Select one attached application first.")); return; }
        QVector<pid_t> pids;
        for (const auto& pid : application->currentData().toList()) pids << pid.toInt();
        if (QMessageBox::warning(this,tr("Close old TCP connections"),
            tr("Close TCP connections outside Skewer for %1? Transfers will be interrupted. Reconnection is NOT guaranteed. UDP and listeners are untouched.").arg(application->currentText()),
            QMessageBox::Yes|QMessageBox::No,QMessageBox::No) != QMessageBox::Yes) return;
        cleanup->setEnabled(false);
        auto* job = new QFutureWatcher<RoutingResult>(this);
        connect(job,&QFutureWatcher<RoutingResult>::finished,this,[this,job,cleanup] {
            const auto result = job->result(); cleanup->setEnabled(true);
            QMessageBox::information(this,tr("TCP cleanup"),result.detail); job->deleteLater();
        });
        job->setFuture(QtConcurrent::run([pids] { return RoutingController().cleanupTcp(pids,RoutingController::Authorization::Desktop); }));
    });
    const auto refresh_applications = [model, application] {
        const auto selected = application->currentData(Qt::UserRole + 1).toString();
        QSignalBlocker blocker(application);
        application->clear(); application->addItem(tr("All my processes"));
        for (int section=0; section<model->rowCount(); ++section) {
            const auto parent = model->index(section,0);
            for (int row=0; row<model->rowCount(parent); ++row) {
                const auto item = model->index(row,0,parent);
                application->addItem(item.data().toString(), item.data(ApplicationModel::ProcessIdsRole));
                const int index = application->count()-1;
                const auto id = item.data(ApplicationModel::StableIdRole).toString();
                application->setItemData(index,id,Qt::UserRole+1);
                if (id == selected) application->setCurrentIndex(index);
            }
        }
    };
    refresh_applications();
    connect(model, &ApplicationModel::processesChanged, this, refresh_applications);
    filter->setPlaceholderText(tr("Filter PID, destination or cgroup…"));
    layout->addWidget(filter);
    auto* note = new QLabel(tr("Socket cgroup membership, not proof of traffic passing through Saslik. Current user, current network namespace."));
    note->setWordWrap(true); layout->addWidget(note);
    auto* table = new QTableWidget(0, 7);
    table->setHorizontalHeaderLabels({tr("PID"), tr("Protocol"), tr("Destination"), tr("State"), tr("Group"), tr("Local"), tr("Socket cgroup")});
    table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    table->horizontalHeader()->setStretchLastSection(false);
    const int widths[] = {100, 85, 230, 120, 120, 230, 450};
    for (int col = 0; col < 7; ++col) table->setColumnWidth(col, widths[col]);
    layout->addWidget(table);
    auto* watcher = new QFutureWatcher<ConnectionSnapshot>(this);
    auto* timer = new QTimer(this);
    const auto apply_filter = [table, filter, application] {
        for (int row = 0; row < table->rowCount(); ++row) {
            QString text;
            for (int col=0; col<table->columnCount(); ++col) text += table->item(row,col)->text() + ' ';
            bool matches = application->currentIndex() == 0;
            const auto pids = table->item(row,0)->text().split(',');
            for (const auto& pid : application->currentData().toList())
                if (pids.contains(pid.toString())) matches = true;
            table->setRowHidden(row, !matches || !text.contains(filter->text(), Qt::CaseInsensitive));
        }
    };
    connect(filter, &QLineEdit::textChanged, this, apply_filter);
    connect(application, &QComboBox::currentIndexChanged, this, apply_filter);
    connect(watcher, &QFutureWatcher<ConnectionSnapshot>::finished, this, [=, this] {
        const auto snapshot = watcher->result();
        model->setConnections(snapshot);
        // Badges need snapshots even when this tab is hidden, but thousands of
        // table items do not. Render the detail view only while it is visible.
        if (!isVisible()) return;
        note->setText(snapshot.error.isEmpty()
            ? tr("Socket membership only — not proof of interception. TCP and connected UDP; current user and network namespace.") : snapshot.error);
        const int scroll = table->verticalScrollBar()->value();
        QString selected;
        if (table->currentItem()) selected = table->item(table->currentRow(),0)->data(Qt::UserRole).toString();
        table->setRowCount(snapshot.rows.size());
        int row = 0;
        for (const auto& socket : snapshot.rows) {
            QStringList pids; for (int pid : socket.pids) pids << QString::number(pid);
            pids.sort();
            const bool routed = socket.group.split('/').contains("skewer-routed.slice");
            const QStringList cells{pids.join(","), socket.protocol, socket.remote, socket.state,
                socket.group.isEmpty() ? "?" : routed ? tr("● Skewer") : tr("● Outside"), socket.local, socket.group};
            for (int col=0; col<cells.size(); ++col) table->setItem(row,col,new QTableWidgetItem(cells[col]));
            table->item(row,0)->setData(Qt::UserRole, socket.inode);
            table->item(row,4)->setForeground(QColor(socket.group.isEmpty() ? "#999999" : routed ? "#48c988" : "#dda844"));
            if (socket.inode == selected) table->setCurrentCell(row,0);
            ++row;
        }
        apply_filter(); table->verticalScrollBar()->setValue(scroll);
    });
    connect(timer, &QTimer::timeout, this, [this, watcher] {
        if (window()->isVisible() && !watcher->isRunning())
            watcher->setFuture(QtConcurrent::run(readConnections));
    });
    timer->start(5000);
    watcher->setFuture(QtConcurrent::run(readConnections));
}
