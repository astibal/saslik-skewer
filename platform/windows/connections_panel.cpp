#include <winsock2.h>
#include <ws2tcpip.h>
#include "connections_panel.hpp"
#include "tcp_owners.hpp"
#include "process_browser.hpp"
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QScrollBar>
#include <QTableWidget>
#include <QVBoxLayout>
#include <QtConcurrent>

namespace skewer::windows {
namespace {
QString address(const skewer::traffic::PacketTuple& tuple, bool source) {
    const auto& bytes = source ? tuple.source : tuple.destination;
    char text[INET6_ADDRSTRLEN]{};
    if (!InetNtopA(tuple.ipv6 ? AF_INET6 : AF_INET, bytes.data(), text, sizeof(text))) {
        return QStringLiteral("?");
    }
    const auto port = source ? tuple.source_port : tuple.destination_port;
    return tuple.ipv6 ? QStringLiteral("[%1]:%2").arg(text).arg(port)
                      : QStringLiteral("%1:%2").arg(text).arg(port);
}

QString stateName(std::uint32_t state) {
    static const QStringList names{QStringLiteral("?"), QStringLiteral("CLOSED"),
                                   QStringLiteral("LISTEN"), QStringLiteral("SYN-SENT"),
                                   QStringLiteral("SYN-RECEIVED"), QStringLiteral("ESTABLISHED"),
                                   QStringLiteral("FIN-WAIT-1"), QStringLiteral("FIN-WAIT-2"),
                                   QStringLiteral("CLOSE-WAIT"), QStringLiteral("CLOSING"),
                                   QStringLiteral("LAST-ACK"), QStringLiteral("TIME-WAIT"),
                                   QStringLiteral("DELETE-TCB")};
    return names.value(static_cast<int>(state), QString::number(state));
}
} // namespace

ConnectionsPanel::ConnectionsPanel(skewer::ui::ProcessBrowser* processes, QWidget* parent)
    : QWidget(parent), processes_(processes) {
    auto* layout = new QVBoxLayout(this);
    filter_ = new QLineEdit(this);
    filter_->setPlaceholderText(tr("Filter application, PID, address or state…"));
    status_ = new QLabel(tr("Reading the Windows TCP owner table…"), this);
    status_->setWordWrap(true);
    table_ = new QTableWidget(0, 7, this);
    table_->setObjectName("connectionsTable");
    table_->setHorizontalHeaderLabels({tr("Application"), tr("PID"), tr("State"), tr("Local"),
                                       tr("Remote"), tr("IP"), tr("Expected route")});
    table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->setAlternatingRowColors(true);
    table_->setSortingEnabled(true);
    table_->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    table_->horizontalHeader()->setStretchLastSection(true);
    const int widths[] = {190, 80, 110, 210, 210, 55};
    for (int column = 0; column < 6; ++column) table_->setColumnWidth(column, widths[column]);
    layout->addWidget(filter_);
    layout->addWidget(status_);
    layout->addWidget(table_);
    connect(filter_, &QLineEdit::textChanged, this, [this](const QString& text) {
        for (int row = 0; row < table_->rowCount(); ++row) {
            QString joined;
            for (int column = 0; column < table_->columnCount(); ++column)
                joined += table_->item(row, column)->text() + QLatin1Char(' ');
            table_->setRowHidden(row, !joined.contains(text, Qt::CaseInsensitive));
        }
    });
    connect(&watcher_, &QFutureWatcher<traffic::TcpOwnerSnapshot>::finished, this,
            [this] { render(watcher_.result()); });
    connect(&timer_, &QTimer::timeout, this, &ConnectionsPanel::refresh);
    timer_.start(3000);
    refresh();
}

ConnectionsPanel::~ConnectionsPanel() {
    timer_.stop();
    watcher_.waitForFinished();
}

void ConnectionsPanel::setRoutingState(bool known, const RoutingReply& state) {
    routing_known_ = known;
    routing_ = state;
    if (!watcher_.isRunning()) refresh();
}

void ConnectionsPanel::refresh() {
    if (watcher_.isRunning()) return;
    watcher_.setFuture(QtConcurrent::run([] {
        try {
            return traffic::captureTcpOwners();
        } catch (const std::exception& error) {
            traffic::TcpOwnerSnapshot result;
            result.error = error.what();
            return result;
        }
    }));
}

void ConnectionsPanel::render(const traffic::TcpOwnerSnapshot& snapshot) {
    if (!snapshot.error.empty()) {
        status_->setText(tr("TCP connection inventory unavailable: %1")
                             .arg(QString::fromUtf8(snapshot.error)));
        return;
    }
    QHash<quint64, skewer::ui::ProcessRecord> owners;
    for (const auto& process : processes_->processes()) owners.insert(process.pid, process);
    const auto scroll = table_->verticalScrollBar()->value();
    table_->setSortingEnabled(false);
    // IP Helper exposes machine-wide ownership. Keep this unprivileged view
    // scoped to the same current-user process inventory as the Applications tab.
    table_->setRowCount(0);
    int row_index{};
    for (const auto& row : snapshot.rows) {
        if (!owners.contains(row.pid)) continue;
        const auto owner = owners.value(row.pid);
        QString route = tr("Outside Skewer");
        if (!routing_known_) {
            route = tr("Unknown");
        } else if (routing_.scope == RoutingScope::WholeHost && routing_.phase == RoutingPhase::Active) {
            route = tr("Skewer (whole host)");
        } else if (routing_.scope == RoutingScope::SelectedProcess && routing_.selected &&
                   routing_.phase == RoutingPhase::Active && routing_.selected->pid == row.pid &&
                   owner.created == routing_.selected->created) {
            route = tr("Skewer (selected)");
        }
        const QStringList cells{owner.name.isEmpty() ? tr("Unknown process") : owner.name,
                                QString::number(row.pid), stateName(row.state), address(row.tuple, true),
                                address(row.tuple, false), row.tuple.ipv6 ? QStringLiteral("IPv6")
                                                                         : QStringLiteral("IPv4"),
                                route};
        table_->insertRow(row_index);
        for (int column = 0; column < cells.size(); ++column)
            table_->setItem(row_index, column, new QTableWidgetItem(cells[column]));
        ++row_index;
    }
    table_->setSortingEnabled(true);
    table_->verticalScrollBar()->setValue(scroll);
    status_->setText(tr("%1 TCP sockets from the Windows owner table. Route is policy state, not "
                        "packet-level proof; UDP is not shown.")
                         .arg(row_index));
    emit filter_->textChanged(filter_->text());
}
} // namespace skewer::windows
