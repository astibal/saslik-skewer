#include "tui.hpp"

#include <QElapsedTimer>
#include <QProcess>
#include <QSettings>

#include <ncurses.h>

#include <algorithm>
#include <clocale>

namespace {
QString clipped(QString value, int width)
{
    value.replace(QLatin1Char('\n'), QLatin1Char(' '));
    if (width <= 1) return {};
    if (value.size() >= width) return value.left(width - 1) + QChar(0x2026);
    return value;
}
}

int Tui::run()
{
    std::setlocale(LC_ALL, "");
    initscr();
    cbreak();
    noecho();
    keypad(stdscr, true);
    curs_set(0);
    timeout(200);
    if (has_colors()) {
        start_color();
        use_default_colors();
        init_pair(1, COLOR_CYAN, -1);
        init_pair(2, COLOR_GREEN, -1);
        init_pair(3, COLOR_YELLOW, -1);
        init_pair(4, COLOR_BLACK, COLOR_CYAN);
    }
    expanded_.insert(QStringLiteral("section:applications"));
    expanded_.insert(QStringLiteral("section:other"));
    rebuildRows();
    routing_next_hop_ = QSettings().value(QStringLiteral("routing/nextHop")).toString();
    routing_active_ = routing_.active(routing_next_hop_);
    QElapsedTimer refresh;
    refresh.start();
    bool running = true;
    while (running) {
        if (refresh.elapsed() >= 2500) {
            model_.refresh();
            rebuildRows();
            routing_active_ = routing_.active(routing_next_hop_);
            refresh.restart();
        }
        draw();
        switch (getch()) {
        case KEY_UP: case 'k': moveSelection(-1); break;
        case KEY_DOWN: case 'j': moveSelection(1); break;
        case KEY_RIGHT: case '\n': case ' ': toggleExpanded(); break;
        case 's': changeRouting(true); break;
        case 'd': changeRouting(false); break;
        case 'g': configureRouting(); break;
        case 'x': disableRouting(); break;
        case 'n': launch(); break;
        case 'r': model_.refresh(); rebuildRows(); refresh.restart(); break;
        case KEY_RESIZE: break;
        case 'q': case 27: running = false; break;
        default: break;
        }
    }
    endwin();
    return 0;
}

void Tui::rebuildRows()
{
    const QString selected_id = rows_.isEmpty() ? QString{}
        : rows_.at(std::clamp(selected_, 0, static_cast<int>(rows_.size()) - 1))
              .index.data(ApplicationModel::StableIdRole).toString();
    rows_.clear();
    const auto visit = [this](const auto& self, const QModelIndex& parent, int depth) -> void {
        for (int row = 0; row < model_.rowCount(parent); ++row) {
            const QModelIndex index = model_.index(row, 0, parent);
            rows_.push_back({index, depth});
            const QString id = index.data(ApplicationModel::StableIdRole).toString();
            if (expanded_.contains(id)) self(self, index, depth + 1);
        }
    };
    visit(visit, {}, 0);
    selected_ = 0;
    for (int row = 0; row < rows_.size(); ++row) {
        if (rows_.at(row).index.data(ApplicationModel::StableIdRole).toString() == selected_id) {
            selected_ = row;
            break;
        }
    }
}

void Tui::draw()
{
    erase();
    int height = 0, width = 0;
    getmaxyx(stdscr, height, width);
    attron(A_BOLD | COLOR_PAIR(1));
    mvaddnstr(0, 2, "SKEWER", width - 4);
    attroff(A_BOLD | COLOR_PAIR(1));
    const QString routing_state = routing_active_
        ? QStringLiteral("routing ACTIVE") : QStringLiteral("routing inactive");
    const QByteArray heading = QStringLiteral("Application selection for Saslik routing · %1")
        .arg(routing_state).toLocal8Bit();
    mvaddnstr(1, 2, heading.constData(), width - 4);
    mvhline(2, 0, ACS_HLINE, width);
    const int visible = std::max(0, height - 7);
    const int offset = std::clamp(selected_ - visible / 2, 0,
                                  std::max(0, static_cast<int>(rows_.size()) - visible));
    for (int line = 0; line < visible && offset + line < rows_.size(); ++line) {
        const int row = offset + line;
        const QModelIndex index = rows_.at(row).index;
        const auto type = static_cast<ApplicationModel::NodeType>(
            index.data(ApplicationModel::NodeTypeRole).toInt());
        const bool routed = index.data(ApplicationModel::RoutedRole).toBool();
        const bool has_children = model_.rowCount(index) > 0;
        QString prefix(rows_.at(row).depth * 2, QLatin1Char(' '));
        prefix += has_children
            ? (expanded_.contains(index.data(ApplicationModel::StableIdRole).toString())
                   ? QStringLiteral("▾ ") : QStringLiteral("▸ "))
            : QStringLiteral("  ");
        QString text = prefix + index.data().toString();
        if (type == ApplicationModel::NodeType::Application)
            text += routed ? QStringLiteral("  [ROUTED]") : QStringLiteral("  [direct]");
        if (row == selected_) attron(COLOR_PAIR(4));
        else if (routed) attron(COLOR_PAIR(2));
        else if (type == ApplicationModel::NodeType::Section) attron(A_BOLD | COLOR_PAIR(3));
        const QByteArray output = clipped(text, width - 4).toLocal8Bit();
        mvaddnstr(3 + line, 2, output.constData(), width - 4);
        clrtoeol();
        attrset(A_NORMAL);
    }
    mvhline(height - 4, 0, ACS_HLINE, width);
    const QByteArray status = clipped(status_, width - 4).toLocal8Bit();
    mvaddnstr(height - 3, 2, status.constData(), width - 4);
    mvaddnstr(height - 2, 2,
              "Enter expand  S attach  D release  G gateway  X routing off  N launch  R refresh  Q quit", width - 4);
    refresh();
}

void Tui::configureRouting()
{
    QSettings settings;
    QString next_hop = prompt(QStringLiteral("Next-hop IPv4"));
    if (next_hop.isEmpty()) next_hop = settings.value(QStringLiteral("routing/nextHop")).toString();
    if (next_hop.isEmpty()) {
        status_ = QStringLiteral("No next hop entered");
        return;
    }
    const RoutingResult result = routing_.activate(next_hop,
        RoutingController::Authorization::Terminal);
    status_ = result.detail;
    if (result.ok) {
        routing_next_hop_ = next_hop;
        settings.setValue(QStringLiteral("routing/nextHop"), next_hop);
        settings.setValue(QStringLiteral("routing/requested"), true);
    }
    routing_active_ = routing_.active(routing_next_hop_);
}

void Tui::disableRouting()
{
    status_ = routing_.deactivate(RoutingController::Authorization::Terminal).detail;
    QSettings().setValue(QStringLiteral("routing/requested"), false);
    routing_active_ = routing_.active(routing_next_hop_);
}

void Tui::moveSelection(int delta)
{
    if (!rows_.isEmpty())
        selected_ = std::clamp(selected_ + delta, 0, static_cast<int>(rows_.size()) - 1);
}

void Tui::toggleExpanded()
{
    if (rows_.isEmpty()) return;
    const QString id = rows_.at(selected_).index.data(ApplicationModel::StableIdRole).toString();
    if (expanded_.contains(id)) expanded_.remove(id); else expanded_.insert(id);
    rebuildRows();
}

void Tui::changeRouting(bool routed)
{
    if (rows_.isEmpty()) return;
    const QModelIndex index = rows_.at(selected_).index;
    const auto type = static_cast<ApplicationModel::NodeType>(
        index.data(ApplicationModel::NodeTypeRole).toInt());
    if (type != ApplicationModel::NodeType::Application) {
        status_ = QStringLiteral("Select an application, not an individual helper process");
        return;
    }
    const CgroupResult result = routed
        ? cgroups_.route(selectedPids(), index.data().toString())
        : cgroups_.release(selectedPids(), index.data().toString());
    status_ = result.detail;
    if (result.ok) { model_.refresh(); rebuildRows(); }
}

void Tui::launch()
{
    const QString entered = prompt(QStringLiteral("Run through Skewer"));
    if (entered.isEmpty()) return;
    const QString command = model_.resolveLaunchCommand(entered);
    QStringList words = QProcess::splitCommand(command);
    if (words.isEmpty()) return;
    QStringList invocation = CgroupManager::routedLaunchPrefix(words.first());
    invocation.append(words);
    const QString program = invocation.takeFirst();
    status_ = QProcess::startDetached(program, invocation)
        ? QStringLiteral("Application launched") : QStringLiteral("Launch failed");
}

QString Tui::prompt(const QString& label)
{
    int height = 0, width = 0;
    getmaxyx(stdscr, height, width);
    echo();
    curs_set(1);
    timeout(-1);
    move(height - 3, 2);
    clrtoeol();
    const QByteArray heading = (label + QStringLiteral(": ")).toLocal8Bit();
    addstr(heading.constData());
    QByteArray buffer(std::max(2, width - static_cast<int>(heading.size()) - 4), '\0');
    getnstr(buffer.data(), buffer.size() - 1);
    timeout(200);
    curs_set(0);
    noecho();
    return QString::fromLocal8Bit(buffer.constData()).trimmed();
}

QVector<pid_t> Tui::selectedPids() const
{
    QVector<pid_t> pids;
    if (rows_.isEmpty()) return pids;
    for (const QVariant& value : rows_.at(selected_).index
             .data(ApplicationModel::ProcessIdsRole).toList()) pids.push_back(value.toInt());
    return pids;
}
