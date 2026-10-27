#include "tui.hpp"
#include "routing_guard.hpp"
#include "interface_routing.hpp"
#include "ca_store.hpp"
#include "runtime_trust_service.hpp"
#include "routing_plan.hpp"
#include <QStandardPaths>
#include <QtConcurrent>
#include <QFile>

#include <QElapsedTimer>
#include <QProcess>
#include <QSettings>
#include <QThread>

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
    model_.applyPreferences();
    rebuildRows();
    routing_next_hop_ = QSettings().value(QStringLiteral("routing/nextHop")).toString();
    routing_active_ = routing_.active(routing_next_hop_);
    restoreRoutingIntent();
    startSession([] {
        def_prog_mode(); endwin();
        const auto reply = TuiTunnel::authorize();
        reset_prog_mode(); refresh();
        return reply;
    }, [this] { enableRouting(); });
    QElapsedTimer refresh;
    refresh.start();
    bool running = true;
    while (running) {
        pollTunnel();
        if (refresh.elapsed() >= Preferences::number("refresh/processSeconds", 5, 2, 60) * 1000) {
            model_.refresh();
            rebuildRows();
            routing_active_ = routing_.active(routing_next_hop_)
                && (!tunnel_pinned_ || (tunnel_.view.state == "verified" && tunnel_.view.fresh));
            refresh.restart();
        }
        draw();
        switch (getch()) {
        case KEY_UP: case 'k': moveSelection(-1); break;
        case KEY_DOWN: case 'j': moveSelection(1); break;
        case KEY_RIGHT: case '\n': case ' ': toggleExpanded(); break;
        case 'a': case 'A': changeRouting(true); break;
        case 'd': case 'D': changeRouting(false); break;
        case 'g': case 'G': configureRouting(); break;
        case 'x': case 'X': disableRouting(); break;
        case 'e': case 'E': enableRouting(); break;
        case 's': case 'S': configureSaslik(); break;
        case 't': case 'T': configureTransport(); break;
        case 'h': case 'H': configureScope(); break;
        case 'i': case 'I': showTunnelDetails(); break;
        case 'c': case 'C': caTrust(); break;
        case 'v': case 'V': connections(); break;
        case 'o': case 'O': preferences(); break;
        case 'p': case 'P': pairSaslik(); break;
        case 'u': case 'U': runtimeTrust(); break;
        case 'z': case 'Z': {
            if (requested_) disableRouting();
            if (requested_) break;
            QSettings().setValue("saslik/disconnected", true);
            certificate_.clear(); tunnel_.view.connected = false;
            if (prompt("Disconnected. Review and remove retained CA from stores? Type YES") == "YES") caTrust();
            break;
        }
        case 'n': case 'N': launch(); break;
        case '!': shell(); break;
        case 'r': model_.refresh(); rebuildRows(); refresh.restart(); break;
        case KEY_RESIZE: break;
        case 'q': case 27: running = false; break;
        default: break;
        }
    }
    tunnel_.stop();
    endwin();
    return 0;
}

void Tui::rebuildRows()
{
    const QString selected_id = rows_.isEmpty() ? QString{}
        : rows_.at(std::clamp(selected_, 0, static_cast<int>(rows_.size()) - 1))
              .stable_id;
    rows_.clear();
    const auto visit = [this](const auto& self, const QModelIndex& parent, int depth) -> void {
        for (int row = 0; row < model_.rowCount(parent); ++row) {
            const QModelIndex index = model_.index(row, 0, parent);
            const QString id = index.data(ApplicationModel::StableIdRole).toString();
            // Model resets invalidate indexes; preserve selection by value,
            // never by dereferencing a node from the previous snapshot.
            rows_.push_back({QPersistentModelIndex(index), depth, id});
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

QString Tui::routingSummary() const
{
    QString message = routing_issue_;
    if (message.isEmpty()) message = Tuntom::compactStatus(tunnel_.view,
        !QFileInfo(Preferences::tuntomBinary()).isExecutable());
    if (QSettings().value("routing/scope", "applications") == "host") message.prepend("Whole host (IPv4; IPv6 blocked) · ");
    if (requested_ && retry_.isValid())
        message += QString(" · retry in %1 s (E now)").arg(std::max<qint64>(0, (60000 - retry_.elapsed() + 999) / 1000));
    return message;
}

void Tui::draw()
{
    const bool protected_slice = RoutingGuard::installed(getuid());
    model_.setRoutingState(routing_active_, protected_slice);
    erase();
    int height = 0, width = 0;
    getmaxyx(stdscr, height, width);
    attron(A_BOLD | COLOR_PAIR(1));
    mvaddnstr(0, 2, "SKEWER", width - 4);
    attroff(A_BOLD | COLOR_PAIR(1));
    const bool alarm = !routing_active_ && model_.hasAttachedProcesses();
    const QString routing_state = routing_active_ ? QStringLiteral("Routing active")
        : alarm ? (protected_slice ? QStringLiteral("Traffic blocked") : QStringLiteral("WARNING: traffic not protected"))
                : QStringLiteral("Routing inactive");
    const QByteArray heading = QStringLiteral("%1 · %2")
        .arg(routing_state, routingSummary()).toLocal8Bit();
    if (alarm) attron(A_BOLD | COLOR_PAIR(3));
    mvaddnstr(1, 2, heading.constData(), width - 4);
    if (alarm) attroff(A_BOLD | COLOR_PAIR(3));
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
            text += index.data(ApplicationModel::PartiallyRoutedRole).toBool()
                ? QStringLiteral("  [PARTIAL]")
                : routed ? QStringLiteral("  [ATTACHED]") : QStringLiteral("  [not attached]");
        const auto sockets = index.siblingAtColumn(ApplicationModel::ConnectionsColumn).data().toString();
        if (!sockets.isEmpty()) text += "  " + sockets;
        if (row == selected_) attron(COLOR_PAIR(4));
        else if (routed) attron(COLOR_PAIR(routing_active_ ? 2 : 3));
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
              "A attach D release E on X off S Saslik T transport I details G gateway N launch ! shell Q quit", width - 4);
    mvaddnstr(height - 1, 2, "H scope  C CA Trust  U Runtime Trust  V Connections  O Settings  P Pair  Z disconnect", width - 4);
    refresh();
}

void Tui::configureRouting()
{
    if (requested_) { status_ = "Disable routing before changing destination"; return; }
    QSettings settings;
    QString next_hop = prompt(QStringLiteral("Next-hop IPv4"));
    if (next_hop.isEmpty()) next_hop = settings.value(QStringLiteral("routing/nextHop")).toString();
    if (next_hop.isEmpty()) {
        status_ = QStringLiteral("No next hop entered");
        return;
    }
    def_prog_mode(); endwin();
    const RoutingResult result = routing_.activate(next_hop,
        RoutingController::Authorization::Terminal);
    reset_prog_mode(); refresh();
    status_ = result.detail;
    if (result.ok) {
        requested_ = true;
        routing_next_hop_ = next_hop;
        tunnel_.view.mode = "direct";
        tunnel_.view.requested = true;
        routing_issue_.clear();
        settings.setValue(QStringLiteral("routing/nextHop"), next_hop);
        settings.setValue(QStringLiteral("routing/requested"), true);
        settings.setValue("routing/mode", "gateway");
        settings.setValue("routing/lastTransport", "direct");
    }
    routing_active_ = routing_.active(routing_next_hop_);
}

void Tui::startSession(const std::function<PrivilegedSession::Reply()>& authorize,
                       const std::function<void()>& resume)
{
    // Like the GUI, authorize once per frontend lifetime, independently of
    // saved routing intent and server availability. Polling must not retry it.
    const auto reply = authorize();
    if (!reply.ok) {
        routing_issue_ = "Helper not authorized · E retries, I details";
        status_ = "Helper authorization canceled or unavailable; E retries: " + reply.detail;
        tunnel_.error = status_;
        tunnel_.view.state = "authorization-required";
        return;
    }
    status_ = "Helper ready";
    routing_issue_.clear();
    const QSettings settings;
    if (requested_ && settings.value("routing/resumeOnStartup", true).toBool()
        && !settings.value("saslik/disconnected", false).toBool()) resume();
}

void Tui::restoreRoutingIntent()
{
    QSettings settings;
    requested_ = settings.value("routing/requested", false).toBool();
    tunnel_.view.requested = requested_;
    tunnel_.view.mode = settings.value("routing/mode").toString() == "saslik"
        ? settings.value("routing/transport", "auto").toString() : QStringLiteral("direct");
    // Saved intent is not evidence of a live transport or verified routing.
    tunnel_pinned_ = requested_ && tunnel_.view.mode != "direct"
        && settings.value("routing/lastTransport").toString() == "tunnel";
}

void Tui::enableRouting()
{
    if (tunnel_.running()) { status_ = "Tunnel already starting or running; I shows details"; return; }
    retry_.invalidate();
    routing_issue_.clear();
    QSettings settings;
    if (settings.value("routing/mode") != "saslik") {
        def_prog_mode(); endwin();
        const auto result = routing_.resume(RoutingController::Authorization::Terminal);
        reset_prog_mode(); refresh(); status_ = result.detail;
        tunnel_.view.mode = "direct";
        tunnel_.view.requested = result.ok || requested_;
        if (!result.ok) routing_issue_ = "Cannot restore direct routing · E retries, I details";
        if (result.ok) { requested_ = true; settings.setValue("routing/requested", true); }
        return;
    }
    if (settings.value("saslik/disconnected", false).toBool()) {
        routing_issue_ = "Disconnected from Saslik · S selects a server";
        status_ = "Reconnect to Saslik first (S)"; return;
    }
    // Publish intent before authorization: a missing helper is not "Tunnel off".
    requested_ = true; settings.setValue("routing/requested", true);
    tunnel_.view.requested = true;
    tunnel_.view.mode = settings.value("routing/transport", "auto").toString();
    def_prog_mode(); endwin();
    const auto auth = TuiTunnel::authorize();
    reset_prog_mode(); refresh();
    if (!auth.ok) {
        routing_issue_ = "Helper not authorized · E retries, I details";
        status_ = "Helper authorization failed; E retries: " + auth.detail;
        tunnel_.error = status_; tunnel_.view.state = "authorization-required";
        return;
    }
    tunnel_.view.state = "connecting";
    tunnel_.error.clear();
    const auto address = settings.value("routing/saslikUrl").toString();
    QProcess discovery;
    discovery.start(QCoreApplication::applicationFilePath(), {"remote-status", address});
    if (!discovery.waitForStarted(3000) || !discovery.waitForFinished(10000)
        || discovery.exitCode() != 0) {
        discovery.kill(); discovery.waitForFinished(1000);
        routing_issue_ = "Cannot reach or authenticate Saslik · I details";
        tunnel_.error = QString::fromUtf8(discovery.readAllStandardError()).trimmed();
        status_ = "Saslik control request failed; retry scheduled. Check address, server and pairing (I).";
        tunnel_.view.connected = false; retry_.restart(); return;
    }
    const auto state = QJsonDocument::fromJson(discovery.readAllStandardOutput()).object();
    rememberCertificate(state);
    if (state["version"].toInt() != 1 || !state["available"].isBool()) {
        routing_issue_ = "Unsupported Saslik status response · I details";
        tunnel_.view.connected = false;
        status_ = "Cannot interpret the server response; check compatible Saslik/Skewer versions.";
        retry_.restart(); return;
    }
    const auto gateway = state["gateway"].toString();
    tunnel_.view.connected = true; tunnel_.view.paired = true;
    tunnel_.view.license = state["features"].toObject()["tuntom_license"].toString();
    tunnel_.view.enabled = state["features"].toObject()["tuntom"].toBool() ? 1 : 0;
    if (!state["available"].toBool()) {
        routing_issue_ = "Lab not ready (Saslik connected)";
        status_ = "Saslik reports available=false. Start/check the lab in Saslik; Skewer will retry automatically.";
        retry_.restart(); return;
    }
    tunnel_.view.directKnown = true; tunnel_.view.direct = routing_.nextHopReachable(gateway);
    const bool useTunnel = tunnel_.view.mode != "direct" && (tunnel_.view.mode == "tunnel"
        || !tunnel_.view.direct || settings.value("routing/lastTransport") == "tunnel" || tunnel_pinned_);
    if (useTunnel) {
        if (!InterfaceRouting::state(getuid())["selections"].toObject().isEmpty()) {
            routing_issue_ = "Tunnel blocked by attached VM/interfaces · release them first";
            status_ = "Release VM/interface ingress before enabling a tunnel"; return;
        }
        tunnel_pinned_ = true;
        settings.setValue("routing/lastTransport", "tunnel");
        if (!tunnel_.start(address)) {
            routing_issue_ = "Cannot start Tuntom · I details, O settings";
            status_ = tunnel_.error; retry_.restart();
        }
        else { status_ = "Starting Tuntom"; retry_.invalidate(); }
    } else {
        const auto result = routing_.activate(gateway, RoutingController::Authorization::Terminal);
        status_ = result.detail;
        if (!result.ok) routing_issue_ = "Cannot enable direct routing · E retries, I details";
        if (result.ok) { routing_next_hop_ = gateway; settings.setValue("routing/lastTransport", "direct"); }
    }
}

void Tui::pollTunnel()
{
    if (connections_started_ && connections_pending_.isFinished()) {
        model_.setConnections(connections_pending_.result()); connections_started_ = false;
    }
    if (!connections_started_ && (!connections_age_.isValid()
        || connections_age_.elapsed() >= Preferences::number("refresh/connectionSeconds", 5, 2, 60) * 1000)) {
        connections_pending_ = QtConcurrent::run(readConnections);
        connections_started_ = true; connections_age_.restart();
    }
    const bool wasRunning = tunnel_.running();
    const auto previousState = tunnel_.view.state;
    tunnel_.poll();
    if (previousState != "verified" && tunnel_.view.state == "verified")
        status_ = "Tunnel verified; checking local routing. I shows diagnostics.";
    if (!tunnel_.gateway.isEmpty()) routing_next_hop_ = tunnel_.gateway;
    if (tunnel_pinned_) {
        routing_active_ = routing_active_ && tunnel_.view.state == "verified" && tunnel_.view.fresh;
        tunnel_.view.routingActive = routing_active_;
    }
    if (wasRunning && !tunnel_.running()) {
        routing_issue_ = "Tunnel controller stopped · I details";
        status_ = "Tunnel stopped; I shows diagnostics. Retrying in 60 s";
        retry_.restart();
    }
    if (requested_ && retry_.isValid() && retry_.elapsed() >= 60000) {
        retry_.invalidate();
        // Never produce unattended password prompts after authorization loss.
        if (PrivilegedSession::client().running()) enableRouting();
        else {
            routing_issue_ = "Helper session ended · E authorizes again";
            status_ = "Automatic retries paused: helper session ended. Press E to authorize again.";
        }
    }
}

void Tui::configureSaslik()
{
    if (requested_) { status_ = "Disable routing before changing Saslik"; return; }
    const auto input = prompt("Paired skewer:// address (pair first with skewer pair -)");
    const QUrl url(input);
    if (url.scheme() != "skewer" || url.path() != "/pair" || url.host().isEmpty()
        || url.hasFragment() || url.hasQuery() || !url.userInfo().isEmpty()) {
        status_ = "Expected a paired address without invitation secret"; return;
    }
    QSettings settings;
    settings.setValue("routing/saslikUrl", input); settings.setValue("routing/mode", "saslik");
    settings.setValue("saslik/disconnected", false);
    status_ = "Saslik selected; E enables routing";
}

void Tui::configureScope()
{
    if (requested_ || routing_active_ || QFile::exists("/run/skewer-host.json")) { status_ = "Disable routing before changing scope"; return; }
    const int scope = choose("Routing scope", {"Selected applications", "Whole host (IPv4; IPv6 blocked; Disable releases host)"});
    if (scope < 0) return;
    QSettings().setValue("routing/scope", scope == 1 ? "host" : "applications");
    status_ = scope == 1 ? "Whole host selected; E enables routing including services" : "Selected applications";
}

void Tui::configureTransport()
{
    if (requested_) { status_ = "Disable routing before changing transport"; return; }
    const auto mode = prompt("Transport: auto / direct / tunnel").toLower();
    if (!QStringList{"auto", "direct", "tunnel"}.contains(mode)) { status_ = "Invalid transport mode"; return; }
    QSettings().setValue("routing/transport", mode);
    tunnel_.view.mode = mode; tunnel_pinned_ = false;
    status_ = "Transport: " + mode;
}

void Tui::showTunnelDetails()
{
    erase();
    const auto detail = routingSummary() + "\nHelper: "
        + (PrivilegedSession::client().running() ? QStringLiteral("authorized session running") : QStringLiteral("no active session"))
        + "\n" + status_ + "\n\n" + Tuntom::statusSummary(tunnel_.view) + "\n\n" + tunnel_.error
        + "\n\nPress any key to return";
    addstr(detail.toLocal8Bit().constData()); refresh();
    while (getch() == ERR) pollTunnel();
}

void Tui::disableRouting()
{
    tunnel_.stop(); retry_.invalidate();
    def_prog_mode(); endwin();
    const auto result = routing_.deactivate(RoutingController::Authorization::Terminal);
    reset_prog_mode(); refresh();
    status_ = result.detail;
    if (result.ok) {
        requested_ = false; tunnel_pinned_ = false; tunnel_.view.requested = false;
        routing_issue_.clear();
        status_ = "Routing disabled; attached applications remain in the guarded slice.";
        QSettings().setValue(QStringLiteral("routing/requested"), false);
    }
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
    if (type == ApplicationModel::NodeType::Interface) {
        if (routed && tunnel_pinned_) { status_ = "Interface ingress through Tuntom is not supported"; return; }
        if (routed && index.data(ApplicationModel::PartiallyRoutedRole).toBool()) {
            status_ = "Already selected through its bridge; release the bridge first";
            return;
        }
        if (routed && prompt("IPv4; host bridge gateway required; other gateway MACs/IPv6 blocked; guest CA unknown. Type ATTACH") != "ATTACH") return;
        def_prog_mode(); endwin();
        const auto result = routing_.interfaceChange(index.data(ApplicationModel::InterfaceNameRole).toString(),
            index.data(ApplicationModel::InterfaceIndexRole).toInt(), routing_next_hop_, routed,
            RoutingController::Authorization::Terminal);
        reset_prog_mode(); refresh();
        status_ = result.detail;
        model_.refresh(); rebuildRows();
        return;
    }
    if (type != ApplicationModel::NodeType::Application) {
        status_ = QStringLiteral("Select an application, not an individual helper process");
        return;
    }
    const auto pids = selectedPids();
    const CgroupResult result = routed
        ? cgroups_.route(pids, index.data().toString())
        : cgroups_.release(pids, index.data().toString());
    status_ = result.detail;
    if (result.ok && routed && QSettings().value("connections/cleanupOnAttach",false).toBool()) {
        def_prog_mode(); endwin();
        QThread::msleep(500);
        const auto cleaned = RoutingController().cleanupTcp(pids,RoutingController::Authorization::Terminal);
        reset_prog_mode(); refresh(); status_ = cleaned.detail;
    }
    if (result.ok) { model_.refresh(); rebuildRows(); }
}

void Tui::launch()
{
    const QString entered = prompt(QStringLiteral("Run through Skewer"));
    if (entered.isEmpty()) return;
    const QString command = model_.resolveLaunchCommand(entered);
    QStringList words = QProcess::splitCommand(command);
    if (words.isEmpty()) return;
    const auto executable = QStandardPaths::findExecutable(words.first());
    if (executable.isEmpty()) { status_ = "Command not found: " + words.first(); return; }
    words[0] = executable;
    QStringList invocation = CgroupManager::routedLaunchPrefix(words.first());
    invocation.append(words);
    const QString program = invocation.takeFirst();
    status_ = QProcess::startDetached(program, invocation)
        ? QStringLiteral("Launch requested; existing instances may receive it. Check the routing badge.") : QStringLiteral("Launch failed");
}

void Tui::shell()
{
    def_prog_mode();
    endwin();
    auto invocation = CgroupManager::routedLaunchPrefix("shell", true);
    const auto program = invocation.takeFirst();
    QProcess process;
    process.setProcessChannelMode(QProcess::ForwardedChannels);
    process.setInputChannelMode(QProcess::ForwardedInputChannel);
    process.start(program, invocation);
    if (!process.waitForStarted()) status_ = "Cannot start Skewer shell: " + process.errorString();
    else {
        while (!process.waitForFinished(100)) pollTunnel();
        status_ = QString("Skewer shell exited (%1)").arg(process.exitCode());
    }
    reset_prog_mode();
    refresh();
    model_.refresh();
    rebuildRows();
}

QString Tui::prompt(const QString& label, bool secret)
{
    int height = 0, width = 0;
    getmaxyx(stdscr, height, width);
    echo();
    curs_set(1);
    timeout(100);
    move(height - 3, 2);
    clrtoeol();
    const QByteArray heading = (label + QStringLiteral(": ")).toLocal8Bit();
    addstr(heading.constData());
    // Keep controller pipes and lease renewals alive while editing a field.
    noecho();
    QString value;
    while (true) {
        pollTunnel();
        const int key = getch();
        if (key == '\n' || key == KEY_ENTER) break;
        if (key == 27) { value.clear(); break; }
        if (key == KEY_BACKSPACE || key == 127 || key == 8) value.chop(1);
        else if (key >= 32 && key < 127 && value.size() < 8192) value += QChar(key);
        move(height - 3, 2); clrtoeol();
        addstr(clipped(label + ": " + (secret ? QString(value.size(), '*') : value), width - 4).toLocal8Bit().constData()); refresh();
    }
    timeout(200);
    curs_set(0);
    noecho();
    return value.trimmed();
}

int Tui::choose(const QString& title, const QStringList& items)
{
    int selected = 0;
    while (true) {
        pollTunnel();
        erase();
        int height, width; getmaxyx(stdscr, height, width);
        addnstr(title.toLocal8Bit().constData(), std::max(0, width - 1));
        const int count = std::max(1, height - 4);
        const int offset = std::max(0, selected - count + 1);
        for (int i = offset; i < items.size() && i < offset + count; ++i) {
            if (i == selected) attron(A_REVERSE);
            mvaddnstr(2 + i - offset, 1, clipped(items[i], width - 2).toLocal8Bit().constData(), std::max(0, width - 2));
            attroff(A_REVERSE);
        }
        mvaddnstr(height - 1, 1, "Up/Down select | Enter open | Esc back", std::max(0, width - 2)); refresh();
        switch (getch()) {
        case KEY_UP: case 'k': selected = std::max(0, selected - 1); break;
        case KEY_DOWN: case 'j': selected = std::min(std::max(0, int(items.size()) - 1), selected + 1); break;
        case '\n': case KEY_ENTER: return items.isEmpty() ? -1 : selected;
        case 27: case 'q': return -1;
        }
    }
}

void Tui::rememberCertificate(const QJsonObject& state)
{
    const auto cert = CaStoreManager::parse(state["ca_pem"].toString().toUtf8());
    if (cert.isNull()) return;
    certificate_ = cert.toPem();
    QSettings().setValue("knownCa/" + CaStoreManager(cert).fingerprint(), certificate_);
}

void Tui::pairSaslik()
{
    if (requested_) { status_ = "Disable routing before pairing"; return; }
    const auto invitation = prompt("Paste pairing invitation (hidden)", true);
    if (invitation.isEmpty()) return;
    QProcess pair;
    pair.start(QCoreApplication::applicationFilePath(), {"pair", "-"});
    if (!pair.waitForStarted(3000)) { status_ = pair.errorString(); return; }
    pair.write(invitation.toUtf8() + '\n'); pair.closeWriteChannel();
    QElapsedTimer deadline; deadline.start();
    while (!pair.waitForFinished(100) && deadline.elapsed() < 20000) pollTunnel();
    if (pair.state() != QProcess::NotRunning) { pair.kill(); pair.waitForFinished(1000); status_ = "Pairing timed out"; return; }
    if (pair.exitCode()) { status_ = "Pairing failed; verify the invitation"; return; }
    QUrl address(invitation); address.setFragment({});
    QSettings settings;
    settings.setValue("routing/saslikUrl", address.toString());
    settings.setValue("routing/mode", "saslik"); settings.setValue("saslik/disconnected", false);
    status_ = "Paired using TLS-PSK; E enables routing";
}

void Tui::caTrust()
{
    const int source = choose("CA Trust", {"Select retained CA", "Download from paired Saslik", "Load CA file"});
    if (source < 0) return;
    if (source == 1) {
        QProcess discovery;
        discovery.start(QCoreApplication::applicationFilePath(), {"remote-status", QSettings().value("routing/saslikUrl").toString()});
        QElapsedTimer deadline; deadline.start();
        while (!discovery.waitForFinished(100) && deadline.elapsed() < 10000) pollTunnel();
        if (discovery.state() != QProcess::NotRunning) { discovery.kill(); discovery.waitForFinished(1000); }
        if (discovery.exitCode() != 0) { status_ = "Authenticated CA download failed"; return; }
        rememberCertificate(QJsonDocument::fromJson(discovery.readAllStandardOutput()).object());
    } else if (source == 2) {
        QFile input(prompt("CA PEM file"));
        if (!input.open(QIODevice::ReadOnly) || input.size() > 65536) { status_ = "Cannot read CA file"; return; }
        const auto certificate = CaStoreManager::parse(input.readAll());
        if (certificate.isNull()) { status_ = "Invalid CA"; return; }
        QSettings().setValue("knownCa/" + CaStoreManager(certificate).fingerprint(), certificate.toPem());
    }
    QSettings settings; settings.beginGroup("knownCa");
    const auto keys = settings.childKeys();
    QStringList labels;
    for (const auto& key : keys) {
        const auto pem = settings.value(key).toByteArray();
        const auto cert = CaStoreManager::parse(pem);
        labels << cert.subjectInfo(QSslCertificate::CommonName).join(", ") + " · " + key
            + (pem == certificate_ ? " · active" : " · unused");
    }
    const int chosen = choose("CA Trust — retained certificates (no automatic installation)", labels);
    if (chosen < 0) return;
    const auto cert = CaStoreManager::parse(settings.value(keys[chosen]).toByteArray());
    if (cert.isNull()) { status_ = "Invalid CA"; return; }
    CaStoreManager manager(cert);
    status_ = "Scanning certificate stores…"; draw();
    auto scan = QtConcurrent::run([manager] { return manager.stores(); });
    while (!scan.isFinished()) { pollTunnel(); QThread::msleep(50); }
    const auto stores = scan.result();
    labels = {"Search and remove this CA from ALL discovered stores"};
    for (const auto& store : stores)
        labels << QString("%1 | %2 | %3 | %4").arg(store.label,
            store.installed ? "Trusted" : store.available ? "CA absent" : "Unavailable", store.snap_state, store.path);
    const int index = choose("CA " + manager.fingerprint(), labels);
    if (index < 0) return;
    const bool all = index == 0;
    const auto action = all ? QString("remove") : prompt("Action: install / remove / details / save");
    if (action == "save") {
        const auto path = prompt("Save CA PEM to new file");
        QFile output(path);
        status_ = !path.isEmpty() && output.open(QIODevice::WriteOnly | QIODevice::NewOnly)
            && output.write(cert.toPem()) == cert.toPem().size() ? "CA exported" : "Cannot create new file";
        return;
    }
    if (action == "details") { choose(stores[index - 1].path, {stores[index - 1].detail}); return; }
    if (action != "install" && action != "remove") return;
    const bool remove = action == "remove";
    const QString warning = remove ? "Remove CA; existing TLS sessions remain open. Type YES"
        : "Trust permits TLS interception by this CA owner. Type YES";
    if (prompt(warning) != "YES") return;
    QVector<CaStore> targets;
    if (all) { for (const auto& store : stores) if (!store.matches.isEmpty() || store.installed) targets << store; }
    else targets << stores[index - 1];
    if (std::any_of(targets.begin(), targets.end(), [](const auto& store) { return store.system; })) {
        def_prog_mode(); endwin();
        QProcess auth; auth.setProcessChannelMode(QProcess::ForwardedChannels);
        auth.start("sudo", {"-v"});
        QElapsedTimer deadline; deadline.start();
        while (!auth.waitForFinished(100) && deadline.elapsed() < 60000) pollTunnel();
        const bool authorized = auth.state() == QProcess::NotRunning
            && auth.exitStatus() == QProcess::NormalExit && auth.exitCode() == 0;
        if (auth.state() != QProcess::NotRunning) { auth.kill(); auth.waitForFinished(1000); }
        reset_prog_mode(); refresh();
        if (!authorized) { status_ = "Authorization failed"; return; }
    }
    auto operation = QtConcurrent::run([manager, targets, remove] {
        QStringList failures;
        for (const auto& store : targets) {
            QString error;
            if (!(remove ? manager.remove(store, error, false) : manager.install(store, error, false)))
                failures << store.path + ": " + error;
        }
        return failures;
    });
    status_ = "Updating selected CA stores…"; draw();
    while (!operation.isFinished()) { pollTunnel(); QThread::msleep(50); }
    status_ = operation.result().isEmpty() ? "CA stores updated" : operation.result().join("; ");
}

void Tui::runtimeTrust()
{
    QSettings settings; settings.beginGroup("knownCa");
    const auto keys = settings.childKeys();
    const int ca = choose("Runtime Trust: select retained CA", keys);
    if (ca < 0) return;
    const auto pem = settings.value(keys[ca]).toByteArray();
    const int action = choose("Runtime Trust — affects new processes, not existing shells",
        {"Inspect runtimes", "Prepare managed CA bundle", "Remove managed CA bundle", "Show shell exports"});
    if (action == 0) {
        status_ = "Inspecting runtimes…"; draw();
        auto scan = QtConcurrent::run([pem] { return discoverRuntimeTrust(pem); });
        while (!scan.isFinished()) { pollTunnel(); QThread::msleep(50); }
        QStringList rows;
        for (const auto& item : scan.result()) rows << QString("%1 %2 | %3 | %4 | %5")
            .arg(item.runtime, item.version, item.state, item.location, item.detail);
        choose("Runtime certificate sources", rows);
    } else if (action == 1) {
        if (prompt("This CA permits TLS interception in new Skewer programs. Type TRUST") == "TRUST")
            status_ = prepareRuntimeTrust(pem);
    } else if (action == 2) {
        if (prompt("Remove bundle? Existing shells keep exports. Type REMOVE") == "REMOVE")
            status_ = removeRuntimeTrust(pem);
    } else if (action == 3) choose("New Skewer shells use prepared bundles automatically", runtimeTrustEnvironment(pem).split('\n'));
}

void Tui::connections()
{
    const auto selection = selectedPids();
    const int scope = choose("Connections", {"All user applications", "Selected application"});
    if (scope < 0) return;
    const bool selectedOnly = scope == 1;
    status_ = "Reading sockets…"; draw();
    auto scan = QtConcurrent::run(readConnections);
    while (!scan.isFinished()) { pollTunnel(); QThread::msleep(50); }
    const auto snapshot = scan.result(); model_.setConnections(snapshot);
    QStringList rows;
    for (const auto& connection : snapshot.rows) {
        if (selectedOnly && std::none_of(selection.begin(), selection.end(), [&](int pid) { return connection.pids.contains(pid); })) continue;
        QStringList pids; for (int pid : connection.pids) pids << QString::number(pid);
        rows << QString("%1 %2  %3 -> %4 | PID %5 | %6").arg(connection.protocol, connection.state,
            connection.local, connection.remote, pids.join(','), connection.group);
    }
    choose("Socket membership, not proof of interception. " + snapshot.error, rows);
    if (selectedOnly && !selection.isEmpty()
        && prompt("Close selected application's old TCP connections? Reconnect NOT guaranteed. Type CLOSE") == "CLOSE") {
        def_prog_mode(); endwin();
        const auto result = routing_.cleanupTcp(selection, RoutingController::Authorization::Terminal);
        reset_prog_mode(); refresh(); status_ = result.detail;
    }
}

void Tui::preferences()
{
    struct Option { const char* key; const char* label; int fallback, minimum, maximum; };
    const Option options[] = {
        {"routing/resumeOnStartup", "Resume at startup", 1, 0, 1},
        {"connections/cleanupOnAttach", "Close old TCP after attach (reconnect not guaranteed)", 0, 0, 1},
        {"refresh/processSeconds", "Process refresh seconds", 5, 2, 60},
        {"refresh/connectionSeconds", "Connections refresh seconds", 5, 2, 60},
        {"refresh/routingSeconds", "Routing refresh seconds", 5, 2, 60},
        {"refresh/saslikSeconds", "Saslik refresh seconds", 10, 5, 120},
        {"refresh/vmSeconds", "VM names refresh seconds", 30, 10, 300},
    };
    QStringList labels;
    for (const auto& option : options) labels << QString("%1: %2").arg(option.label)
        .arg(QSettings().value(option.key, option.fallback).toInt());
    labels << "Tuntom executable: " + Preferences::tuntomBinary();
    labels << "Destination exemptions";
    const int selected = choose("Shared Skewer settings", labels);
    if (selected < 0) return;
    if (selected == int(std::size(options)) + 1) {
        if (requested_) { status_ = "Disable routing before editing exemptions"; return; }
        const auto text = prompt("Exempt IPv4 addresses/CIDRs, comma-separated (empty clears)");
        QStringList normalized; QString error;
        if (!RoutingPlanner::normalizeExemptions(text.split(',', Qt::SkipEmptyParts), normalized, error)) {
            status_ = error; return;
        }
        QSettings().setValue("routing/exemptions", normalized);
    } else if (selected == int(std::size(options))) {
        const auto path = prompt("Absolute Tuntom executable path");
        if (path.isEmpty()) return;
        QString error;
        bool development = false;
        if (Tuntom::checkedBinary(path, error).isEmpty() && Tuntom::developmentBinaryAllowed)
            development = prompt("Development executable will run as ROOT. Only trusted code! Type ACCEPT") == "ACCEPT";
        if (Tuntom::checkedBinary(path, error, development).isEmpty()) { status_ = error; return; }
        QSettings().setValue("tunnel/binary", path);
        QSettings().setValue("tunnel/developmentAcknowledgedPath", development ? path : QString{});
    } else {
        const auto& option = options[selected];
        bool valid = false;
        const int value = prompt(QString("%1 (%2..%3)").arg(option.label).arg(option.minimum).arg(option.maximum)).toInt(&valid);
        if (!valid || value < option.minimum || value > option.maximum) { status_ = "Invalid value"; return; }
        QSettings().setValue(option.key, value);
    }
    model_.applyPreferences(); status_ = "Settings saved (shared with GUI)";
}

QVector<pid_t> Tui::selectedPids() const
{
    QVector<pid_t> pids;
    if (rows_.isEmpty()) return pids;
    for (const QVariant& value : rows_.at(selected_).index
             .data(ApplicationModel::ProcessIdsRole).toList()) pids.push_back(value.toInt());
    return pids;
}
