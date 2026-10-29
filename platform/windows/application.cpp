#include "processes.hpp"
#include "process_browser.hpp"
#include "launch_catalog.hpp"
#include "ui/application_shell.hpp"
#include "ui/application_page.hpp"
#include <QApplication>
#include <QCompleter>
#include <QFileDialog>
#include <QFutureWatcher>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QProcess>
#include <QTimer>
#include <QVBoxLayout>
#include <QtConcurrent>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QSpinBox>
#include <QDir>
#include <QStandardPaths>
#include <QLockFile>
#include <QLocalServer>
#include <QLocalSocket>
#include <QCryptographicHash>
#include <QMessageBox>
#include <QItemSelectionModel>
#ifdef SKEWER_WINDOWS_PAIRING
#include "client_report.hpp"
#include "ca_trust_panel.hpp"
#include "connections_panel.hpp"
#include "pairing.hpp"
#include "routing_panel.hpp"
#include "routed_launch.hpp"
#include "runtime_trust_panel.hpp"
#include <QSettings>
#include <QDateTime>
#include <QDesktopServices>
#include <QHostAddress>
#include <QJsonObject>
#endif
#include <cstdio>
#include <cstring>

// Native controllers plug into the same shell and Applications page as Linux.
// Unsupported operations never fall back to shell commands or simulated success.
namespace {
struct ScanResult {
    QVector<skewer::ui::ProcessRecord> records;
    QString error;
    bool windows{};
    unsigned inaccessible{};
};
ScanResult scan() {
    ScanResult result;
    try {
        const auto snapshot = skewer::windows::scanCurrentUser();
        result.windows = snapshot.window_enumeration_available;
        result.inaccessible = snapshot.inaccessible;
        for (const auto& process : snapshot.processes) {
            skewer::ui::ProcessRecord record{process.key.pid,
                                             process.key.created,
                                             process.parent,
                                             QString::fromStdWString(process.name),
                                             QString::fromStdWString(process.executable),
                                             {}};
            for (const auto& title : process.window_titles) {
                record.windows.append(QString::fromStdWString(title));
            }
            result.records.append(std::move(record));
        }
    } catch (const std::exception& error) {
        result.error = QString::fromUtf8(error.what());
    }
    return result;
}
struct LaunchResult {
    DWORD pid{};
    std::uint64_t generation{};
    bool routed{};
    QString error;
};
#ifdef SKEWER_WINDOWS_PAIRING
struct PairedStatusResult {
    QString source;
    QJsonObject value;
    QString error;
};
#endif
LaunchResult launch(const QString& executable, const QStringList& arguments, const QString& service, bool routed,
                    const std::shared_ptr<skewer::windows::Handle>& cancel,
                    const skewer::windows::EnvironmentOverrides& environment) {
    try {
        std::vector<std::wstring> native_arguments;
        native_arguments.reserve(arguments.size());
        for (const auto& argument : arguments) {
            native_arguments.push_back(argument.toStdWString());
        }
        if (routed) {
            const auto result = skewer::windows::launchRouted(service.toStdWString(),
                                                              executable.toStdWString(), native_arguments,
                                                              cancel->get(), environment);
            skewer::windows::Handle thread(result.process.hThread), handle(result.process.hProcess);
            return {result.identity.pid, result.generation, true, {}};
        }
        const auto process = skewer::windows::launch(executable.toStdWString(), native_arguments,
                                                     skewer::windows::LaunchMode::Running, environment);
        skewer::windows::Handle thread(process.hThread), handle(process.hProcess);
        return {process.dwProcessId, 0, false, {}};
    } catch (const std::exception& error) {
        return {0, 0, routed, QString::fromUtf8(error.what())};
    }
}
class WindowsWindow final : public skewer::ui::ApplicationShell {
public:
    WindowsWindow()
        : ApplicationShell(QStringLiteral(SKEWER_VERSION)),
          launch_cancel_(
              std::make_shared<skewer::windows::Handle>(CreateEventW(nullptr, TRUE, FALSE, nullptr))) {
        if (!*launch_cancel_) {
            throw std::runtime_error("Cannot create launcher cancellation event");
        }
        buildPage();
        buildLauncher();
#ifdef SKEWER_WINDOWS_PAIRING
        buildSaslikPage();
        routing_status_bar_ = new QLabel(tr("Routing: checking…"), this);
        routing_status_bar_->setAccessibleName(tr("Windows routing status"));
        statusBar()->addPermanentWidget(routing_status_bar_);
        routing_panel_ = new skewer::windows::RoutingPanel(this);
        pages()->addTab(routing_panel_, tr("Routing"));
        routing_panel_->setStateCallback(
            [this](bool known, const skewer::windows::RoutingReply& state) {
                routingStateChanged(known, state);
            });
#endif
        applyPreferences();
        connect(preferencesAction(), &QAction::triggered, this, &WindowsWindow::editPreferences);
        connect(&scan_watcher_, &QFutureWatcher<ScanResult>::finished, this, &WindowsWindow::scanFinished);
        connect(&launch_watcher_, &QFutureWatcher<LaunchResult>::finished, this,
                &WindowsWindow::launchFinished);
        connect(&timer_, &QTimer::timeout, this, &WindowsWindow::refresh);
        timer_.start();
    }

    ~WindowsWindow() override {
        // Workers only own value arguments. Finish them before destroying the UI;
        // closing Skewer must not terminate any application it launched.
        timer_.stop();
#ifdef SKEWER_WINDOWS_PAIRING
        report_timer_.stop();
        pairing_watcher_.waitForFinished();
        report_watcher_.waitForFinished();
        paired_status_watcher_.waitForFinished();
#endif
        scan_watcher_.waitForFinished();
        SetEvent(launch_cancel_->get());
        launch_watcher_.waitForFinished();
    }

    void refresh() {
        if (scan_watcher_.isRunning() || !isVisible() || isMinimized()) {
            return;
        }
        scan_watcher_.setFuture(QtConcurrent::run(scan));
    }

private:
#ifdef SKEWER_WINDOWS_PAIRING
    void buildSaslikPage() {
        auto* page = new QWidget(this);
        auto* layout = new QVBoxLayout(page);
        auto* explanation =
            new QLabel(tr("Report this paired Windows client to Saslik. "
                          "Online presence does not mean that application routing is active. "
                          "Current User Root and Skewer-managed runtime trust are reported "
                          "for the exact advertised CA."),
                       page);
        explanation->setWordWrap(true);
        layout->addWidget(explanation);
        invitation_ = new QLineEdit(page);
        invitation_->setAccessibleName(tr("Saslik pairing invitation"));
        invitation_->setEchoMode(QLineEdit::Password);
        invitation_->setPlaceholderText(tr("Paste one-time skewer:// pairing invitation…"));
        layout->addWidget(invitation_);
        pair_button_ = new QPushButton(tr("Pair with Saslik"), page);
        layout->addWidget(pair_button_);
        endpoint_ = new QLineEdit(QSettings().value("windows/saslikEndpoint").toString(), page);
        endpoint_->setPlaceholderText("skewer://HOST:8766/pair (already paired endpoint)");
        layout->addWidget(endpoint_);
        report_button_ = new QPushButton(tr("Start reporting"), page);
        layout->addWidget(report_button_);
        report_status_ = new QLabel(tr("Not reporting. Pair first using skewer-control pair - ."), page);
        report_status_->setWordWrap(true);
        layout->addWidget(report_status_);
        paired_status_ = new QLabel(tr("Authenticated lab status has not been loaded yet."), page);
        paired_status_->setObjectName("pairedLabStatus");
        paired_status_->setAccessibleName(tr("Authenticated lab status"));
        paired_status_->setWordWrap(true);
        paired_status_->setTextInteractionFlags(Qt::TextSelectableByMouse);
        layout->addWidget(paired_status_);
        auto* links = new QHBoxLayout;
        open_saslik_ = new QPushButton(tr("Open Saslik"), page);
        open_spider_ = new QPushButton(tr("Open Spider"), page);
        for (auto* button : {open_saslik_, open_spider_}) {
            button->setEnabled(false);
            links->addWidget(button);
            connect(button, &QPushButton::clicked, this, [button] {
                const QUrl target(button->property("targetUrl").toString());
                if ((target.scheme() == "http" || target.scheme() == "https") &&
                    target.userInfo().isEmpty()) {
                    QDesktopServices::openUrl(target);
                }
            });
        }
        links->addStretch();
        layout->addLayout(links);
        layout->addStretch();
        pages()->addTab(page, tr("Saslik"));
        report_timer_.setInterval(10000);
        connect(&report_timer_, &QTimer::timeout, this, &WindowsWindow::sendReport);
        connect(pair_button_, &QPushButton::clicked, this, [this] {
            const auto invitation = invitation_->text().trimmed();
            if (invitation.isEmpty() || invitation.size() > 8192 || pairing_watcher_.isRunning()) {
                report_status_->setText(tr("Paste one complete pairing invitation first."));
                return;
            }
            invitation_->setEnabled(false);
            pair_button_->setEnabled(false);
            report_status_->setText(tr("Pairing with Saslik…"));
            pairing_watcher_.setFuture(QtConcurrent::run([invitation] {
                try {
                    return QPair<QString, QString>{pairInvitation(invitation).toString(), {}};
                } catch (const std::exception&) {
                    // Never echo a malformed invitation or its PSK into the UI.
                    return QPair<QString, QString>{{},
                        QObject::tr("Pairing failed. Check the invitation, connectivity and Saslik state.")};
                }
            }));
        });
        connect(&pairing_watcher_, &QFutureWatcher<QPair<QString, QString>>::finished, this, [this] {
            const auto result = pairing_watcher_.result();
            invitation_->clear();
            invitation_->setEnabled(true);
            pair_button_->setEnabled(true);
            if (!result.second.isEmpty()) {
                report_status_->setText(result.second);
                return;
            }
            endpoint_->setText(result.first);
            QSettings().setValue("windows/saslikEndpoint", result.first);
            ca_trust_->setPairedEndpoint(result.first);
            if (routing_panel_) {
                routing_panel_->setPairedEndpoint(result.first);
            }
            report_status_->setText(tr("Paired. Starting presence reporting…"));
            if (!report_timer_.isActive()) startReporting();
        });
        connect(report_button_, &QPushButton::clicked, this, [this] {
            if (report_timer_.isActive()) {
                report_timer_.stop();
                // Do not overlap a new endpoint with an in-flight request.
                report_button_->setEnabled(!report_watcher_.isRunning());
                report_button_->setText(tr("Start reporting"));
                endpoint_->setEnabled(!report_watcher_.isRunning());
                report_status_->setText(tr("Reporting stopped. Pairing and routing are unchanged."));
                return;
            }
            startReporting();
        });
        connect(&report_watcher_, &QFutureWatcher<QString>::finished, this, [this] {
            if (!report_timer_.isActive()) {
                endpoint_->setEnabled(true);
                report_button_->setEnabled(true);
                return;
            }
            const auto error = report_watcher_.result();
            if (!error.isEmpty()) {
                report_status_->setText(error + tr(" Retrying in 10 seconds."));
                return;
            }
            QSettings().setValue("windows/saslikEndpoint", endpoint_->text().trimmed());
            ca_trust_->setPairedEndpoint(endpoint_->text());
            if (routing_panel_) {
                routing_panel_->setPairedEndpoint(endpoint_->text());
            }
            report_status_->setText(tr("Report accepted at %1. Routing status is independent.")
                                        .arg(QDateTime::currentDateTime().toString("HH:mm:ss")));
            refreshPairedStatus();
        });
        connect(&paired_status_watcher_, &QFutureWatcher<PairedStatusResult>::finished, this, [this] {
            const auto result = paired_status_watcher_.result();
            if (result.source != endpoint_->text().trimmed()) {
                return;
            }
            const auto setLink = [this](QPushButton* button, QUrl target) {
                const QUrl endpoint(endpoint_->text().trimmed());
                if (QHostAddress(target.host()).isLoopback() || target.host() == "localhost") {
                    target.setHost(endpoint.host());
                }
                const bool valid = target.isValid() && !target.host().isEmpty() &&
                                   (target.scheme() == "http" || target.scheme() == "https") &&
                                   target.userInfo().isEmpty();
                button->setProperty("targetUrl", valid ? target.toString() : QString{});
                button->setToolTip(valid ? target.toDisplayString() : QString{});
                button->setEnabled(valid);
            };
            if (!result.error.isEmpty()) {
                paired_status_->setText(tr("Authenticated lab status unavailable: %1").arg(result.error));
                setLink(open_saslik_, {});
                setLink(open_spider_, {});
                return;
            }
            const auto status = result.value;
            const auto lab = status.value("lab_status").toObject();
            const auto proxy = lab.value("services").toObject().value("smithproxy").toObject();
            const auto end_to_end = lab.value("end_to_end").toObject();
            QStringList checks;
            const auto check_values = end_to_end.value("checks").toObject();
            for (auto it = check_values.begin(); it != check_values.end(); ++it) {
                checks << it.key() + ": " + it.value().toObject().value("state").toString(tr("unknown"));
            }
            const auto observation = skewer::windows::advertisedCaObservation();
            paired_status_->setText(
                tr("Authenticated via TLS-PSK\n"
                   "Workspace: %1 · lab ingress: %2\n"
                   "Gateway: %3 · interface: %4\n"
                   "Lab: %5 · Smithproxy: %6 · PID: %7\n"
                   "Internet: %8%9\n"
                   "Locally advertised CA SHA-256: %10\nUpdated: %11")
                    .arg(status.value("workspace").toString(tr("unknown")),
                         status.value("available").toBool() ? tr("available") : tr("unavailable"),
                         status.value("gateway").toString(tr("—")),
                         status.value("host_interface").toString(tr("—")),
                         lab.value("runtime_state").toString(tr("unknown")),
                         proxy.value("state").toString(tr("unknown")),
                         proxy.value("pid").isDouble() ? QString::number(proxy.value("pid").toInt())
                                                       : tr("—"),
                         checks.isEmpty() ? tr("not measured") : checks.join(" · "),
                         end_to_end.value("stale").toBool() ? tr(" (stale)") : QString{},
                         observation.fingerprint.isEmpty() ? tr("not downloaded")
                                                           : observation.fingerprint,
                         QDateTime::currentDateTime().toString(Qt::ISODate)));
            QUrl web;
            web.setScheme("https");
            web.setHost(QUrl(result.source).host());
            web.setPort(status.value("ui_port").toInt(-1));
            web.setPath("/");
            setLink(open_saslik_, status.value("ui_port").toInt() > 0 ? web : QUrl{});
            const auto spider = lab.value("endpoints").toObject().value("spider_ui").toString();
            setLink(open_spider_, spider.isEmpty() ? QUrl{} : web.resolved(QUrl(spider)));
        });
        // A previously validated endpoint resumes presence on the next launch.
        if (!endpoint_->text().isEmpty()) {
            startReporting();
        }
    }

    void startReporting() {
        const QUrl endpoint(endpoint_->text().trimmed());
        if (!endpoint.isValid() || endpoint.scheme() != "skewer" || endpoint.host().isEmpty() ||
            endpoint.port() <= 0 || endpoint.path() != "/pair" || endpoint.hasFragment() ||
            endpoint.hasQuery() || !endpoint.userInfo().isEmpty()) {
            report_status_->setText(
                tr("Enter a paired skewer://HOST:PORT/pair endpoint, not an invitation."));
            return;
        }
        endpoint_->setEnabled(false);
        report_button_->setText(tr("Stop reporting"));
        report_timer_.start();
        sendReport();
    }

    void sendReport() {
        if (report_watcher_.isRunning()) {
            return;
        }
        report_status_->setText(tr("Reporting to Saslik…"));
        // TLS and DNS run off the GUI thread, including while minimized.
        const QUrl endpoint(endpoint_->text().trimmed());
        report_watcher_.setFuture(QtConcurrent::run(
            [endpoint] { return skewer::windows::sendClientReport(endpoint, SKEWER_VERSION); }));
    }

    void refreshPairedStatus() {
        if (paired_status_watcher_.isRunning()) {
            return;
        }
        const auto source = endpoint_->text().trimmed();
        const QUrl endpoint(source);
        if (!endpoint.isValid() || endpoint.scheme() != "skewer" || endpoint.host().isEmpty() ||
            endpoint.port() <= 0 || endpoint.path() != "/pair" || endpoint.hasFragment() ||
            endpoint.hasQuery() || !endpoint.userInfo().isEmpty()) {
            return;
        }
        paired_status_watcher_.setFuture(QtConcurrent::run([endpoint, source] {
            try {
                return PairedStatusResult{source, pairedStatus(endpoint), {}};
            } catch (const std::exception& error) {
                return PairedStatusResult{source, {}, QString::fromUtf8(error.what())};
            }
        }));
    }
#endif
    void buildPage() {
        page_ = new skewer::ui::ApplicationPage(this);
        pages()->addTab(page_, tr("Applications"));
#ifdef SKEWER_WINDOWS_PAIRING
        ca_trust_ = new skewer::windows::CaTrustPanel(this);
        auto* runtime_trust = new skewer::windows::RuntimeTrustPanel(this);
        ca_trust_->setCertificateCallback(
            [runtime_trust](const QByteArray& pem) { runtime_trust->setCertificate(pem); });
        pages()->addTab(ca_trust_, tr("CA Trust"));
        pages()->addTab(runtime_trust, tr("Runtime Trust"));
#else
        addUnavailablePage(tr("CA Trust"), tr("This build has no paired CA support."));
        addUnavailablePage(tr("Runtime Trust"), tr("This build has no paired CA support."));
#endif
        auto* disclaimer = new QLabel(tr("Launch through Skewer starts one new process suspended and "
                                         "releases it only after routing is ready. "
                                         "Attach guards the live process tree and resets its existing IPv4 "
                                         "TCP connections before activation. Fresh corroborated IPv4 TCP and UDP are routed, "
                                         "including new descendants and intact live trees. Already-open UDP, "
                                         "orphaned handoffs and IPv6 are not covered. "
                                         "Whole-host routing is controlled on the Routing tab."),
                                      page_);
        disclaimer->setWordWrap(true);
        page_->top->addWidget(disclaimer);
        browser_ = new skewer::ui::ProcessBrowser(page_, page_->tree);
        page_->setProcessWidget(browser_);
        connections_ = new skewer::windows::ConnectionsPanel(browser_, this);
        pages()->addTab(connections_, tr("Connections"));
        connect(page_->search, &QLineEdit::textChanged, browser_, &skewer::ui::ProcessBrowser::setFilterText);
        page_->action_status->setText(tr("Checking authoritative routing state…"));
        page_->attach->setEnabled(false);
        page_->attach->setToolTip(
            tr("Route fresh corroborated IPv4 TCP and UDP from the selected running process."));
        page_->release->setEnabled(false);
        page_->release->setToolTip(tr("Stop the currently selected-process routing session."));
#ifdef SKEWER_WINDOWS_PAIRING
        connect(browser_->tree()->selectionModel(), &QItemSelectionModel::currentChanged, this,
                [this] { updateApplicationActions(); });
        connect(browser_->tree()->selectionModel(), &QItemSelectionModel::selectionChanged, this,
                [this] { updateApplicationActions(); });
        connect(page_->attach, &QPushButton::clicked, this, [this] { attachSelected(); });
        connect(page_->release, &QPushButton::clicked, this, [this] {
            page_->release->setEnabled(false);
            page_->action_status->setText(tr("Stopping selected-process routing…"));
            routing_panel_->stopCurrent();
        });
#endif
        auto* routing_status = new QLabel(tr("Whole-host routing: see Routing tab"), this);
        routing_status->setObjectName("routingStatusBar");
        statusBar()->addPermanentWidget(routing_status);
    }

    void buildLauncher() {
        auto* row = new QHBoxLayout;
        path_ = new QLineEdit(this);
        path_->setAccessibleName(tr("Application executable"));
        path_->setPlaceholderText(
            tr("Find a seen application by name, or enter an executable path…"));
        arguments_ = new QLineEdit(this);
        arguments_->setAccessibleName(tr("Application arguments"));
        arguments_->setPlaceholderText(tr("Arguments (quoted values supported; no shell)…"));
        suggestions_ = new skewer::ui::LaunchCatalog(this);
        auto* completer = new skewer::ui::ApplicationCompleter(suggestions_, this);
        path_->setCompleter(completer);
        auto* browse = new QPushButton(tr("Browse…"), this);
        start_ = new QPushButton(tr("Launch normally"), this);
#ifdef SKEWER_WINDOWS_PAIRING
        routed_start_ = new QPushButton(tr("Launch through Skewer"), this);
        routed_start_->setObjectName("routedLaunch");
#endif
        row->addWidget(path_, 1);
        row->addWidget(arguments_, 1);
        row->addWidget(browse);
        row->addWidget(start_);
#ifdef SKEWER_WINDOWS_PAIRING
        row->addWidget(routed_start_);
#endif
        page_->footer->addLayout(row);
        launch_status_ = new QLabel(this);
        launch_status_->setWordWrap(true);
        page_->footer->addWidget(launch_status_);
        status_ = new QLabel(tr("Scanning…"), this);
        status_->setWordWrap(true);
        page_->footer->addWidget(status_);
        connect(browse, &QPushButton::clicked, this, &WindowsWindow::browseExecutable);
        connect(start_, &QPushButton::clicked, this, &WindowsWindow::startProgram);
#ifdef SKEWER_WINDOWS_PAIRING
        connect(routed_start_, &QPushButton::clicked, this, [this] { startProgram(true); });
        connect(path_, &QLineEdit::returnPressed, this, [this] { startProgram(true); });
#else
        connect(path_, &QLineEdit::returnPressed, this, [this] { startProgram(); });
#endif
    }

    void applyPreferences() {
        const QSettings settings;
        timer_.setInterval(qBound(2, settings.value("refresh/processSeconds", 3).toInt(), 60) * 1000);
        auto font = browser_->tree()->font();
        font.setPointSize(qBound(8, settings.value("appearance/treeFontSize", 10).toInt(), 24));
        browser_->tree()->setFont(font);
    }

    void editPreferences() {
        QDialog dialog(this);
        dialog.setWindowTitle(tr("Preferences"));
        QFormLayout form(&dialog);
        QSpinBox refresh_seconds, font_size;
        refresh_seconds.setRange(2, 60);
        refresh_seconds.setValue(timer_.interval() / 1000);
        font_size.setRange(8, 24);
        font_size.setValue(browser_->tree()->font().pointSize());
        form.addRow(tr("Refresh interval (seconds)"), &refresh_seconds);
        form.addRow(tr("Tree font size"), &font_size);
        QDialogButtonBox buttons(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
        form.addRow(&buttons);
        QObject::connect(&buttons, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
        QObject::connect(&buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
        if (dialog.exec() != QDialog::Accepted) {
            return;
        }
        QSettings settings;
        settings.setValue("refresh/processSeconds", refresh_seconds.value());
        settings.setValue("appearance/treeFontSize", font_size.value());
        applyPreferences();
    }

    void scanFinished() {
        const auto result = scan_watcher_.result();
        if (!result.error.isEmpty()) {
            status_->setText(tr("Scan failed — displayed data may be stale: %1").arg(result.error));
            return;
        }
        browser_->setProcesses(result.records);
        suggestions_->remember(result.records);
        status_->setText(tr("%1 user processes; %2 inaccessible entries. %3")
                             .arg(result.records.size())
                             .arg(result.inaccessible)
                             .arg(result.windows
                                      ? tr("Desktop window detection available.")
                                      : tr("No interactive window station; window detection unavailable.")));
    }

    void launchFinished() {
        start_->setEnabled(true);
#ifdef SKEWER_WINDOWS_PAIRING
        updateApplicationActions();
#endif
        const auto result = launch_watcher_.result();
        if (!result.error.isEmpty()) {
            launch_status_->setText(
                result.routed
                    ? tr("Routed launch failed before the process was released: %1").arg(result.error)
                    : tr("Launch failed: %1").arg(result.error));
        } else if (result.routed) {
            launch_status_->setText(
                tr("PID %1 is routed through Skewer (generation %2). Closing this window "
                   "does not stop it. A single-instance application may still hand off to "
                   "an older, unrouted process.")
                    .arg(result.pid)
                    .arg(result.generation));
        } else {
            launch_status_->setText(tr("Started PID %1 — NOT routed. A single-instance application may "
                                       "hand off to an existing process.")
                                        .arg(result.pid));
        }
        refresh();
    }

#ifdef SKEWER_WINDOWS_PAIRING
    void routingStateChanged(bool known, const skewer::windows::RoutingReply& state) {
        routing_known_ = known;
        routing_state_ = state;
        const bool selected = known && state.scope == skewer::windows::RoutingScope::SelectedProcess &&
                              state.selected.has_value();
        const bool retained = state.phase == skewer::windows::RoutingPhase::Starting ||
                              state.phase == skewer::windows::RoutingPhase::Active ||
                              state.phase == skewer::windows::RoutingPhase::Blocked ||
                              state.phase == skewer::windows::RoutingPhase::Stopping;
        const auto identity = selected
                                  ? QString::number(state.selected->pid) + QLatin1Char(':') +
                                        QString::number(state.selected->created)
                                  : QString{};
        browser_->setRoutingState(known, selected && retained ? identity : QString{});
        connections_->setRoutingState(known, state);
        updateRoutingSummary(known, state, selected, retained);
        updateApplicationActions();
        if (!known) {
            page_->action_status->setText(tr("Routing service unavailable; process state is unknown."));
        } else if (state.phase == skewer::windows::RoutingPhase::Failed && !state.detail.empty()) {
            page_->action_status->setText(
                tr("Routing failed: %1").arg(QString::fromUtf8(state.detail)));
        } else if (selected && retained) {
            page_->action_status->setText(
                tr("PID %1 is selected for routing (generation %2, %3).")
                    .arg(state.selected->pid)
                    .arg(state.generation)
                    .arg(state.phase == skewer::windows::RoutingPhase::Active ? tr("active")
                                                                              : tr("transitioning")));
        } else if (state.scope == skewer::windows::RoutingScope::WholeHost && retained) {
            page_->action_status->setText(
                tr("Whole-host routing is active (generation %1); see the Routing tab.")
                    .arg(state.generation));
        } else {
            page_->action_status->setText(tr("No process is individually routed."));
        }
    }

    void updateRoutingSummary(bool known, const skewer::windows::RoutingReply& state,
                              bool selected, bool retained) {
        QString text;
        QString color = QStringLiteral("#8a9199");
        if (!known) {
            text = tr("Routing unavailable");
            color = QStringLiteral("#ef5b6a");
        } else if (state.phase == skewer::windows::RoutingPhase::Blocked) {
            text = tr("Routing blocked");
            color = QStringLiteral("#ef5b6a");
        } else if (state.phase == skewer::windows::RoutingPhase::Failed) {
            text = tr("Routing failed");
            color = QStringLiteral("#ef5b6a");
        } else if (state.phase == skewer::windows::RoutingPhase::Starting ||
                   state.phase == skewer::windows::RoutingPhase::Stopping) {
            text = state.phase == skewer::windows::RoutingPhase::Starting
                       ? tr("Routing starting") : tr("Routing stopping");
            color = QStringLiteral("#d8a93f");
        } else if (state.phase == skewer::windows::RoutingPhase::Active &&
                   state.scope == skewer::windows::RoutingScope::WholeHost) {
            text = tr("Whole host routed");
            color = QStringLiteral("#41b879");
        } else if (selected && retained) {
            text = tr("PID %1 routed").arg(state.selected->pid);
            color = QStringLiteral("#41b879");
        } else {
            if (!state.tunnel_available && state.direct_available) {
                text = tr("Routing idle — Direct only");
            } else {
                text = state.paired ? tr("Routing idle") : tr("Routing needs pairing");
                if (!state.paired) color = QStringLiteral("#d8a93f");
            }
        }
        routing_status_bar_->setText(text);
        routing_status_bar_->setStyleSheet(QStringLiteral("color:%1; padding:0 6px").arg(color));
        tray_->setToolTip(tr("Skewer\n%1").arg(text));
    }

    void updateApplicationActions() {
        const bool idle = routing_known_ &&
                          (routing_state_.phase == skewer::windows::RoutingPhase::Idle ||
                           routing_state_.phase == skewer::windows::RoutingPhase::Failed);
        const bool selected = routing_known_ &&
                              routing_state_.scope == skewer::windows::RoutingScope::SelectedProcess &&
                              routing_state_.selected.has_value();
        const bool retained = routing_state_.phase == skewer::windows::RoutingPhase::Starting ||
                              routing_state_.phase == skewer::windows::RoutingPhase::Active ||
                              routing_state_.phase == skewer::windows::RoutingPhase::Blocked;
        page_->attach->setEnabled(idle && routing_state_.tunnel_available && routing_state_.paired &&
                                  browser_->selectedProcess().has_value());
        page_->release->setEnabled(selected && retained);
        if (!launch_watcher_.isRunning()) {
            routed_start_->setEnabled(idle && routing_state_.tunnel_available && routing_state_.paired);
        }
    }

    void attachSelected() {
        const auto process = browser_->selectedProcess();
        if (!process || !page_->attach->isEnabled()) {
            return;
        }
        page_->attach->setEnabled(false);
        page_->action_status->setText(
            tr("Attaching PID %1. Guarding its tree and resetting existing IPv4 TCP connections…")
                .arg(process->pid));
        routing_panel_->startSelected(
            {static_cast<DWORD>(process->pid), static_cast<std::uint64_t>(process->created)});
    }
#endif

    void browseExecutable() {
        const auto selected =
            QFileDialog::getOpenFileName(this, tr("Choose an application"), {}, tr("Programs (*.exe)"));
        if (!selected.isEmpty()) {
            path_->setText(selected);
        }
    }

    void startProgram(bool routed = false) {
        // Keep Enter blocked until the completion callback has updated the UI,
        // not merely until the worker has returned its result.
        if (!start_->isEnabled()
#ifdef SKEWER_WINDOWS_PAIRING
            || (routed && !routed_start_->isEnabled())
#endif
        ) {
            return;
        }
        const auto executable = path_->text().trimmed();
        if (executable.isEmpty()) {
            launch_status_->setText(tr("Choose an executable first."));
            return;
        }
        start_->setEnabled(false);
#ifdef SKEWER_WINDOWS_PAIRING
        routed_start_->setEnabled(false);
#endif
        if (!ResetEvent(launch_cancel_->get())) {
            launch_status_->setText(tr("Cannot reset launcher cancellation state."));
            start_->setEnabled(true);
#ifdef SKEWER_WINDOWS_PAIRING
            updateApplicationActions();
#endif
            return;
        }
        const auto service = QSettings().value("windows/routingService", "SkewerRouting").toString();
        const auto arguments = QProcess::splitCommand(arguments_->text());
        const auto environment = skewer::windows::managedRuntimeEnvironment();
#ifdef SKEWER_WINDOWS_PAIRING
        if (routed) {
            // Launch and status must address the same installed service even
            // when another process changed the persisted preference.
            routing_panel_->setServiceName(service);
        }
#endif
        launch_status_->setText(routed ? tr("Preparing routing before starting %1…").arg(executable)
                                       : tr("Starting %1 without routing…").arg(executable));
        launch_watcher_.setFuture(
            QtConcurrent::run(launch, executable, arguments, service, routed, launch_cancel_, environment));
    }

    skewer::ui::ApplicationPage* page_{};
    skewer::ui::ProcessBrowser* browser_{};
    QLineEdit* path_{};
    QLineEdit* arguments_{};
    QPushButton* start_{};
#ifdef SKEWER_WINDOWS_PAIRING
    QPushButton* routed_start_{};
    skewer::windows::RoutingPanel* routing_panel_{};
    skewer::windows::CaTrustPanel* ca_trust_{};
    QLabel* routing_status_bar_{};
    skewer::windows::ConnectionsPanel* connections_{};
    skewer::windows::RoutingReply routing_state_{};
    bool routing_known_{};
#endif
    skewer::ui::LaunchCatalog* suggestions_{};
    QLabel* launch_status_{};
    QLabel* status_{};
    QFutureWatcher<ScanResult> scan_watcher_;
    QFutureWatcher<LaunchResult> launch_watcher_;
    std::shared_ptr<skewer::windows::Handle> launch_cancel_;
    QTimer timer_;
#ifdef SKEWER_WINDOWS_PAIRING
    QLineEdit* endpoint_{};
    QLineEdit* invitation_{};
    QPushButton* pair_button_{};
    QPushButton* report_button_{};
    QLabel* report_status_{};
    QLabel* paired_status_{};
    QPushButton* open_saslik_{};
    QPushButton* open_spider_{};
    QTimer report_timer_;
    QFutureWatcher<QString> report_watcher_;
    QFutureWatcher<QPair<QString, QString>> pairing_watcher_;
    QFutureWatcher<PairedStatusResult> paired_status_watcher_;
#endif
};
} // namespace

int main(int argc, char** argv) {
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--version") == 0) {
            std::printf("Skewer %s\n", SKEWER_VERSION);
            return 0;
        }
        if (std::strcmp(argv[i], "--gui") != 0) {
            std::fprintf(stderr, "Unsupported Windows command. Available: --gui, --version\n");
            return 2;
        }
    }
    QApplication app(argc, argv);
    app.setOrganizationName("Saslik");
    app.setApplicationName("Skewer");
    app.setApplicationVersion(SKEWER_VERSION);
    const auto state = QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation);
    if (!QDir().mkpath(state)) {
        QMessageBox::critical(nullptr, "Skewer", "Cannot create application state directory.");
        return 1;
    }

    // Scope both the lock and activation pipe to this user's state directory.
    const auto socket_name =
        QStringLiteral("skewer-gui-") +
        QString::fromLatin1(QCryptographicHash::hash(state.toUtf8(), QCryptographicHash::Sha256).toHex());
    QLockFile lock(state + "/gui.lock");
    lock.setStaleLockTime(0);
    if (!lock.tryLock(100)) {
        QLocalSocket peer;
        peer.connectToServer(socket_name);
        if (peer.waitForConnected(1500)) {
            peer.disconnectFromServer();
            return 0;
        }
        QMessageBox::warning(nullptr, "Skewer", "Skewer is already running but could not be activated.");
        return 1;
    }
    QLocalServer server;
    server.setSocketOptions(QLocalServer::UserAccessOption);
    if (!server.listen(socket_name)) {
        QMessageBox::critical(nullptr, "Skewer", server.errorString());
        return 1;
    }
    WindowsWindow window;
    QObject::connect(&server, &QLocalServer::newConnection, &window, [&] {
        while (auto* peer = server.nextPendingConnection()) {
            peer->close();
            peer->deleteLater();
        }
        window.showNormal();
        window.raise();
        window.activateWindow();
    });
    window.show();
    window.refresh();
    return app.exec();
}
