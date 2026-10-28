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
#ifdef SKEWER_WINDOWS_PAIRING
#include "client_report.hpp"
#include "routing_panel.hpp"
#include "routed_launch.hpp"
#include <QSettings>
#include <QDateTime>
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
LaunchResult launch(const QString& executable, const QString& service, bool routed,
                    const std::shared_ptr<skewer::windows::Handle>& cancel) {
    try {
        if (routed) {
            const auto result = skewer::windows::launchRouted(service.toStdWString(),
                                                              executable.toStdWString(), {}, cancel->get());
            skewer::windows::Handle thread(result.process.hThread), handle(result.process.hProcess);
            return {result.identity.pid, result.generation, true, {}};
        }
        const auto process = skewer::windows::launch(executable.toStdWString(), {});
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
        report_watcher_.waitForFinished();
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
                          "This build does not report certificate-store installation status."),
                       page);
        explanation->setWordWrap(true);
        layout->addWidget(explanation);
        endpoint_ = new QLineEdit(QSettings().value("windows/saslikEndpoint").toString(), page);
        endpoint_->setPlaceholderText("skewer://HOST:8766/pair (already paired endpoint)");
        layout->addWidget(endpoint_);
        report_button_ = new QPushButton(tr("Start reporting"), page);
        layout->addWidget(report_button_);
        report_status_ = new QLabel(tr("Not reporting. Pair first using skewer-control pair - ."), page);
        report_status_->setWordWrap(true);
        layout->addWidget(report_status_);
        layout->addStretch();
        pages()->addTab(page, tr("Saslik"));
        report_timer_.setInterval(10000);
        connect(&report_timer_, &QTimer::timeout, this, &WindowsWindow::sendReport);
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
            report_status_->setText(tr("Report accepted at %1. Routing status is independent.")
                                        .arg(QDateTime::currentDateTime().toString("HH:mm:ss")));
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
#endif
    void buildPage() {
        page_ = new skewer::ui::ApplicationPage(this);
        pages()->addTab(page_, tr("Applications"));
        addUnavailablePage(tr("CA Trust"), tr("Windows certificate-store management is not implemented yet. "
                                              "No certificates are installed or changed by this build."));
        addUnavailablePage(tr("Runtime Trust"),
                           tr("Application-specific trust integration is not available on Windows yet."));
        addUnavailablePage(tr("Connections"),
                           tr("Windows per-process connection inspection is not available yet."));

        auto* disclaimer = new QLabel(tr("Launch through Skewer starts one new process suspended and "
                                         "releases it only after routing is ready. "
                                         "Existing instances, descendants, UDP and IPv6 are not routed yet. "
                                         "Whole-host routing is controlled on the Routing tab."),
                                      page_);
        disclaimer->setWordWrap(true);
        page_->top->addWidget(disclaimer);
        browser_ = new skewer::ui::ProcessBrowser(page_, page_->tree);
        page_->setProcessWidget(browser_);
        connect(page_->search, &QLineEdit::textChanged, browser_, &skewer::ui::ProcessBrowser::setFilterText);
        page_->action_status->setText(tr("Checking authoritative routing state…"));
        page_->attach->setEnabled(false);
        page_->attach->setToolTip(tr("Attaching an already running process is not implemented yet."));
        page_->release->setEnabled(false);
        page_->release->setToolTip(tr("Stop the currently selected-process routing session."));
#ifdef SKEWER_WINDOWS_PAIRING
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
            tr("Find a seen application by name, or enter an executable path (no arguments yet)…"));
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
        routed_start_->setEnabled(true);
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
        page_->release->setEnabled(selected && retained &&
                                   state.phase != skewer::windows::RoutingPhase::Stopping);
        if (!known) {
            page_->action_status->setText(tr("Routing service unavailable; process state is unknown."));
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
            || !routed_start_->isEnabled()
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
            routed_start_->setEnabled(true);
#endif
            return;
        }
        const auto service = QSettings().value("windows/routingService", "SkewerRouting").toString();
#ifdef SKEWER_WINDOWS_PAIRING
        if (routed) {
            // Launch and status must address the same installed service even
            // when another process changed the persisted preference.
            routing_panel_->setServiceName(service);
        }
#endif
        launch_status_->setText(routed ? tr("Preparing routing before starting %1…").arg(executable)
                                       : tr("Starting %1 without routing…").arg(executable));
        launch_watcher_.setFuture(QtConcurrent::run(launch, executable, service, routed, launch_cancel_));
    }

    skewer::ui::ApplicationPage* page_{};
    skewer::ui::ProcessBrowser* browser_{};
    QLineEdit* path_{};
    QPushButton* start_{};
#ifdef SKEWER_WINDOWS_PAIRING
    QPushButton* routed_start_{};
    skewer::windows::RoutingPanel* routing_panel_{};
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
    QPushButton* report_button_{};
    QLabel* report_status_{};
    QTimer report_timer_;
    QFutureWatcher<QString> report_watcher_;
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
