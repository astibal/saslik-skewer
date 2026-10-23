#include "main_window.hpp"
#include "routing_guard.hpp"
#include "privileged_session.hpp"
#include "interface_routing.hpp"
#include "launcher.hpp"
#include "pairing.hpp"
#include "portal_trust.hpp"
#include "connections.hpp"
#include <QInputDialog>
#include <QScrollBar>
#include <QScrollArea>
#include <QFutureWatcher>
#include <QtConcurrent>

#include "application_model.hpp"
#include "ca_store.hpp"
#include "ca_panel.hpp"
#include "routing_plan.hpp"
#include <QDialogButtonBox>
#include <QPlainTextEdit>
#include <QRegularExpression>
#include <QStandardPaths>
#include "runtime_trust.hpp"
#include <QTabWidget>

#include <QApplication>
#include <QAction>
#include <QMenuBar>
#include <QMenu>
#include <QSystemTrayIcon>
#include <QPainter>
#include <QCompleter>
#include <QCloseEvent>
#include <QComboBox>
#include <QDateTime>
#include <QDesktopServices>
#include <QDialog>
#include <QDir>
#include <QFileDialog>
#include <QGroupBox>
#include <QHeaderView>
#include <QGridLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QJsonDocument>
#include <QJsonArray>
#include <QJsonObject>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QProcess>
#include <QPushButton>
#include <QSortFilterProxyModel>
#include <QSettings>
#include <QStatusBar>
#include <QStringListModel>
#include <QTimer>
#include <QTemporaryFile>
#include <QToolButton>
#include <QPointer>
#include <QHostAddress>
#include <QHostInfo>
#include <QUrlQuery>
#include <QTreeView>
#include <QVBoxLayout>

MainWindow::MainWindow(const QString& connect_url, QWidget* parent,
                       std::function<RoutingResult()> resume_routing)
    : QMainWindow(parent)
{
    setWindowTitle(tr("Skewer"));
    resize(980, 680);
    QSettings settings;
    restoreGeometry(settings.value(QStringLiteral("window/geometry")).toByteArray());
    auto* settings_menu = menuBar()->addMenu(tr("Settings"));
    close_to_tray_ = settings_menu->addAction(tr("Close to system tray"));
    close_to_tray_->setObjectName("closeToTray");
    close_to_tray_->setCheckable(true);
    close_to_tray_->setChecked(settings.value(QStringLiteral("window/closeToTray"), true).toBool());
    connect(close_to_tray_, &QAction::toggled, this, [](bool enabled) {
        QSettings().setValue(QStringLiteral("window/closeToTray"), enabled);
    });
    tray_ = new QSystemTrayIcon(this);
    tray_->setObjectName("skewerTray");
    tray_->setToolTip(tr("Skewer"));
    auto* tray_menu = new QMenu(this);
    const auto restore = [this] { showNormal(); raise(); activateWindow(); };
    connect(tray_menu->addAction(tr("Show Skewer")), &QAction::triggered, this, restore);
    tray_menu->addSeparator();
    const auto quit = [this] {
        // Exiting the UI never releases applications or disables routing.
        quitting_ = true;
        close();
        QApplication::quit();
    };
    connect(tray_menu->addAction(tr("Quit")), &QAction::triggered, this, quit);
    connect(settings_menu->addAction(tr("Quit")), &QAction::triggered, this, quit);
    tray_->setContextMenu(tray_menu);
    connect(tray_, &QSystemTrayIcon::activated, this, [restore](QSystemTrayIcon::ActivationReason reason) {
        if (reason == QSystemTrayIcon::Trigger || reason == QSystemTrayIcon::DoubleClick) restore();
    });
    updateTrayIcon();
    tray_->show();

    auto* central = new QWidget(this);
    auto* tabs = new QTabWidget(this);
    auto* ca_panel = ca_panel_ = new CaTrustPanel(tabs);
    auto* runtime_trust = new RuntimeTrustPanel(tabs);
    tabs->addTab(central, tr("Applications"));
    tabs->addTab(ca_panel, tr("CA Trust"));
    tabs->addTab(runtime_trust, tr("Runtime Trust"));
    connect(runtime_trust, &RuntimeTrustPanel::selectCertificateRequested, this,
            [tabs, ca_panel] { tabs->setCurrentWidget(ca_panel); });
    connect(ca_panel, &CaTrustPanel::certificateChanged,
            runtime_trust, &RuntimeTrustPanel::setCertificate);
    auto* layout = new QVBoxLayout(central);
    layout->setContentsMargins(18, 18, 18, 14);
    layout->setSpacing(10);

    auto* title = new QLabel(tr("Skewer applications through Saslik"), central);
    QFont title_font = title->font();
    title_font.setPointSize(title_font.pointSize() + 5);
    title_font.setBold(true);
    title->setFont(title_font);
    layout->addWidget(title);

    search_ = new QLineEdit(central);
    search_->setPlaceholderText(tr("Find an application or process…"));
    search_->setClearButtonEnabled(true);
    layout->addWidget(search_);

    auto* routing_box = new QGroupBox(tr("Routing"), central);
    auto* routing_layout = new QHBoxLayout(routing_box);
    routing_source_ = new QComboBox(routing_box);
    routing_source_->addItem(tr("Set gateway"), QStringLiteral("gateway"));
    routing_source_->addItem(tr("Saslik URL"), QStringLiteral("saslik"));
    next_hop_ = new QLineEdit(routing_box);
    next_hop_->setPlaceholderText(tr("Directly reachable next-hop IPv4 address"));
    QSettings initial_settings;
    saslik_disconnected_ = initial_settings.value("saslik/disconnected", false).toBool();
    next_hop_->setText(initial_settings.value(QStringLiteral("routing/nextHop")).toString());
    saslik_url_ = new QLineEdit(routing_box);
    saslik_url_->setPlaceholderText(tr("http://127.0.0.1:8765/api/skewer"));
    saslik_url_->setText(initial_settings.value(QStringLiteral("routing/saslikUrl")).toString());
    routing_source_->setCurrentIndex(
        initial_settings.value(QStringLiteral("routing/mode")) == QStringLiteral("saslik") ? 1 : 0);
    routing_requested_ = initial_settings.value(QStringLiteral("routing/requested"), false).toBool();
    routing_up_ = new QPushButton(tr("Enable"), routing_box);
    routing_down_ = new QPushButton(tr("Disable"), routing_box);
    routing_status_ = new QLabel(routing_box);
    routing_status_->setObjectName(QStringLiteral("routingStatus"));
    routing_layout->addWidget(routing_source_);
    routing_layout->addWidget(next_hop_, 1);
    routing_layout->addWidget(saslik_url_, 1);
    routing_layout->addWidget(routing_up_);
    routing_layout->addWidget(routing_down_);
    routing_layout->addWidget(routing_status_);
    layout->addWidget(routing_box);
    auto* pair_button = new QPushButton(tr("Pair with Saslik…"),central);
    routing_layout->insertWidget(routing_layout->indexOf(routing_up_), pair_button);
    const auto begin_pairing = [this,pair_button](const QString& address) {
        if (address.isEmpty() || !pair_button->isEnabled()) return;
        QUrl endpoint(address); endpoint.setFragment({});
        if (endpoint.scheme()!="skewer" || endpoint.path()!="/pair") {
            QMessageBox::warning(this,tr("Pairing"),tr("Invalid pairing address."));return;
        }
        pair_button->setEnabled(false);
        auto* process = new QProcess(this);
        connect(process,&QProcess::started,this,[process,address] {process->write(address.toUtf8()+'\n');process->closeWriteChannel();});
        connect(process,qOverload<int,QProcess::ExitStatus>(&QProcess::finished),this,
            [this,process,pair_button,endpoint](int code,QProcess::ExitStatus status) {
                pair_button->setEnabled(true);
                if (!code && status==QProcess::NormalExit) {
                    saslik_disconnected_ = false;
                    ++saslik_epoch_;
                    QSettings().setValue("saslik/disconnected", false);
                    if (auto* button = findChild<QPushButton*>("saslikConnection")) button->setText(tr("Disconnect"));
                    saslik_url_->setText(endpoint.toString());
                    QSettings().setValue("routing/saslikUrl",endpoint.toString());
                    QSettings().setValue("routing/mode","saslik");
                    routing_source_->setCurrentIndex(1);
                    pollSaslik();
                    QMessageBox::information(this,tr("Pairing"),tr("Paired using TLS 1.3 PSK. No plaintext fallback."));
                } else QMessageBox::warning(this,tr("Pairing"),tr("Pairing failed. Check the invitation and endpoint. If confirmation was interrupted, retry the same address."));
                process->deleteLater();
            });
        connect(process,&QProcess::errorOccurred,this,[process,pair_button](QProcess::ProcessError error) {
            if (error==QProcess::FailedToStart) {pair_button->setEnabled(true);process->deleteLater();}
        });
        QTimer::singleShot(20000,process,[process] {if(process->state()!=QProcess::NotRunning)process->kill();});
        process->start(QCoreApplication::applicationFilePath(),{"pair","-"});
    };
    connect(pair_button,&QPushButton::clicked,this,[this,begin_pairing] {
        bool accepted = false;
        const QString address = QInputDialog::getText(this,tr("Pair with Saslik"),
            tr("Paste the skewer:// pairing address. It contains a secret; do not share it."),
            QLineEdit::Password,{},&accepted);
        if (accepted) begin_pairing(address);
    });
    connect(saslik_url_,&QLineEdit::textChanged,this,[this,begin_pairing](const QString& address) {
        QUrl endpoint(address);
        if (endpoint.scheme()!="skewer" || !endpoint.hasFragment()) return;
        endpoint.setFragment({});
        { QSignalBlocker blocker(saslik_url_); saslik_url_->setText(endpoint.toString()); }
        // Consume the invitation before settings or discovery can see its secret fragment.
        QTimer::singleShot(0,this,[begin_pairing,address] {begin_pairing(address);});
    });
    auto* exemptions = new QPushButton(tr("Destination exemptions…"), central);
    exemptions->setObjectName("destinationExemptions");
    connect(exemptions, &QPushButton::clicked, this, [this] {
        QDialog dialog(this);
        dialog.setWindowTitle(tr("Destination exemptions"));
        dialog.resize(560, 360);
        auto* content = new QVBoxLayout(&dialog);
        auto* explanation = new QLabel(tr("These destinations bypass Skewer marking and use the host's normal routing, "
            "for all attached applications. Enter IPv4 addresses or CIDR networks, one per line. "
            "No DNS names. Existing connections may break when their route changes; reconnect them. "
            "An empty list removes all exceptions. 0.0.0.0/0 bypasses everything. "
            "IPv6 is not routed by Skewer."), &dialog);
        explanation->setWordWrap(true); content->addWidget(explanation);
        auto* editor = new QPlainTextEdit(&dialog);
        editor->setPlaceholderText("203.0.113.7\n192.168.0.0/16");
        editor->setPlainText(QSettings().value("routing/exemptions").toStringList().join('\n'));
        content->addWidget(editor);
        auto* error = new QLabel(&dialog); error->setWordWrap(true); error->setTextFormat(Qt::PlainText);
        content->addWidget(error);
        auto* buttons = new QDialogButtonBox(QDialogButtonBox::Save | QDialogButtonBox::Cancel, &dialog);
        content->addWidget(buttons);
        connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
        connect(buttons, &QDialogButtonBox::accepted, &dialog, [&, this] {
            QStringList normalized; QString detail;
            const auto entries = editor->toPlainText().split(QRegularExpression("[\\s,]+"), Qt::SkipEmptyParts);
            if (!RoutingPlanner::normalizeExemptions(entries, normalized, detail)) { error->setText(detail); return; }
            if (!InterfaceRouting::state(getuid()).isEmpty()) {
                error->setText(tr("Release interfaces before changing destination exemptions.")); return;
            }
            if (routing_.active(currentNextHop())) {
                const auto result = routing_.updateExemptions(normalized, RoutingController::Authorization::Desktop);
                if (!result.ok) { error->setText(result.detail); return; }
            }
            QSettings().setValue("routing/exemptions", normalized);
            action_status_->setText(tr("Saved %1 destination exemptions.").arg(normalized.size()));
            dialog.accept();
        });
        dialog.exec();
    });
    // Status requests are deliberately independent of discovery and routing.
    auto* info_toggle = new QToolButton(central);
    info_toggle->setText(tr("Saslik"));
    info_toggle->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
    info_toggle->setArrowType(Qt::RightArrow);
    info_toggle->setCheckable(true);
    auto* tools_row = new QHBoxLayout;
    tools_row->addWidget(info_toggle);
    tools_row->addStretch();
    tools_row->addWidget(exemptions);
    layout->addLayout(tools_row);
    auto* info = new QWidget(central);
    auto* info_layout = new QVBoxLayout(info);
    info_layout->setContentsMargins(8, 0, 8, 0);
    auto* info_url = new QLineEdit(info);
    info_url->setObjectName(QStringLiteral("saslikInfoUrl"));
    info_url->setPlaceholderText(tr("Saslik URL: skewer://host:8766/pair or https://host:8765"));
    info_url->setText(settings.value(QStringLiteral("saslik/statusUrl"),
                                    saslik_url_->text()).toString());
    info_layout->addWidget(info_url);
    auto* info_text = new QLabel(tr("Enter the Saslik URL to load status."), info);
    info_text->setObjectName(QStringLiteral("saslikInfoText"));
    info_text->setTextFormat(Qt::PlainText);
    info_text->setWordWrap(false);
    info_text->setAlignment(Qt::AlignLeft | Qt::AlignTop);
    info_text->setMargin(8);
    info_text->setTextInteractionFlags(Qt::TextSelectableByMouse);
    auto* status_box = new QScrollArea(info);
    status_box->setObjectName(QStringLiteral("saslikStatusBox"));
    status_box->setWidgetResizable(true);
    status_box->setFrameShape(QFrame::StyledPanel);
    // The status owns its scrollbars; polling must never resize the window or
    // push the process tree around when a response has more or fewer lines.
    status_box->setFixedHeight(info_text->fontMetrics().lineSpacing() * 8 + 24);
    status_box->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    status_box->setWidget(info_text);
    info_layout->addWidget(status_box);
    auto* links = new QHBoxLayout;
    auto* open_lab = new QPushButton(tr("Open Saslik"), info);
    auto* open_spider = new QPushButton(tr("Spider"), info);
    auto* download_ca = new QPushButton(tr("Manage CA trust"), info);
    for (auto* button : {open_lab, open_spider, download_ca}) {
        button->setEnabled(false);
        links->addWidget(button);
    }
    for (auto* button : {open_lab, open_spider}) {
        connect(button, &QPushButton::clicked, this, [button] {
            const QUrl url(button->property("targetUrl").toString());
            if (url.scheme() == "http" || url.scheme() == "https")
                QDesktopServices::openUrl(url);
        });
    }
    links->addStretch();
    info_layout->addLayout(links);
    layout->addWidget(info);
    info->hide();
    connect(info_toggle, &QToolButton::toggled, info, [info, info_toggle](bool expanded) {
        info->setVisible(expanded);
        info_toggle->setArrowType(expanded ? Qt::DownArrow : Qt::RightArrow);
    });
    auto* status_network = new QNetworkAccessManager(info);
    report_network_ = new QNetworkAccessManager(this);
    installPortalTrust(status_network, this);
    installPortalTrust(report_network_, this);
    connect(ca_panel, &CaTrustPanel::trustReportReady, this,
            [this](const QJsonObject& trust) {
        trust_report_ = trust;
        sendTrustReport();
    });
    struct StatusState {
        bool paired_pending{};
        QPointer<QNetworkReply> pending;
        QString source;
        QString last_success;
        QString summary;
        QString identity;
    };
    auto status = std::make_shared<StatusState>();
    connect(download_ca, &QPushButton::clicked, this, [tabs, ca_panel] { tabs->setCurrentWidget(ca_panel); });
    const auto poll_status = [=, this] {
        if (saslik_disconnected_) {
            if (status->pending) status->pending->abort();
            info_text->setText(tr("Disconnected from Saslik. Pairing and known CAs are retained."));
            for (auto* button : {open_lab, open_spider, download_ca}) button->setEnabled(false);
            return;
        }
        const auto epoch = saslik_epoch_;
        const QString source = info_url->text().trimmed();
        if (source != status->source) {
            status->source = source;
            status->last_success.clear();
            status->summary.clear();
            for (auto* button : {open_lab, open_spider, download_ca}) button->setEnabled(false);
            if (status->pending) status->pending->abort();
        }
        if (status->pending) return;
        QUrl base(source);
        if (base.scheme() == "skewer") {
            if (status->paired_pending) return;
            if (base.host().isEmpty() || base.path() != "/pair" || base.hasFragment()) {
                info_text->setText(tr("Use a paired skewer://host:port/pair address. Paste invitations into Pair with Saslik instead."));
                return;
            }
            status->paired_pending = true;
            // Keep the last result visible throughout a background refresh.
            using Result = QPair<QJsonObject, QString>;
            auto* check = new QFutureWatcher<Result>(info);
            connect(check, &QFutureWatcher<Result>::finished, info, [=, this] {
                status->paired_pending = false;
                const auto result = check->result(); check->deleteLater();
                if (epoch != saslik_epoch_ || saslik_disconnected_ || source != info_url->text().trimmed()) return;
                if (!result.second.isEmpty()) {
                    info_text->setText(tr("Authenticated connection unavailable: %1").arg(result.second));
                    return;
                }
                const auto value = result.first;
                if (!value["ca_pem"].toString().isEmpty())
                    ca_panel->setRemoteCertificate(value["ca_pem"].toString().toUtf8());
                const auto detail = value["lab_status"].toObject();
                const auto proxy = detail["services"].toObject()["smithproxy"].toObject();
                QStringList checks;
                const auto e2e = detail["end_to_end"].toObject();
                const auto check_values = e2e["checks"].toObject();
                for (auto it = check_values.begin(); it != check_values.end(); ++it)
                    checks << it.key() + ": " + it.value().toObject()["state"].toString(tr("unknown"));
                info_text->setText(tr("Authenticated via TLS-PSK\nWorkspace: %1 · lab ingress: %2\nGateway: %3 · interface: %4\nCA: %5")
                    .arg(value["workspace"].toString(), value["available"].toBool() ? tr("available") : tr("unavailable"),
                         value["gateway"].toString(), value["host_interface"].toString(),
                         value["ca_pem"].toString().isEmpty() ? value["ca_error"].toString(tr("not supplied by server")) : tr("downloaded; see CA Trust"))
                    + tr("\nLab: %1 · Smithproxy: %2 · PID: %3\nInternet: %4%5\nUpdated: %6")
                        .arg(detail["runtime_state"].toString(tr("unknown")), proxy["state"].toString(tr("unknown")),
                             proxy["pid"].isDouble() ? QString::number(proxy["pid"].toInt()) : QStringLiteral("—"),
                             checks.isEmpty() ? tr("not measured") : checks.join(" · "),
                             e2e["stale"].toBool() ? tr(" (stale)") : QString{}, QDateTime::currentDateTime().toString(Qt::ISODate)));
                QUrl web;
                web.setScheme("https"); web.setHost(base.host()); web.setPort(value["ui_port"].toInt(-1)); web.setPath("/");
                const auto set_web_link = [base](QPushButton* button, QUrl url) {
                    if (QHostAddress(url.host()).isLoopback() || url.host() == "localhost") url.setHost(base.host());
                    const bool valid = !url.host().isEmpty() && (url.scheme() == "http" || url.scheme() == "https");
                    button->setProperty("targetUrl", valid ? url.toString() : QString{});
                    button->setEnabled(valid); button->setToolTip(valid ? url.toDisplayString() : QString{});
                };
                set_web_link(open_lab, value["ui_port"].toInt() > 0 ? web : QUrl{});
                const auto spider = detail["endpoints"].toObject()["spider_ui"].toString();
                set_web_link(open_spider, spider.isEmpty() ? QUrl{} : web.resolved(QUrl(spider)));
                download_ca->setEnabled(!value["ca_pem"].toString().isEmpty());
            });
            // Never downgrade a paired endpoint to the plaintext HTTP API.
            check->setFuture(QtConcurrent::run([base]() -> Result {
                try { return {pairedStatus(base), {}}; }
                catch (const std::exception& error) { return {{}, QString::fromUtf8(error.what())}; }
            }));
            return;
        }
        if (!base.isValid() || base.host().isEmpty() || base.scheme() != "https") {
            info_text->setText(tr("Enter a valid HTTPS or paired skewer:// Saslik URL."));
            return;
        }
        // Accept either the UI URL or the existing /api/skewer discovery URL.
        base.setPath(QStringLiteral("/"));
        base.setQuery(QString{});
        base.setFragment(QString{});
        QNetworkRequest request(base.resolved(QUrl(QStringLiteral("api/status"))));
        request.setTransferTimeout(5000);
        auto* reply = status_network->get(request);
        status->pending = reply;
        connect(reply, &QNetworkReply::finished, info, [=, this] {
            status->pending.clear();
            reply->deleteLater();
            if (epoch != saslik_epoch_ || saslik_disconnected_ || source != info_url->text().trimmed()) return;
            QJsonParseError error;
            const auto document = QJsonDocument::fromJson(reply->readAll(), &error);
            const auto value = document.object();
            if (reply->error() != QNetworkReply::NoError
                || error.error != QJsonParseError::NoError
                || !value.contains(QStringLiteral("runtime_state"))) {
                info_text->setText(tr("Unavailable · last success: %1\n%2")
                    .arg(status->last_success.isEmpty() ? tr("never") : status->last_success,
                         status->summary));
                return;
            }
            const auto proxy = value["services"].toObject()["smithproxy"].toObject();
            status->identity = value["identity"].toString(value["instance"].toString());
            const auto e2e = value["health"].toObject()["end_to_end"].toObject();
            QStringList checks;
            const auto check_values = e2e["checks"].toObject();
            for (auto it = check_values.begin(); it != check_values.end(); ++it)
                checks << it.key() + ": " + it.value().toObject()["state"].toString(tr("unknown"));
            const QString sampled = e2e["sampled_at"].isDouble()
                ? QDateTime::fromSecsSinceEpoch(static_cast<qint64>(e2e["sampled_at"].toDouble()))
                    .toString(Qt::ISODate) : tr("unknown");
            status->summary = tr("Workspace: %1 · lab: %2\nSmithproxy: %3 · PID: %4\nInternet: %5\nProbe sample: %6%7")
                .arg(value["identity"].toString(value["instance"].toString()),
                     value["runtime_state"].toString(), proxy["state"].toString(tr("unknown")),
                     proxy["pid"].isDouble() ? QString::number(proxy["pid"].toInt()) : QStringLiteral("—"),
                     checks.isEmpty() ? tr("not measured") : checks.join(QStringLiteral(" · ")),
                     sampled, e2e["stale"].toBool() ? tr(" (stale)") : QString{});
            status->last_success = QDateTime::currentDateTime().toString(Qt::ISODate);
            info_text->setText(status->summary + tr("\nUpdated: %1").arg(status->last_success));
            const auto endpoints = value["endpoints"].toObject();
            const auto set_link = [base](QPushButton* button, const QString& target) {
                QUrl url = target.isEmpty() ? QUrl{} : base.resolved(QUrl(target));
                // A remote server's loopback address refers to that server, not this client.
                if (QHostAddress(url.host()).isLoopback() || url.host() == "localhost")
                    url.setHost(base.host());
                const bool valid = url.isValid() && !url.host().isEmpty()
                    && (url.scheme() == "http" || url.scheme() == "https");
                button->setProperty("targetUrl", valid ? url.toString() : QString{});
                button->setEnabled(valid);
                button->setToolTip(valid ? url.toDisplayString() : QString{});
            };
            set_link(open_lab, base.toString());
            set_link(open_spider, endpoints["spider_ui"].toString());
            set_link(download_ca, endpoints["ca_download"].toString());
            ca_panel->setSource(QUrl(download_ca->property("targetUrl").toString()));
        });
    };
    auto* status_timer = new QTimer(info);
    status_timer->setInterval(10000);
    connect(status_timer, &QTimer::timeout, info, poll_status);
    connect(info_url, &QLineEdit::editingFinished, info, [=] {
        QSettings().setValue(QStringLiteral("saslik/statusUrl"), info_url->text().trimmed());
        poll_status();
    });
    connect(info_toggle, &QToolButton::toggled, info, [=](bool expanded) {
        if (expanded) poll_status();
    });
    status_timer->start();
    auto* connection_button = new QPushButton(central);
    connection_button->setObjectName("saslikConnection");
    links->addWidget(connection_button);
    const auto connection_label = [this, connection_button] {
        connection_button->setText(saslik_disconnected_ ? tr("Reconnect") : tr("Disconnect"));
    };
    connection_label();
    connect(connection_button, &QPushButton::clicked, this, [=, this] {
        if (!saslik_disconnected_ && (routing_requested_ || routing_.active(currentNextHop()))) {
            deactivateRouting();
            if (routing_requested_ || routing_.active(currentNextHop())) return;
        }
        saslik_disconnected_ = !saslik_disconnected_;
        ++saslik_epoch_;
        QSettings().setValue("saslik/disconnected", saslik_disconnected_);
        if (saslik_disconnected_) {
            saslik_reachable_ = false;
            discovery_online_ = false;
            discovery_gateway_.clear();
            discovery_warning_.clear();
            ca_panel_->disconnectAndOfferRemoval();
        } else pollSaslik();
        connection_label();
        poll_status();
        updateRoutingStatus();
    });
    QTimer::singleShot(0, info, poll_status);
    connect(routing_up_, &QPushButton::clicked, this, &MainWindow::activateRouting);
    connect(routing_down_, &QPushButton::clicked, this, &MainWindow::deactivateRouting);
    routing_status_bar_ = new QLabel(this);
    statusBar()->addPermanentWidget(routing_status_bar_);
    connect(routing_source_, &QComboBox::currentIndexChanged,
            this, &MainWindow::updateRoutingSource);
    network_ = new QNetworkAccessManager(this);
    installPortalTrust(network_, this);
    connect(network_, &QNetworkAccessManager::finished, this, &MainWindow::receiveSaslik);
    openConnectUrl(connect_url);
    updateRoutingSource();
    routing_watchdog_ = new QTimer(this);
    routing_watchdog_->setInterval(5000);
    connect(routing_watchdog_, &QTimer::timeout, this, [this] {
        if (usesSaslikUrl()) pollSaslik();
        updateRoutingStatus();
    });
    routing_watchdog_->start();
    if (usesSaslikUrl()) pollSaslik();
    updateRoutingStatus();

    model_ = new ApplicationModel(this);
    tabs->addTab(new ConnectionsPanel(model_, tabs), tr("Connections"));
    connect(ca_panel, &CaTrustPanel::caStatusChanged, model_, &ApplicationModel::setCaStatus);
    filtered_model_ = new QSortFilterProxyModel(this);
    filtered_model_->setSourceModel(model_);
    filtered_model_->setRecursiveFilteringEnabled(true);
    filtered_model_->setFilterCaseSensitivity(Qt::CaseInsensitive);
    filtered_model_->setFilterKeyColumn(-1);

    tree_ = new QTreeView(central);
    tree_->setModel(filtered_model_);
    tree_->setAlternatingRowColors(true);
    tree_->setUniformRowHeights(true);
    tree_->setSortingEnabled(true);
    tree_->sortByColumn(ApplicationModel::NameColumn, Qt::AscendingOrder);
    tree_->header()->setSectionResizeMode(QHeaderView::Interactive);
    tree_->header()->setStretchLastSection(false);
    tree_->setColumnWidth(ApplicationModel::NameColumn, 280);
    tree_->setColumnWidth(ApplicationModel::ProcessIdColumn, 85);
    tree_->setColumnWidth(ApplicationModel::RoutingColumn, 150);
    tree_->setColumnWidth(ApplicationModel::CaColumn, 150);
    tree_->setColumnWidth(ApplicationModel::CommandColumn, 500);
    tree_->setColumnWidth(ApplicationModel::ConnectionsColumn, 90);
    layout->addWidget(tree_, 1);

    auto* actions = new QHBoxLayout;
    action_status_ = new QLabel(tr("Select an application to manage its routing."), central);
    action_status_->setObjectName(QStringLiteral("actionStatus"));
    route_button_ = new QPushButton(tr("Attach to Skewer"), central);
    release_button_ = new QPushButton(tr("Release"), central);
    route_button_->setEnabled(false);
    release_button_->setEnabled(false);
    actions->addWidget(action_status_, 1);
    actions->addWidget(release_button_);
    actions->addWidget(route_button_);
    layout->addLayout(actions);
    connect(tree_->selectionModel(), &QItemSelectionModel::currentChanged,
            this, &MainWindow::updateSelection);
    connect(route_button_, &QPushButton::clicked, this, &MainWindow::routeSelection);
    connect(release_button_, &QPushButton::clicked, this, &MainWindow::releaseSelection);

    connect(model_, &QAbstractItemModel::modelAboutToBeReset,
            this, &MainWindow::rememberExpandedItems);
    connect(model_, &QAbstractItemModel::modelReset,
            this, &MainWindow::restoreExpandedItems);
    connect(model_, &ApplicationModel::processesChanged, this, &MainWindow::updateSelection);
    tree_->expandToDepth(0);

    connect(search_, &QLineEdit::textChanged, filtered_model_,
            &QSortFilterProxyModel::setFilterFixedString);

    layout->addWidget(new Launcher(central));
    auto* launcher = new QHBoxLayout;
    auto* shell_button = new QPushButton(tr("Shell…"), central);
    launcher->addWidget(shell_button);
    connect(shell_button, &QPushButton::clicked, this, [this] {
        const auto invocation = CgroupManager::routedLaunchPrefix("shell", true);
        QStringList terminals{"xdg-terminal-exec", "x-terminal-emulator", "konsole", "gnome-terminal", "xfce4-terminal"};
        const auto desktop = qEnvironmentVariable("XDG_CURRENT_DESKTOP");
        // Prefer the desktop's native terminal over a generic dispatcher which
        // can still be configured to use xterm on an otherwise KDE desktop.
        if (desktop.contains("KDE", Qt::CaseInsensitive)) terminals.prepend("konsole");
        else if (desktop.contains("GNOME", Qt::CaseInsensitive)) terminals.prepend("gnome-terminal");
        else if (desktop.contains("XFCE", Qt::CaseInsensitive)) terminals.prepend("xfce4-terminal");
        terminals.removeDuplicates();
        for (const auto& name : terminals) {
            const QString terminal = QStandardPaths::findExecutable(name);
            if (terminal.isEmpty()) continue;
            QStringList arguments;
            if (name == "gnome-terminal") arguments << "--";
            else if (name == "xfce4-terminal") arguments << "-x";
            else if (name != "xdg-terminal-exec") arguments << "-e";
            arguments.append(invocation);
            if (QProcess::startDetached(terminal, arguments)) {
                action_status_->setText(tr("Opening Skewer shell…")); return;
            }
        }
        QMessageBox::information(this, tr("Skewer shell"), tr("No supported terminal could be started. Run skewer shell in your terminal."));
    });
    layout->addLayout(launcher);

    auto* note = new QLabel(
        tr("Attaching a running application only affects newly created sockets. "
           "For reliable routing, launch the application through Skewer."),
        central);
    note->setWordWrap(true);
    note->setObjectName(QStringLiteral("routingNote"));
    layout->addWidget(note);

    setCentralWidget(tabs);
    setStyleSheet(QStringLiteral(
        "QLabel#routingNote { color: palette(window-text); padding-top: 4px; }"
        "QLabel#actionStatus { color: palette(window-text); }"
        "QLabel#routingStatus { color: palette(window-text); min-width: 58px; }"
        "QTreeView { font-size: 10pt; }"));
    // Startup is an explicit lifecycle action, separate from read-only polling.
    // Authorize at most once, including when canceled or when the lab is down.
    // A connect URL selects a new destination and must not resume the old one.
    if (connect_url.isEmpty() && initial_settings.value("routing/requested", false).toBool()
        && !saslik_disconnected_) {
        QTimer::singleShot(0, this, [this, resume_routing] {
            if (!routing_requested_ || saslik_disconnected_) return;
            const auto result = resume_routing ? resume_routing()
                : routing_.resume(RoutingController::Authorization::Desktop);
            action_status_->setText(result.ok ? result.detail
                : tr("Automatic routing resume failed: %1 Use Restore routing to retry.").arg(result.detail));
            updateRoutingStatus();
        });
    }
}

void MainWindow::openConnectUrl(const QString& connect_url)
{
    if (connect_url.isEmpty()) return;
    const QUrl url(connect_url);
    const QString discovery = QUrlQuery(url).queryItemValue(QStringLiteral("discovery"));
    if (url.scheme() != QStringLiteral("skewer") || discovery.isEmpty()) return;
    routing_source_->setCurrentIndex(1);
    saslik_url_->setText(discovery);
    if (auto* info = findChild<QLineEdit*>(QStringLiteral("saslikInfoUrl")); info && info->text().isEmpty())
        info->setText(discovery);
    routing_requested_ = true;
    QSettings settings;
    settings.setValue(QStringLiteral("routing/mode"), QStringLiteral("saslik"));
    settings.setValue(QStringLiteral("routing/saslikUrl"), discovery);
    settings.setValue(QStringLiteral("routing/requested"), true);
}

void MainWindow::closeEvent(QCloseEvent* event)
{
    QSettings settings;
    settings.setValue(QStringLiteral("window/geometry"), saveGeometry());
    settings.setValue(QStringLiteral("routing/nextHop"), next_hop_->text().trimmed());
    settings.setValue(QStringLiteral("routing/saslikUrl"), saslik_url_->text().trimmed());
    settings.setValue(QStringLiteral("routing/mode"),
                      usesSaslikUrl() ? QStringLiteral("saslik") : QStringLiteral("gateway"));
    if (!quitting_ && close_to_tray_->isChecked() && QSystemTrayIcon::isSystemTrayAvailable()) {
        event->ignore();
        hide();
        return;
    }
    QMainWindow::closeEvent(event);
}

void MainWindow::updateTrayIcon()
{
    if (!tray_) return;
    QIcon icon(QStringLiteral(":/icons/skewer.svg"));
    if (palette().color(QPalette::Window).lightness() < 128) {
        // Reuse the fork geometry, tinting its alpha mask for dark desktops.
        QIcon monochrome;
        for (const int size : {16, 22, 24, 32, 48, 64, 128}) {
            QPixmap pixmap = icon.pixmap(size, size);
            QPainter painter(&pixmap);
            painter.setCompositionMode(QPainter::CompositionMode_SourceIn);
            painter.fillRect(pixmap.rect(), palette().color(QPalette::WindowText));
            painter.end();
            monochrome.addPixmap(pixmap);
        }
        icon = monochrome;
    }
    setWindowIcon(icon);
    tray_->setIcon(icon);
}

void MainWindow::changeEvent(QEvent* event)
{
    QMainWindow::changeEvent(event);
    if (event->type() == QEvent::PaletteChange) updateTrayIcon();
}

void MainWindow::activateRouting()
{
    if (usesSaslikUrl() && saslik_disconnected_) {
        action_status_->setText(tr("Reconnect to Saslik before enabling routing."));
        return;
    }
    if (usesSaslikUrl()) pollSaslik();
    const QString next_hop = currentNextHop();
    if (next_hop.isEmpty()) {
        QMessageBox::information(this, tr("Skewer"), usesSaslikUrl()
            ? tr("Saslik has not supplied a usable directly-connected gateway yet.")
            : tr("Enter a next-hop IPv4 address."));
        return;
    }
    const RoutingResult result = routing_.activate(next_hop,
        RoutingController::Authorization::Desktop);
    if (!result.ok) QMessageBox::warning(this, tr("Skewer routing"), result.detail);
    else {
        routing_requested_ = true;
        QSettings().setValue(QStringLiteral("routing/nextHop"), next_hop);
        QSettings().setValue(QStringLiteral("routing/saslikUrl"), saslik_url_->text().trimmed());
        QSettings().setValue(QStringLiteral("routing/mode"),
                             usesSaslikUrl() ? QStringLiteral("saslik") : QStringLiteral("gateway"));
        QSettings().setValue(QStringLiteral("routing/requested"), true);
        action_status_->setText(result.detail);
    }
    updateRoutingStatus();
}

void MainWindow::deactivateRouting()
{
    const RoutingResult result = routing_.deactivate(RoutingController::Authorization::Desktop);
    if (!result.ok) QMessageBox::warning(this, tr("Skewer routing"), result.detail);
    else {
        routing_requested_ = false;
        QSettings().setValue(QStringLiteral("routing/requested"), false);
        action_status_->setText(result.detail);
    }
    updateRoutingStatus();
}

void MainWindow::updateRoutingStatus()
{
    if (routing_check_pending_) return;
    const QString next_hop = currentNextHop();
    routing_check_pending_ = true;
    auto* check = new QFutureWatcher<QPair<bool, bool>>(this);
    connect(check, &QFutureWatcher<QPair<bool, bool>>::finished, this, [this, check, next_hop] {
        const auto result = check->result();
        check->deleteLater();
        routing_check_pending_ = false;
        // Discard a result for a gateway the user has changed in the meantime.
        if (next_hop != currentNextHop()) { updateRoutingStatus(); return; }
        renderRoutingStatus(result.first, result.second);
    });
    check->setFuture(QtConcurrent::run([next_hop] {
        RoutingController controller;
        return qMakePair(!next_hop.isEmpty() && controller.active(next_hop),
                         !next_hop.isEmpty() && controller.nextHopReachable(next_hop));
    }));
}

void MainWindow::renderRoutingStatus(bool active, bool reachable)
{
    const bool protected_slice = RoutingGuard::installed(getuid());
    model_->setRoutingState(active, protected_slice);
    const bool alarm = !active && model_->hasAttachedProcesses();
    auto* blink = findChild<QTimer*>("routingAlarm");
    if (!blink) {
        blink = new QTimer(this);
        blink->setObjectName("routingAlarm");
        blink->setInterval(600);
        connect(blink, &QTimer::timeout, this, [this, blink] {
            const bool bright = !blink->property("bright").toBool();
            blink->setProperty("bright", bright);
            const QString color = bright ? "#ff5364" : "#b83e4b";
            routing_status_->setStyleSheet("color:" + color);
            routing_status_bar_->setStyleSheet("color:" + color + "; padding:0 6px");
        });
    }
    if (alarm && !blink->isActive()) blink->start();
    if (!alarm) blink->stop();
    const QString next_hop = currentNextHop();
    const auto interface_state = InterfaceRouting::state(getuid());
    const bool interfaces_attached = !interface_state["selections"].toObject().isEmpty();
    QString text;
    QString color;
    if (active) {
        text = tr("● Routing active via %1").arg(next_hop);
        color = QStringLiteral("#63dc94");
    } else if (alarm) {
        text = protected_slice ? tr("● Dropped · process routing unavailable")
                               : tr("● Unprotected · restore process routing");
        color = QStringLiteral("#ff5364");
    } else if (interfaces_attached) {
        text = tr("● Interface ingress configured via %1").arg(interface_state["gateway"].toString());
        color = QStringLiteral("#e3b94f");
    } else if (routing_requested_) {
        if (!discovery_warning_.isEmpty()) text = tr("● %1").arg(discovery_warning_);
        else if (usesSaslikUrl() && !saslik_reachable_) text = tr("● Waiting for Saslik…");
        else if (usesSaslikUrl() && !discovery_online_)
            text = tr("● Saslik connected · waiting for lab…");
        else text = reachable ? tr("● Routing inactive · click Restore routing") : tr("● Gateway unavailable…");
        color = QStringLiteral("#e3b94f");
    } else {
        text = tr("○ Routing inactive");
        color = QStringLiteral("#899098");
    }
    routing_status_->setText(text);
    routing_status_bar_->setText(text);
    // Reuse the periodic status snapshot: hovering never runs network checks.
    QStringList tooltip{tr("Skewer"), text};
    if (!next_hop.isEmpty()) tooltip << tr("Gateway: %1").arg(next_hop);
    if (usesSaslikUrl()) {
        tooltip << (saslik_reachable_ ? tr("Saslik: connected") : tr("Saslik: unavailable"));
        if (saslik_reachable_)
            tooltip << (discovery_online_ ? tr("Lab: online") : tr("Lab: offline"));
    }
    tray_->setToolTip(tooltip.join('\n'));
    routing_status_->setStyleSheet(QStringLiteral("color:%1").arg(color));
    routing_status_bar_->setStyleSheet(QStringLiteral("color:%1; padding:0 6px").arg(color));
    // Existing kernel routes may outlive the previous GUI's privileged session.
    // Re-authorize explicitly; read-only startup polling must not show dialogs.
    const bool maintained = PrivilegedSession::client().running()
        && QFile::exists(QString("/run/skewer-route-intent-%1.json").arg(getuid()));
    routing_up_->setText(active && !maintained ? tr("Maintain routing")
        : routing_requested_ && !active ? tr("Restore routing") : tr("Enable"));
    routing_up_->setEnabled(!active || !maintained);
    routing_up_->setToolTip(tr("Authorize a persistent helper for this Skewer session. "
        "Missing routes will be restored without asking for the password again."));
    routing_down_->setEnabled(routing_requested_ || active || interfaces_attached);
    routing_source_->setEnabled(!routing_requested_ && !active && !interfaces_attached);
    next_hop_->setEnabled(!routing_requested_ && !active && !interfaces_attached && !usesSaslikUrl());
    saslik_url_->setEnabled(!routing_requested_ && !active && !interfaces_attached && usesSaslikUrl());

    // Polling is read-only: privilege elevation requires an explicit click.
}

bool MainWindow::usesSaslikUrl() const
{
    return routing_source_->currentData().toString() == QStringLiteral("saslik");
}

QString MainWindow::currentNextHop() const
{
    return usesSaslikUrl() ? discovery_gateway_ : next_hop_->text().trimmed();
}

void MainWindow::updateRoutingSource()
{
    if (ca_panel_) ca_panel_->setRemoteDisconnected();
    const bool saslik = usesSaslikUrl();
    if (!saslik) {
        saslik_reachable_ = false;
        discovery_online_ = false;
        discovery_warning_.clear();
    }
    next_hop_->setVisible(!saslik);
    saslik_url_->setVisible(saslik);
    if (saslik) pollSaslik();
    updateRoutingStatus();
}

void MainWindow::pollSaslik()
{
    if (saslik_disconnected_) return;
    if (discovery_request_pending_) return;
    const QUrl url(saslik_url_->text().trimmed());
    if (url.scheme()=="skewer" && !url.hasFragment()) {
        discovery_request_pending_ = true;
        auto* process = new QProcess(this);
        const auto epoch = saslik_epoch_;
        connect(process,qOverload<int,QProcess::ExitStatus>(&QProcess::finished),this,[this,process,url,epoch](int code,QProcess::ExitStatus status) {
            discovery_request_pending_ = false;
            if (epoch == saslik_epoch_ && url == QUrl(saslik_url_->text().trimmed()))
                applyDiscovery(process->readAllStandardOutput(),code==0 && status==QProcess::NormalExit);
            process->deleteLater();
        });
        connect(process,&QProcess::errorOccurred,this,[this,process](QProcess::ProcessError error) {
            if(error==QProcess::FailedToStart){discovery_request_pending_=false;applyDiscovery({},false);process->deleteLater();}
        });
        QTimer::singleShot(10000,process,[process] {if(process->state()!=QProcess::NotRunning)process->kill();});
        process->start(QCoreApplication::applicationFilePath(),{"remote-status",url.toString()});
        return;
    }
    if (!url.isValid() || url.scheme() != QStringLiteral("https")) {
        saslik_reachable_ = false;
        discovery_online_ = false;
        discovery_warning_ = tr("Invalid Saslik URL");
        return;
    }
    discovery_request_pending_ = true;
    QNetworkRequest request(url);
    request.setTransferTimeout(1800);
    network_->get(request)->setProperty("saslikEpoch", QVariant::fromValue(saslik_epoch_));
}

void MainWindow::receiveSaslik(QNetworkReply* reply)
{
    discovery_request_pending_ = false;
    const QByteArray payload = reply->readAll();
    const bool request_ok = reply->error() == QNetworkReply::NoError;
    reply->deleteLater();
    if (reply->property("saslikEpoch").toULongLong() != saslik_epoch_
        || reply->url() != QUrl(saslik_url_->text().trimmed())) return;
    applyDiscovery(payload,request_ok);
}

void MainWindow::applyDiscovery(const QByteArray& payload, bool request_ok)
{
    if (saslik_disconnected_) return;
    if (!request_ok) {
        ca_panel_->setRemoteDisconnected();
        saslik_reachable_ = false;
        discovery_online_ = false;
        discovery_warning_.clear();
        updateRoutingStatus();
        return;
    }
    QJsonParseError parse_error;
    const QJsonDocument document = QJsonDocument::fromJson(payload, &parse_error);
    const QJsonObject value = document.object();
    if (parse_error.error != QJsonParseError::NoError
        || value.value(QStringLiteral("version")).toInt() != 1) {
        saslik_reachable_ = false;
        discovery_online_ = false;
        discovery_warning_.clear();
        updateRoutingStatus();
        return;
    }
    saslik_reachable_ = true;
    if (QUrl(saslik_url_->text().trimmed()).scheme() == "skewer") {
        const auto pem = value["ca_pem"].toString().toUtf8();
        if (!pem.isEmpty()) ca_panel_->setRemoteCertificate(pem);
        else ca_panel_->setRemoteDisconnected();
    }
    // Trust inventory belongs to the Saslik connection, not to the lab's
    // current routing state.  Keep reporting while the lab is stopped too.
    QUrl ca_source(saslik_url_->text().trimmed());
    ca_source.setPath(QStringLiteral("/api/ca"));
    ca_source.setQuery(QString{}); ca_source.setFragment(QString{});
    if (ca_source.scheme()=="https") ca_panel_->setSource(ca_source);
    if (!trust_report_.isEmpty()
        && QDateTime::currentMSecsSinceEpoch() - last_trust_report_ms_ >= 10000)
        sendTrustReport();
    const QString gateway = value.value(QStringLiteral("gateway")).toString();
    const QString advertised_interface = value.value(QStringLiteral("host_interface")).toString();
    if (gateway.isEmpty() || advertised_interface.isEmpty()
        || !value.value(QStringLiteral("available")).toBool()) {
        discovery_online_ = false;
        discovery_warning_.clear();
        updateRoutingStatus();
        return;
    }
    const QString actual_interface = routing_.directInterface(gateway);
    discovery_online_ = true;
    discovery_warning_ = actual_interface.isEmpty()
        ? tr("Saslik gateway is not directly connected")
        : actual_interface != advertised_interface
            ? tr("Saslik expected %1, found %2").arg(advertised_interface, actual_interface)
            : QString{};
    discovery_gateway_ = gateway;
    discovery_interface_ = advertised_interface;
    const QString generation = value.value(QStringLiteral("generation")).toString();
    const bool reconnected = !discovery_generation_.isEmpty()
        && generation != discovery_generation_;
    discovery_generation_ = generation;
    if (reconnected) action_status_->setText(tr("Saslik reconnected; checking routing."));
    updateRoutingStatus();
}

void MainWindow::sendTrustReport()
{
    if (saslik_disconnected_) return;
    QUrl target(saslik_url_->text().trimmed());
    if (trust_report_.isEmpty() || !target.isValid() || target.host().isEmpty()) return;
    const QJsonObject report{{"version", 1}, {"hostname", QHostInfo::localHostName()},
                             {"skewer_version", QString::fromLatin1(SKEWER_VERSION)},
                             {"ca", trust_report_}};
    if (target.scheme() == "skewer") {
        if (trust_report_pending_) return;
        trust_report_pending_ = true;
        auto* job = new QFutureWatcher<QString>(this);
        connect(job, &QFutureWatcher<QString>::finished, this, [this, job] {
            trust_report_pending_ = false;
            const auto error = job->result(); job->deleteLater();
            if (error.isEmpty()) last_trust_report_ms_ = QDateTime::currentMSecsSinceEpoch();
            else action_status_->setText(tr("CA report could not be sent: %1").arg(error));
        });
        job->setFuture(QtConcurrent::run([target, report] {
            try {
                const auto result = pairedRequest(target, {{"action", "report"}, {"report", report}});
                return result["ok"].toBool() ? QString{} : QStringLiteral("Report rejected");
            } catch (const std::exception& error) { return QString::fromUtf8(error.what()); }
        }));
        return;
    }
    target.setPath(QStringLiteral("/api/skewer/report"));
    target.setQuery(QString{}); target.setFragment(QString{});
    QNetworkRequest request(target);
    request.setHeader(QNetworkRequest::ContentTypeHeader, QStringLiteral("application/json"));
    request.setTransferTimeout(10000);
    auto* reply = report_network_->post(request,
        QJsonDocument(report).toJson(QJsonDocument::Compact));
    connect(reply, &QNetworkReply::finished, reply, &QObject::deleteLater);
    last_trust_report_ms_ = QDateTime::currentMSecsSinceEpoch();
}

void MainWindow::launchCommand()
{
    const QString command = model_->resolveLaunchCommand(command_->text().trimmed());
    if (command.isEmpty()) {
        return;
    }
    QStringList words = QProcess::splitCommand(command);
    if (words.isEmpty()) return;
    QStringList invocation = CgroupManager::routedLaunchPrefix(words.first());
    invocation.append(words);
    const QString program = invocation.takeFirst();
    if (!QProcess::startDetached(program, invocation)) {
        QMessageBox::warning(this, tr("Skewer"),
                             tr("The command could not be started."));
        return;
    }
    command_->clear();
}

void MainWindow::rememberExpandedItems()
{
    tree_->setUpdatesEnabled(false);
    saved_tree_scroll_ = tree_->verticalScrollBar()->value();
    saved_tree_horizontal_scroll_ = tree_->horizontalScrollBar()->value();
    expanded_items_.clear();
    selected_item_ = tree_->currentIndex().data(ApplicationModel::StableIdRole).toString();
    const auto visit = [this](const auto& self, const QModelIndex& parent) -> void {
        for (int row = 0; row < filtered_model_->rowCount(parent); ++row) {
            const QModelIndex index = filtered_model_->index(row, 0, parent);
            if (tree_->isExpanded(index))
                expanded_items_.insert(index.data(ApplicationModel::StableIdRole).toString());
            self(self, index);
        }
    };
    visit(visit, {});
}

void MainWindow::restoreExpandedItems()
{
    const auto visit = [this](const auto& self, const QModelIndex& parent) -> void {
        for (int row = 0; row < filtered_model_->rowCount(parent); ++row) {
            const QModelIndex index = filtered_model_->index(row, 0, parent);
            const auto type = static_cast<ApplicationModel::NodeType>(
                index.data(ApplicationModel::NodeTypeRole).toInt());
            const QString id = index.data(ApplicationModel::StableIdRole).toString();
            if ((!restored_once_ && type == ApplicationModel::NodeType::Section)
                || expanded_items_.contains(id)) tree_->setExpanded(index, true);
            if (!selected_item_.isEmpty() && id == selected_item_)
                tree_->setCurrentIndex(index);
            self(self, index);
        }
    };
    visit(visit, {});
    restored_once_ = true;
    // Finish the reset, expansion and layout as one visible update. Restoring
    // the current item must not scroll another section into view each poll.
    tree_->doItemsLayout();
    tree_->verticalScrollBar()->setValue(saved_tree_scroll_);
    tree_->horizontalScrollBar()->setValue(saved_tree_horizontal_scroll_);
    tree_->setUpdatesEnabled(true);
}

void MainWindow::updateLauncherSuggestions(const QStringList& suggestions)
{
    launcher_model_->setStringList(suggestions);
}

void MainWindow::updateSelection()
{
    const QModelIndex index = tree_->currentIndex().siblingAtColumn(0);
    const auto type = static_cast<ApplicationModel::NodeType>(
        index.data(ApplicationModel::NodeTypeRole).toInt());
    const bool application = index.isValid() && type == ApplicationModel::NodeType::Application;
    if (index.isValid() && type == ApplicationModel::NodeType::Interface) {
        const bool attached = index.data(ApplicationModel::RoutedRole).toBool();
        route_button_->setEnabled(!attached && !index.data(ApplicationModel::PartiallyRoutedRole).toBool()
            && index.data(ApplicationModel::InterfaceNameRole).toString() != "lo");
        release_button_->setEnabled(attached);
        action_status_->setText(tr("Interface ingress only. CA trust inside guests is unknown; no certificates are installed there."));
        return;
    }
    const bool routed = application && index.data(ApplicationModel::RoutedRole).toBool();
    const bool partial = index.data(ApplicationModel::PartiallyRoutedRole).toBool();
    route_button_->setEnabled(application && (!routed || partial));
    release_button_->setEnabled(application && routed);
    action_status_->setText(application
        ? (partial ? tr("Only some instances are attached. Actions apply to all selected instances.")
           : routed ? tr("This application is attached to the Skewer cgroup.")
                  : tr("Existing sockets keep their current route."))
        : tr("Select an application to manage its routing."));
}

void MainWindow::browseExecutable()
{
    const QString path = QFileDialog::getOpenFileName(this, tr("Choose an application"),
                                                       QStringLiteral("/usr/bin"));
    if (path.isEmpty()) return;
    QString quoted = path;
    quoted.replace(QLatin1Char('"'), QStringLiteral("\\\""));
    command_->setText(QLatin1Char('"') + quoted + QLatin1Char('"'));
    command_->setFocus();
}

void MainWindow::routeSelection()
{
    const QModelIndex index = tree_->currentIndex().siblingAtColumn(0);
    if (index.data(ApplicationModel::NodeTypeRole).toInt() == int(ApplicationModel::NodeType::Interface)) {
        const QString name = index.data(ApplicationModel::InterfaceNameRole).toString();
        const int number = index.data(ApplicationModel::InterfaceIndexRole).toInt();
        if (currentNextHop().isEmpty() || (usesSaslikUrl() && saslik_disconnected_)) {
            QMessageBox::information(this, tr("Interface routing"), tr("Select a reachable Saslik gateway first.")); return;
        }
        if (QMessageBox::warning(this, tr("Route interface ingress"),
            tr("Route incoming IPv4 on %1 via %2? A bridge selects its CURRENT ports only.\n"
               "Bridge traffic must use the host bridge as its gateway; other gateway MACs are blocked.\n"
               "IPv6 and non-IP bridge traffic except ARP are blocked. DHCP and host-local traffic stay local.\n"
               "Return routes and forwarding/firewall must already permit traffic. No SNAT or guest CA installation.\n"
               "Changing paths can interrupt existing connections. Guest CA trust is unknown.").arg(name, currentNextHop()),
            QMessageBox::Yes | QMessageBox::Cancel, QMessageBox::Cancel) != QMessageBox::Yes) return;
        const auto result = routing_.interfaceChange(name, number, currentNextHop(), true, RoutingController::Authorization::Desktop);
        if (!result.ok) QMessageBox::warning(this, tr("Interface routing"), result.detail);
        model_->refresh(); updateRoutingStatus(); action_status_->setText(result.detail); return;
    }
    QVector<pid_t> pids;
    for (const QVariant& value : index.data(ApplicationModel::ProcessIdsRole).toList())
        pids.push_back(value.toInt());
    const CgroupResult result = cgroups_.route(pids, index.data().toString());
    action_status_->setText(result.detail);
    if (!result.ok) QMessageBox::warning(this, tr("Skewer"), result.detail);
    else {
        model_->refresh();
        if (QSettings().value("connections/cleanupOnAttach", false).toBool()) {
            QTimer::singleShot(500, this, [this,pids] {
                auto* job = new QFutureWatcher<RoutingResult>(this);
                connect(job,&QFutureWatcher<RoutingResult>::finished,this,[this,job] {
                    action_status_->setText(job->result().detail); job->deleteLater();
                });
                job->setFuture(QtConcurrent::run([pids] {
                    return RoutingController().cleanupTcp(pids,RoutingController::Authorization::Desktop);
                }));
            });
        }
    }
}

void MainWindow::releaseSelection()
{
    const QModelIndex index = tree_->currentIndex().siblingAtColumn(0);
    if (index.data(ApplicationModel::NodeTypeRole).toInt() == int(ApplicationModel::NodeType::Interface)) {
        const auto result = routing_.interfaceChange(index.data(ApplicationModel::InterfaceNameRole).toString(),
            index.data(ApplicationModel::InterfaceIndexRole).toInt(), {}, false, RoutingController::Authorization::Desktop);
        if (!result.ok) QMessageBox::warning(this, tr("Interface routing"), result.detail);
        model_->refresh(); action_status_->setText(result.detail); return;
    }
    QVector<pid_t> pids;
    for (const QVariant& value : index.data(ApplicationModel::ProcessIdsRole).toList())
        pids.push_back(value.toInt());
    const CgroupResult result = cgroups_.release(pids, index.data().toString());
    action_status_->setText(result.detail);
    if (!result.ok) QMessageBox::warning(this, tr("Skewer"), result.detail);
    else model_->refresh();
}
