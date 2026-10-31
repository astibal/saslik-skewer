#include "main_window.hpp"
#include "ui/application_page.hpp"
#include "routing_guard.hpp"
#include "privileged_session.hpp"
#include "interface_routing.hpp"
#include "tuntom_session.hpp"
#include "tuntom_status.hpp"
#include <QTextStream>
#include "tuntom_binary.hpp"
#include "preferences_values.hpp"
#include "preferences_dialog.hpp"
#include <QSignalBlocker>
#include <QCheckBox>
#include <sys/stat.h>
#include <pwd.h>
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
#include <QMouseEvent>
#include <QKeyEvent>
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
                       std::function<RoutingResult()> resume_routing,
                       std::function<RoutingResult()> authorize_session)
    : skewer::ui::ApplicationShell(QStringLiteral(SKEWER_VERSION), parent)
{
    connect(preferencesAction(), &QAction::triggered, this, [this] {
        PreferencesDialog dialog(this);
        if (dialog.exec() == QDialog::Accepted) applyPreferences();
    });
    auto* central = new skewer::ui::ApplicationPage(this);
    auto* tabs = pages();
    auto* ca_panel = ca_panel_ = new CaTrustPanel(tabs);
    auto* runtime_trust = new RuntimeTrustPanel(tabs);
    tabs->addTab(central, tr("Applications"));
    tabs->addTab(ca_panel, tr("CA Trust"));
    tabs->addTab(runtime_trust, tr("Runtime Trust"));
    connect(runtime_trust, &RuntimeTrustPanel::selectCertificateRequested, this,
            [tabs, ca_panel] { tabs->setCurrentWidget(ca_panel); });
    connect(ca_panel, &CaTrustPanel::certificateChanged,
            runtime_trust, &RuntimeTrustPanel::setCertificate);
    auto* layout = central->top;
    search_ = central->search;
    auto* routing_row = new QHBoxLayout;
    auto* scope_box = new QGroupBox(central);
    scope_box->setAccessibleName(tr("Routing scope"));
    scope_box->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Preferred);
    auto* scope_layout = new QHBoxLayout(scope_box);
    scope_layout->setContentsMargins(8, 6, 8, 6);
    auto* routing_box = new QGroupBox(central);
    routing_box->setAccessibleName(tr("Routing"));
    auto* routing_layout = new QHBoxLayout(routing_box);
    routing_layout->setContentsMargins(8, 6, 8, 6);
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
    transport_mode_ = new QComboBox(routing_box);
    transport_mode_->setObjectName("routingTransport");
    transport_mode_->addItem(tr("Auto"), "auto");
    transport_mode_->addItem(tr("Direct"), "direct");
    transport_mode_->addItem(tr("Enforced tunnel"), "tunnel");
    const int transport_index = transport_mode_->findData(initial_settings.value("routing/transport", "auto"));
    transport_mode_->setCurrentIndex(qMax(0, transport_index));
    transport_mode_->setToolTip(tr("Auto: direct next hop when available, otherwise Tuntom. "
        "Direct: never create a tunnel. Enforced tunnel: always use authenticated Tuntom, even when directly connected. "
        "Disable routing before changing mode. Tunnel routing currently supports applications, not VM interfaces."));
    connect(transport_mode_, &QComboBox::currentIndexChanged, this, [this] {
        QSettings().setValue("routing/transport", transport_mode_->currentData());
    });
    routing_scope_ = new QComboBox(scope_box);
    routing_scope_->setObjectName("routingScope");
    routing_scope_->addItem(tr("Selected Apps"), "applications");
    routing_scope_->addItem(tr("Whole Host"), "host");
    auto scope_font = routing_scope_->font();
    scope_font.setWeight(QFont::DemiBold);
    routing_scope_->setFont(scope_font);
    routing_scope_->setSizeAdjustPolicy(QComboBox::AdjustToContents);
    scope_layout->addWidget(routing_scope_);
    routing_scope_->setCurrentIndex(initial_settings.value("routing/scope", "applications") == "host" ? 1 : 0);
    routing_scope_->setToolTip(tr("Whole host: all local IPv4 traffic, including services. IPv6 is blocked. "
        "Loopback, DHCP and tunnel control stay local. Forwarded VM traffic is configured separately. "
        "Disable releases host routing; tunnel loss blocks host traffic until recovery or Disable."));
    connect(routing_scope_, &QComboBox::currentIndexChanged, this, [this] {
        QSettings().setValue("routing/scope", routing_scope_->currentData());
    });
    routing_up_ = new QPushButton(tr("Enable"), routing_box);
    routing_down_ = new QPushButton(tr("Disable"), routing_box);
    routing_status_ = new QLabel(routing_box);
    routing_status_->setObjectName("routingStatus");
    routing_status_->installEventFilter(this);
    routing_status_->setObjectName(QStringLiteral("routingStatus"));
    routing_layout->addWidget(routing_source_);
    routing_layout->addWidget(next_hop_, 1);
    routing_layout->addWidget(saslik_url_, 1);
    routing_layout->addWidget(transport_mode_);
    routing_layout->addWidget(routing_up_);
    routing_layout->addWidget(routing_down_);
    routing_layout->addWidget(routing_status_);
    routing_row->addWidget(scope_box);
    routing_row->addWidget(routing_box, 1);
    layout->addLayout(routing_row);
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
            QString reset_detail;
            if (tunnel_selected_ || routing_.active(currentNextHop())) {
                const auto result = routing_.updateExemptions(normalized, RoutingController::Authorization::Desktop);
                if (!result.ok) { error->setText(result.detail); return; }
                if (QSettings().value("connections/cleanupOnAttach", false).toBool()) reset_detail = result.detail;
            }
            QSettings().setValue("routing/exemptions", normalized);
            action_status_->setText(tr("Saved %1 destination exemptions.").arg(normalized.size()));
            if (!reset_detail.isEmpty()) action_status_->setText(action_status_->text() + ' ' + reset_detail);
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
    const auto sync_status_endpoint = [this, info_url] {
        // A connected lab has one identity. Legacy status-only settings must
        // not hide its status or point CA/link actions at a different server.
        const auto endpoint = saslik_url_->text().trimmed();
        const bool follows_connection = usesSaslikUrl() && !endpoint.isEmpty();
        info_url->setReadOnly(follows_connection);
        if (follows_connection) info_url->setText(endpoint);
        else info_url->setText(QSettings().value("saslik/statusUrl").toString());
    };
    sync_status_endpoint();
    connect(saslik_url_, &QLineEdit::textChanged, info, sync_status_endpoint);
    connect(routing_source_, qOverload<int>(&QComboBox::currentIndexChanged), info, sync_status_endpoint);
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
    links->addSpacing(12);
    tuntom_availability_ = new QLabel(tr("Tunnel off"), info);
    tuntom_availability_->setObjectName("tuntomAvailability");
    tuntom_availability_->setTextFormat(Qt::PlainText);
    tuntom_availability_->setWordWrap(true);
    tuntom_availability_->setMinimumWidth(0);
    links->addWidget(tuntom_availability_, 1);
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
    status_timer->setObjectName("saslikRefresh");
    status_timer->setInterval(Preferences::number("refresh/saslikSeconds", 10, 5, 120) * 1000);
    connect(status_timer, &QTimer::timeout, info, poll_status);
    connect(info_url, &QLineEdit::editingFinished, info, [=] {
        if (!info_url->isReadOnly())
            QSettings().setValue(QStringLiteral("saslik/statusUrl"), info_url->text().trimmed());
        poll_status();
    });
    connect(saslik_url_, &QLineEdit::editingFinished, info, poll_status);
    connect(routing_source_, qOverload<int>(&QComboBox::currentIndexChanged), info, poll_status);
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
    routing_status_bar_->setObjectName("routingStatusBar");
    routing_status_bar_->installEventFilter(this);
    statusBar()->addPermanentWidget(routing_status_bar_);
    connect(routing_source_, &QComboBox::currentIndexChanged,
            this, &MainWindow::updateRoutingSource);
    network_ = new QNetworkAccessManager(this);
    installPortalTrust(network_, this);
    connect(network_, &QNetworkAccessManager::finished, this, &MainWindow::receiveSaslik);
    openConnectUrl(connect_url);
    updateRoutingSource();
    routing_watchdog_ = new QTimer(this);
    routing_watchdog_->setInterval(Preferences::number("refresh/routingSeconds", 5, 2, 60) * 1000);
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

    tree_ = central->tree;
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
    action_status_ = central->action_status;
    action_status_->setTextFormat(Qt::PlainText);
    route_button_ = central->attach;
    release_button_ = central->release;
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

    layout = central->footer;
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
        "QTreeView { font-size: %1pt; }").arg(Preferences::number("appearance/treeFontSize", 10, 8, 24)));
    // Startup is an explicit lifecycle action, separate from read-only polling.
    // Authorize at most once, including when canceled or when the lab is down.
    // A connect URL selects a new destination and must not resume the old one.
    const bool resume_on_start = connect_url.isEmpty() && initial_settings.value("routing/resumeOnStartup", true).toBool()
        && initial_settings.value("routing/requested", false).toBool()
        && !saslik_disconnected_;
    QTimer::singleShot(0, this, [this, resume_routing, authorize_session, resume_on_start] {
            // Authorize independently of routing intent or remote availability.
            // The persistent helper remains alive until the application exits;
            // no sudo timestamp or periodic authentication refresh is involved.
            const auto authorization = authorize_session ? authorize_session() : [] {
                QString helper = QCoreApplication::applicationDirPath() + "/skewer-net-helper";
                if (!QFileInfo(helper).isExecutable()) helper = SKEWER_INSTALLED_HELPER_PATH;
                const auto reply = PrivilegedSession::request(helper, {"tunnel-poll"}, true);
                return RoutingResult{reply.ok, reply.detail};
            }();
            if (!authorization.ok) {
                action_status_->setText(tr("Helper authorization canceled or unavailable. Enable / Restore routing to retry."));
                return;
            }
            if (!resume_on_start || !routing_requested_ || saslik_disconnected_) return;
            if (!resume_routing && wantsTunnel()) { startTunnel(); return; }
            const auto result = resume_routing ? resume_routing()
                : routing_.resume(RoutingController::Authorization::Desktop);
            action_status_->setText(result.ok ? result.detail
                : tr("Automatic routing resume failed: %1 Use Restore routing to retry.").arg(result.detail));
            updateRoutingStatus();
        });
}

MainWindow::~MainWindow()
{
    stopTunnel();
    // QProcess destruction can emit finished while QObject deletes children.
    // Discovery callbacks must not access widgets already being torn down.
    for (auto* process : findChildren<QProcess*>()) process->disconnect(this);
}

void MainWindow::applyPreferences()
{
    close_to_tray_->setChecked(QSettings().value("window/closeToTray", true).toBool());
    model_->applyPreferences();
    routing_watchdog_->setInterval(Preferences::number("refresh/routingSeconds", 5, 2, 60) * 1000);
    if (auto* timer = findChild<QTimer*>("saslikRefresh"))
        timer->setInterval(Preferences::number("refresh/saslikSeconds", 10, 5, 120) * 1000);
    if (auto* timer = findChild<QTimer*>("connectionsRefresh"))
        timer->setInterval(Preferences::number("refresh/connectionSeconds", 5, 2, 60) * 1000);
    if (auto* automatic = findChild<QCheckBox*>("automaticTcpCleanup")) {
        QSignalBlocker blocker(automatic);
        automatic->setChecked(QSettings().value("connections/cleanupOnAttach", false).toBool());
    }
    QString style = styleSheet();
    style.replace(QRegularExpression("QTreeView \\{ font-size: \\d+pt; \\}"),
        QString("QTreeView { font-size: %1pt; }").arg(Preferences::number("appearance/treeFontSize", 10, 8, 24)));
    setStyleSheet(style);
    updateRoutingStatus();
}

bool MainWindow::wantsTunnel() const
{
    if (!usesSaslikUrl() || transport_mode_->currentData() == "direct") return false;
    // Once selected, loss of a tunnel never silently falls back to direct.
    if (tunnel_selected_) return true;
    if (routing_requested_ && QSettings().value("routing/lastTransport") == "tunnel") return true;
    const auto mode = transport_mode_->currentData() == "tunnel"
        ? Tuntom::Mode::TunnelOnly : Tuntom::Mode::Auto;
    const QString gateway = discovery_gateway_.isEmpty() ? next_hop_->text().trimmed() : discovery_gateway_;
    return Tuntom::selectRoute(mode, routing_.nextHopReachable(gateway), false, false)
        != Tuntom::Route::Direct;
}

void MainWindow::startTunnel(bool allowAuthorization)
{
    if (tunnel_process_) return;
    if (tunnel_retry_) tunnel_retry_->stop();
    if (tunnel_retry_tick_) tunnel_retry_tick_->stop();
    if (allowAuthorization) tunnel_recovery_.reset();
    const QUrl endpoint(saslik_url_->text().trimmed());
    if (endpoint.scheme() != "skewer" || endpoint.host().isEmpty() || endpoint.port() <= 0 || endpoint.path() != "/pair" || endpoint.hasFragment()
        || endpoint.hasQuery() || !endpoint.userInfo().isEmpty()) {
        action_status_->setText(tr("Tunnel requires an already paired skewer://HOST:PORT/pair address."));
        return;
    }
    if (!InterfaceRouting::state(getuid())["selections"].toObject().isEmpty()) {
        action_status_->setText(tr("Release VM/interface ingress before enabling a tunnel."));
        return;
    }
    const auto preflight = Preferences::tunnelPreflightError();
    if (!preflight.isEmpty()) {
        tunnel_error_ = preflight;
        tunnel_selected_ = true;
        tunnel_state_ = "failed";
        tunnel_retryable_ = false;
        DiagnosticLog::write("preflight", preflight, "error");
        action_status_->setText(preflight);
        updateRoutingStatus();
        return;
    }
    tunnel_retryable_ = true;
    tunnel_selected_ = true;
    tunnel_state_ = "connecting";
    tunnel_error_.clear();
    tunnel_stats_ = {};
    tunnel_status_age_.invalidate();
    tunnel_gateway_.clear();
    tunnel_output_.clear();
    routing_requested_ = true;
    QSettings().setValue("routing/requested", true);
    QSettings().setValue("routing/saslikUrl", endpoint.toString());
    QSettings().setValue("routing/mode", "saslik");
    QSettings().setValue("routing/lastTransport", "tunnel");
    // Keep authorization even if the very first remote request fails.
    QString helper = QCoreApplication::applicationDirPath() + "/skewer-net-helper";
    if (!QFileInfo(helper).isExecutable()) helper = SKEWER_INSTALLED_HELPER_PATH;
    const auto authorization = PrivilegedSession::request(helper, {"tunnel-poll"}, true, allowAuthorization);
    if (!authorization.ok) {
        tunnel_error_ = authorization.detail;
        tunnel_state_ = "failed";
        scheduleTunnelRetry();
        action_status_->setText(tr("Helper unavailable · retry scheduled; click retry to authorize a new session"));
        updateRoutingStatus();
        return;
    }
    auto* process = new QProcess(this);
    tunnel_process_ = process;
    connect(process, &QProcess::readyReadStandardError, this, [this, process] {
        const auto diagnostic = QString::fromUtf8(process->readAllStandardError());
        tunnel_error_ = (tunnel_error_ + diagnostic).right(4096);
    });
    connect(process, &QProcess::readyReadStandardOutput, this, [this, process, allowAuthorization] {
        tunnel_output_ += process->readAllStandardOutput();
        if (tunnel_output_.size() > 65536) {
            tunnel_error_ = tr("Invalid tunnel status stream");
            process->closeWriteChannel();
            return;
        }
        while (tunnel_output_.contains('\n')) {
            const auto line = tunnel_output_.first(tunnel_output_.indexOf('\n'));
            tunnel_output_.remove(0, line.size() + 1);
            const auto status = QJsonDocument::fromJson(line).object();
            if (status["helper_request"].isArray()) {
                QStringList args;
                for (const auto& value : status["helper_request"].toArray()) args << value.toString();
                // Only this child owns the tunnel stream. Background polling
                // must never launch a new authorization dialog after a loss.
                QString helper = QCoreApplication::applicationDirPath() + "/skewer-net-helper";
                if (!QFileInfo(helper).isExecutable()) helper = SKEWER_INSTALLED_HELPER_PATH;
                const auto reply = PrivilegedSession::request(helper, args, true,
                    allowAuthorization && !args.isEmpty() && args.first() == "tunnel-start");
                process->write(QJsonDocument(QJsonObject{{"ok", reply.ok}, {"detail", reply.detail}})
                    .toJson(QJsonDocument::Compact) + '\n');
                continue;
            }
            if (status["phase"].isString()) {
                action_status_->setText(status["phase"].toString());
                continue;
            }
            const auto state = status["state"].toString();
            if (state == "failed") {
                tunnel_error_ = DiagnosticLog::redact(status["error"].toString());
                tunnel_retryable_ = status["retryable"].toBool(true);
                action_status_->setText(tr("Tunnel failed: %1").arg(tunnel_error_));
                continue;
            }
            if (state != "prepared" && state != "waiting" && state != "verified") continue;
            QHostAddress gateway(status["gateway"].toString());
            if (gateway.protocol() != QAbstractSocket::IPv4Protocol) continue;
            if (tunnel_state_ != state) DiagnosticLog::write("tunnel", "State: " + state);
            tunnel_state_ = state;
            if (state == "verified") action_status_->setText(tr("Tunnel connected and routing verified"));
            if (state == "verified") tunnel_recovery_.reset();
            tunnel_stats_ = status["stats"].toObject();
            tunnel_status_age_.restart();
            tunnel_gateway_ = gateway.toString();
            updateRoutingStatus();
        }
    });
    connect(process, qOverload<int,QProcess::ExitStatus>(&QProcess::finished), this,
        [this, process](int code, QProcess::ExitStatus exitStatus) {
            const auto diagnostic = QString::fromUtf8(process->readAllStandardError());
            DiagnosticLog::write("controller", tunnel_error_ + diagnostic, "warning");
            DiagnosticLog::write("controller", QString("Client finished: exit=%1 crash=%2").arg(code).arg(exitStatus == QProcess::CrashExit));
            if (exitStatus == QProcess::NormalExit && code == 2) tunnel_retryable_ = false;
            tunnel_error_ = DiagnosticLog::redact((tunnel_error_ + diagnostic).right(4096));
            tunnel_state_ = "failed";
            tunnel_process_ = nullptr;
            process->deleteLater();
            scheduleTunnelRetry();
            updateRoutingStatus();
        });
    connect(process, &QProcess::errorOccurred, this, [this, process](QProcess::ProcessError error) {
        if (error != QProcess::FailedToStart) return;
        tunnel_error_ = process->errorString();
        DiagnosticLog::write("controller", "Cannot start client: " + tunnel_error_, "error");
        action_status_->setText(tr("Cannot start tunnel controller: %1").arg(tunnel_error_));
        tunnel_retryable_ = false;
        tunnel_state_ = "failed";
        tunnel_process_ = nullptr;
        process->deleteLater();
        scheduleTunnelRetry();
        updateRoutingStatus();
    });
    process->start("/usr/bin/systemd-run",
        Tuntom::controllerArguments(QCoreApplication::applicationFilePath(), endpoint.toString()));
    updateRoutingStatus();
}

void MainWindow::scheduleTunnelRetry()
{
    if (!tunnel_retryable_) return;
    if (!Tuntom::Recovery::allowed(routing_requested_, tunnel_selected_, !saslik_disconnected_,
            quitting_, tunnel_process_ != nullptr)) return;
    if (!tunnel_retry_) {
        tunnel_retry_ = new QTimer(this);
        tunnel_retry_->setObjectName("tunnelRecovery");
        tunnel_retry_->setSingleShot(true);
        connect(tunnel_retry_, &QTimer::timeout, this, [this] {
            // Only explicit user intent or a live attempt cancels a retry.
            if (Tuntom::Recovery::allowed(routing_requested_, tunnel_selected_, !saslik_disconnected_,
                    quitting_, tunnel_process_ != nullptr))
                startTunnel(false);
        });
        tunnel_retry_tick_ = new QTimer(this);
        tunnel_retry_tick_->setInterval(1000);
        connect(tunnel_retry_tick_, &QTimer::timeout, this, &MainWindow::refreshTunnelCountdown);
    }
    const int delay = tunnel_recovery_.nextDelayMs();
    tunnel_retry_->start(delay);
    tunnel_retry_tick_->start();
    DiagnosticLog::write("recovery", QString("Retry in %1 s").arg(delay / 1000));
    action_status_->setText(tr("Tunnel unavailable · retry in %1 s · %2").arg(delay / 1000).arg(tunnel_error_.trimmed().right(700)));
}

void MainWindow::refreshTunnelCountdown()
{
    const bool pending = tunnel_retry_ && tunnel_retry_->isActive();
    for (auto* label : {routing_status_, routing_status_bar_}) {
        label->setCursor(pending ? Qt::PointingHandCursor : Qt::ArrowCursor);
        label->setFocusPolicy(pending ? Qt::StrongFocus : Qt::NoFocus);
        label->setToolTip(pending ? tr("Click to retry now") : tunnel_selected_ ? tunnel_error_ : QString{});
        if (!pending) continue;
        const int seconds = (qMax(0, tunnel_retry_->remainingTime()) + 999) / 1000;
        const auto text = (routing_status_->property("retryGuarded").toBool()
            ? tr("● Dropped · Tuntom: retry in %1 s")
            : tr("● Tuntom unavailable · retry in %1 s")).arg(seconds);
        if (label->text() != text) label->setText(text);
    }
}

bool MainWindow::eventFilter(QObject* watched, QEvent* event)
{
    if ((watched == routing_status_ || watched == routing_status_bar_)
        && tunnel_retry_ && tunnel_retry_->isActive()) {
        bool activate = event->type() == QEvent::MouseButtonRelease
            && static_cast<QMouseEvent*>(event)->button() == Qt::LeftButton;
        if (event->type() == QEvent::KeyPress) {
            const auto* key = static_cast<QKeyEvent*>(event);
            activate = !key->isAutoRepeat() && (key->key() == Qt::Key_Return
                || key->key() == Qt::Key_Enter || key->key() == Qt::Key_Space);
        }
        if (activate && Tuntom::Recovery::allowed(routing_requested_, tunnel_selected_,
                !saslik_disconnected_, quitting_, tunnel_process_ != nullptr)) {
            // A deliberate click may renew authorization; timed retries never do.
            startTunnel(true);
            return true;
        }
    }
    return QMainWindow::eventFilter(watched, event);
}

void MainWindow::stopTunnel()
{
    if (tunnel_retry_) tunnel_retry_->stop();
    if (tunnel_retry_tick_) tunnel_retry_tick_->stop();
    tunnel_recovery_.reset();
    if (tunnel_process_) {
        QString helper = QCoreApplication::applicationDirPath() + "/skewer-net-helper";
        if (!QFileInfo(helper).isExecutable()) helper = SKEWER_INSTALLED_HELPER_PATH;
        // Stop through the existing session before waiting for the child. The
        // GUI cannot service child RPCs while waitForFinished blocks its loop.
        PrivilegedSession::request(helper, {"tunnel-stop"}, true, false);
        auto* process = tunnel_process_;
        process->disconnect(this);
        process->closeWriteChannel();
        if (!process->waitForFinished(10000)) {
            process->terminate();
            if (!process->waitForFinished(2000)) { process->kill(); process->waitForFinished(1000); }
        }
        delete process;
        tunnel_process_ = nullptr;
    }
    tunnel_state_.clear();
    tunnel_stats_ = {};
    tunnel_status_age_.invalidate();
    tunnel_gateway_.clear();
    tunnel_selected_ = false;
}

void MainWindow::openConnectUrl(const QString& connect_url)
{
    if (connect_url.isEmpty()) return;
    if (tunnel_selected_ && routing_requested_) {
        action_status_->setText(tr("Disable the current tunnel before selecting another Saslik."));
        return;
    }
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
    settings.setValue(QStringLiteral("routing/nextHop"), next_hop_->text().trimmed());
    settings.setValue(QStringLiteral("routing/saslikUrl"), saslik_url_->text().trimmed());
    settings.setValue(QStringLiteral("routing/mode"),
                      usesSaslikUrl() ? QStringLiteral("saslik") : QStringLiteral("gateway"));
    skewer::ui::ApplicationShell::closeEvent(event);
}

void MainWindow::activateRouting()
{
    if (usesSaslikUrl() && saslik_disconnected_) {
        action_status_->setText(tr("Reconnect to Saslik before enabling routing."));
        return;
    }
    if (usesSaslikUrl()) pollSaslik();
    if (wantsTunnel()) { startTunnel(); return; }
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
        QSettings().setValue("routing/lastTransport", "direct");
        action_status_->setText(result.detail);
    }
    updateRoutingStatus();
}

void MainWindow::deactivateRouting()
{
    stopTunnel();
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
        const bool reachable = !next_hop.isEmpty() && controller.nextHopReachable(next_hop);
        return qMakePair(!next_hop.isEmpty() && controller.active(next_hop), reachable);
    }));
}

void MainWindow::renderRoutingStatus(bool active, bool reachable)
{
    if (tunnel_selected_ && tunnel_state_ != "verified") active = false;
    Tuntom::StatusView tunnel;
    tunnel.mode = transport_mode_->currentData().toString();
    tunnel.license = tuntom_license_;
    tunnel.enabled = tuntom_remote_enabled_;
    tunnel.connected = saslik_reachable_;
    tunnel.paired = QUrl(saslik_url_->text().trimmed()).scheme() == "skewer";
    tunnel.requested = routing_requested_;
    tunnel.selected = tunnel_selected_;
    // Once selected, currentNextHop refers to the tunnel, not the direct path.
    tunnel.directKnown = !tunnel_selected_ && !currentNextHop().isEmpty();
    tunnel.direct = reachable;
    tunnel.state = tunnel_state_;
    tunnel.fresh = tunnel_status_age_.isValid() && tunnel_status_age_.elapsed() < 15000;
    tunnel.routingActive = active;
    tunnel.stats = tunnel_stats_;
    tuntom_availability_->setText(Tuntom::compactStatus(tunnel,
        !QFileInfo(Preferences::tuntomBinary()).isExecutable()));
    QString details = Tuntom::statusSummary(tunnel);
    if (!tunnel_error_.trimmed().isEmpty()) details += '\n' + tunnel_error_.trimmed();
    // Keep operational details, without the verbose security disclaimer.
    tuntom_availability_->setToolTip(details);
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
        text = tunnel_selected_ ? tr("● Tuntom active via %1").arg(next_hop)
                                : tr("● Routing active via %1").arg(next_hop);
        color = QStringLiteral("#63dc94");
    } else if (alarm) {
        text = protected_slice ? tr("● Dropped · process routing unavailable")
                               : tr("● Unprotected · restore process routing");
        if (protected_slice && tunnel_selected_)
            text = tr("● Dropped · Tuntom: %1").arg(tunnel_state_);
        color = QStringLiteral("#ff5364");
    } else if (tunnel_selected_) {
        text = tunnel_state_ == "failed" ? (tunnel_retry_ && tunnel_retry_->isActive()
                ? tr("● Tunnel unavailable · automatic retry pending") : tr("● Tunnel failed · Restore routing to retry"))
                                        : tr("● Tuntom: %1 · routing blocked").arg(tunnel_state_);
        color = tunnel_state_ == "failed" ? "#ff5364" : "#e3b94f";
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
    if (routing_scope_->currentData() == "host") text.prepend(tr("Whole host · "));
    routing_status_->setProperty("retryGuarded", protected_slice);
    routing_status_->setText(text);
    routing_status_bar_->setText(text);
    refreshTunnelCountdown();
    // Reuse the periodic status snapshot: hovering never runs network checks.
    QStringList tooltip{tr("Skewer"), text};
    if (!next_hop.isEmpty()) tooltip << tr("Gateway: %1").arg(next_hop);
    if (usesSaslikUrl()) {
        tooltip << (saslik_reachable_ ? tr("Saslik: connected") : tr("Saslik: unavailable"));
        if (saslik_reachable_)
            tooltip << (discovery_online_ ? tr("Lab: online") : tr("Lab: offline"));
    }
    tray_->setToolTip(tooltip.join('\n'));
    routing_status_->setToolTip(tunnel_retry_ && tunnel_retry_->isActive()
        ? tr("Click to retry now") : tunnel_selected_ ? tunnel_error_ : QString{});
    routing_status_->setStyleSheet(QStringLiteral("color:%1").arg(color));
    routing_status_bar_->setStyleSheet(QStringLiteral("color:%1; padding:0 6px").arg(color));
    // Existing kernel routes may outlive the previous GUI's privileged session.
    // Re-authorize explicitly; read-only startup polling must not show dialogs.
    const bool maintained = tunnel_process_ || (PrivilegedSession::client().running()
        && QFile::exists(QString("/run/skewer-route-intent-%1.json").arg(getuid())));
    routing_up_->setText(active && !maintained ? tr("Maintain routing")
        : routing_requested_ && !active ? tr("Restore routing") : tr("Enable"));
    routing_up_->setEnabled(!tunnel_process_ && (!active || !maintained));
    routing_up_->setToolTip(tr("Authorize a persistent helper for this Skewer session. "
        "Missing routes will be restored without asking for the password again."));
    const bool host_claimed = QFile::exists("/run/skewer-host.json");
    routing_down_->setText(host_claimed ? tr("Release host") : tr("Disable"));
    routing_down_->setEnabled(host_claimed || routing_requested_ || active || interfaces_attached);
    routing_source_->setEnabled(!routing_requested_ && !active && !interfaces_attached);
    routing_scope_->setEnabled(!host_claimed && !routing_requested_ && !active && !interfaces_attached);
    transport_mode_->setEnabled(!routing_requested_ && !active && !interfaces_attached && usesSaslikUrl());
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
    if (tunnel_selected_) return tunnel_gateway_;
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
    const auto advertised_tuntom = value["features"].toObject()["tuntom"];
    tuntom_remote_enabled_ = advertised_tuntom.isBool() ? int(advertised_tuntom.toBool()) : -1;
    tuntom_license_ = value["features"].toObject()["tuntom_license"].toString();
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
