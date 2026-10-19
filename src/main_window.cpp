#include "main_window.hpp"

#include "application_model.hpp"

#include <QApplication>
#include <QCompleter>
#include <QCloseEvent>
#include <QComboBox>
#include <QDateTime>
#include <QFileDialog>
#include <QGroupBox>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QJsonDocument>
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
#include <QUrlQuery>
#include <QTreeView>
#include <QVBoxLayout>

MainWindow::MainWindow(const QString& connect_url, QWidget* parent)
    : QMainWindow(parent)
{
    setWindowTitle(tr("Skewer"));
    resize(980, 680);
    QSettings settings;
    restoreGeometry(settings.value(QStringLiteral("window/geometry")).toByteArray());

    auto* central = new QWidget(this);
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
    connect(routing_up_, &QPushButton::clicked, this, &MainWindow::activateRouting);
    connect(routing_down_, &QPushButton::clicked, this, &MainWindow::deactivateRouting);
    routing_status_bar_ = new QLabel(this);
    statusBar()->addPermanentWidget(routing_status_bar_);
    connect(routing_source_, &QComboBox::currentIndexChanged,
            this, &MainWindow::updateRoutingSource);
    network_ = new QNetworkAccessManager(this);
    connect(network_, &QNetworkAccessManager::finished, this, &MainWindow::receiveSaslik);
    if (!connect_url.isEmpty()) {
        const QUrl url(connect_url);
        const QString discovery = QUrlQuery(url).queryItemValue(QStringLiteral("discovery"));
        if (url.scheme() == QStringLiteral("skewer") && !discovery.isEmpty()) {
            routing_source_->setCurrentIndex(1);
            saslik_url_->setText(discovery);
            routing_requested_ = true;
            initial_settings.setValue(QStringLiteral("routing/mode"), QStringLiteral("saslik"));
            initial_settings.setValue(QStringLiteral("routing/saslikUrl"), discovery);
            initial_settings.setValue(QStringLiteral("routing/requested"), true);
        }
    }
    updateRoutingSource();
    routing_watchdog_ = new QTimer(this);
    routing_watchdog_->setInterval(2000);
    connect(routing_watchdog_, &QTimer::timeout, this, [this] {
        if (usesSaslikUrl()) pollSaslik();
        updateRoutingStatus();
    });
    routing_watchdog_->start();
    if (usesSaslikUrl()) pollSaslik();
    updateRoutingStatus();

    model_ = new ApplicationModel(this);
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
    tree_->header()->setSectionResizeMode(ApplicationModel::NameColumn,
                                          QHeaderView::ResizeToContents);
    tree_->header()->setSectionResizeMode(ApplicationModel::ProcessIdColumn,
                                          QHeaderView::ResizeToContents);
    tree_->header()->setSectionResizeMode(ApplicationModel::RoutingColumn,
                                          QHeaderView::ResizeToContents);
    tree_->header()->setSectionResizeMode(ApplicationModel::CommandColumn,
                                          QHeaderView::Stretch);
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

    connect(search_, &QLineEdit::textChanged, filtered_model_,
            &QSortFilterProxyModel::setFilterFixedString);

    auto* launcher = new QHBoxLayout;
    command_ = new QLineEdit(central);
    command_->setPlaceholderText(tr("Run an application through Skewer…"));
    launcher_model_ = new QStringListModel(model_->launcherSuggestions(), this);
    auto* completer = new QCompleter(launcher_model_, command_);
    completer->setCaseSensitivity(Qt::CaseInsensitive);
    completer->setFilterMode(Qt::MatchContains);
    completer->setCompletionMode(QCompleter::PopupCompletion);
    command_->setCompleter(completer);
    auto* run = new QPushButton(tr("Run"), central);
    auto* browse = new QPushButton(tr("Browse…"), central);
    launcher->addWidget(command_, 1);
    launcher->addWidget(browse);
    launcher->addWidget(run);
    layout->addLayout(launcher);
    connect(run, &QPushButton::clicked, this, &MainWindow::launchCommand);
    connect(browse, &QPushButton::clicked, this, &MainWindow::browseExecutable);
    connect(command_, &QLineEdit::returnPressed, this, &MainWindow::launchCommand);
    connect(model_, &ApplicationModel::launcherSuggestionsChanged,
            this, &MainWindow::updateLauncherSuggestions);

    auto* note = new QLabel(
        tr("Attaching a running application only affects newly created sockets. "
           "For reliable routing, launch the application through Skewer."),
        central);
    note->setWordWrap(true);
    note->setObjectName(QStringLiteral("routingNote"));
    layout->addWidget(note);

    setCentralWidget(central);
    setStyleSheet(QStringLiteral(
        "QLabel#routingNote { color: palette(window-text); padding-top: 4px; }"
        "QLabel#actionStatus { color: palette(window-text); }"
        "QLabel#routingStatus { color: palette(window-text); min-width: 58px; }"
        "QTreeView { font-size: 10pt; }"));
}

void MainWindow::closeEvent(QCloseEvent* event)
{
    QSettings settings;
    settings.setValue(QStringLiteral("window/geometry"), saveGeometry());
    settings.setValue(QStringLiteral("routing/nextHop"), next_hop_->text().trimmed());
    settings.setValue(QStringLiteral("routing/saslikUrl"), saslik_url_->text().trimmed());
    settings.setValue(QStringLiteral("routing/mode"),
                      usesSaslikUrl() ? QStringLiteral("saslik") : QStringLiteral("gateway"));
    QMainWindow::closeEvent(event);
}

void MainWindow::activateRouting()
{
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
    const QString next_hop = currentNextHop();
    const bool active = !next_hop.isEmpty() && routing_.active(next_hop);
    const bool reachable = !next_hop.isEmpty() && routing_.nextHopReachable(next_hop);
    QString text;
    QString color;
    if (active) {
        text = tr("● Routing active via %1").arg(next_hop);
        color = QStringLiteral("#63dc94");
    } else if (routing_requested_) {
        if (!discovery_warning_.isEmpty()) text = tr("● %1").arg(discovery_warning_);
        else if (usesSaslikUrl() && !discovery_online_) text = tr("● Waiting for Saslik…");
        else text = reachable ? tr("● Restoring routing…") : tr("● Gateway unavailable…");
        color = QStringLiteral("#e3b94f");
    } else {
        text = tr("○ Routing inactive");
        color = QStringLiteral("#899098");
    }
    routing_status_->setText(text);
    routing_status_bar_->setText(text);
    routing_status_->setStyleSheet(QStringLiteral("color:%1").arg(color));
    routing_status_bar_->setStyleSheet(QStringLiteral("color:%1; padding:0 6px").arg(color));
    routing_up_->setEnabled(!routing_requested_ && !active);
    routing_down_->setEnabled(routing_requested_ || active);
    routing_source_->setEnabled(!routing_requested_ && !active);
    next_hop_->setEnabled(!routing_requested_ && !active && !usesSaslikUrl());
    saslik_url_->setEnabled(!routing_requested_ && !active && usesSaslikUrl());

    const qint64 now = QDateTime::currentMSecsSinceEpoch();
    if (routing_requested_ && discovery_warning_.isEmpty()
        && (!usesSaslikUrl() || discovery_online_) && reachable && !active && !routing_repairing_
        && now - last_routing_repair_ms_ >= 5000) {
        last_routing_repair_ms_ = now;
        QTimer::singleShot(0, this, &MainWindow::repairRouting);
    }
}

void MainWindow::repairRouting()
{
    if (routing_repairing_) return;
    routing_repairing_ = true;
    const RoutingResult result = routing_.activate(currentNextHop(),
        RoutingController::Authorization::Desktop);
    routing_repairing_ = false;
    if (result.ok) action_status_->setText(tr("Routing restored after Saslik reconnect."));
    else action_status_->setText(tr("Routing restore failed: %1").arg(result.detail));
    updateRoutingStatus();
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
    const bool saslik = usesSaslikUrl();
    if (!saslik) {
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
    if (discovery_request_pending_) return;
    const QUrl url(saslik_url_->text().trimmed());
    if (!url.isValid() || (url.scheme() != QStringLiteral("http")
                           && url.scheme() != QStringLiteral("https"))) {
        discovery_online_ = false;
        discovery_warning_ = tr("Invalid Saslik URL");
        return;
    }
    discovery_request_pending_ = true;
    QNetworkRequest request(url);
    request.setTransferTimeout(1800);
    network_->get(request);
}

void MainWindow::receiveSaslik(QNetworkReply* reply)
{
    discovery_request_pending_ = false;
    const QByteArray payload = reply->readAll();
    const bool request_ok = reply->error() == QNetworkReply::NoError;
    reply->deleteLater();
    if (!request_ok) {
        discovery_online_ = false;
        discovery_warning_.clear();
        updateRoutingStatus();
        return;
    }
    QJsonParseError parse_error;
    const QJsonDocument document = QJsonDocument::fromJson(payload, &parse_error);
    const QJsonObject value = document.object();
    const QString gateway = value.value(QStringLiteral("gateway")).toString();
    const QString advertised_interface = value.value(QStringLiteral("host_interface")).toString();
    if (parse_error.error != QJsonParseError::NoError || gateway.isEmpty()
        || advertised_interface.isEmpty() || !value.value(QStringLiteral("available")).toBool()) {
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
    const bool routed = application && index.data(ApplicationModel::RoutedRole).toBool();
    route_button_->setEnabled(application && !routed);
    release_button_->setEnabled(application && routed);
    action_status_->setText(application
        ? (routed ? tr("This application is attached to the Skewer cgroup.")
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
    QVector<pid_t> pids;
    for (const QVariant& value : index.data(ApplicationModel::ProcessIdsRole).toList())
        pids.push_back(value.toInt());
    const CgroupResult result = cgroups_.route(pids, index.data().toString());
    action_status_->setText(result.detail);
    if (!result.ok) QMessageBox::warning(this, tr("Skewer"), result.detail);
    else model_->refresh();
}

void MainWindow::releaseSelection()
{
    const QModelIndex index = tree_->currentIndex().siblingAtColumn(0);
    QVector<pid_t> pids;
    for (const QVariant& value : index.data(ApplicationModel::ProcessIdsRole).toList())
        pids.push_back(value.toInt());
    const CgroupResult result = cgroups_.release(pids, index.data().toString());
    action_status_->setText(result.detail);
    if (!result.ok) QMessageBox::warning(this, tr("Skewer"), result.detail);
    else model_->refresh();
}
