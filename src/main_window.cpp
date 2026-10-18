#include "main_window.hpp"

#include "application_model.hpp"

#include <QApplication>
#include <QCompleter>
#include <QCloseEvent>
#include <QFileDialog>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QProcess>
#include <QPushButton>
#include <QSortFilterProxyModel>
#include <QSettings>
#include <QStringListModel>
#include <QTreeView>
#include <QVBoxLayout>

MainWindow::MainWindow(QWidget* parent)
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
        "QLabel#routingNote { color: palette(mid); padding-top: 4px; }"
        "QLabel#actionStatus { color: palette(mid); }"
        "QTreeView { font-size: 10pt; }"));
}

void MainWindow::closeEvent(QCloseEvent* event)
{
    QSettings settings;
    settings.setValue(QStringLiteral("window/geometry"), saveGeometry());
    QMainWindow::closeEvent(event);
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
