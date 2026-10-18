#include "main_window.hpp"

#include "application_model.hpp"

#include <QApplication>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QProcess>
#include <QPushButton>
#include <QSortFilterProxyModel>
#include <QTreeView>
#include <QVBoxLayout>

MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent)
{
    setWindowTitle(tr("Skewer"));
    resize(980, 680);

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

    connect(search_, &QLineEdit::textChanged, filtered_model_,
            &QSortFilterProxyModel::setFilterFixedString);

    auto* launcher = new QHBoxLayout;
    command_ = new QLineEdit(central);
    command_->setPlaceholderText(tr("Run an application through Skewer…"));
    auto* run = new QPushButton(tr("Run"), central);
    launcher->addWidget(command_, 1);
    launcher->addWidget(run);
    layout->addLayout(launcher);
    connect(run, &QPushButton::clicked, this, &MainWindow::launchCommand);
    connect(command_, &QLineEdit::returnPressed, this, &MainWindow::launchCommand);

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
        "QTreeView { font-size: 10pt; }"));
}

void MainWindow::launchCommand()
{
    const QString command = command_->text().trimmed();
    if (command.isEmpty()) {
        return;
    }
    if (!QProcess::startDetached(QStringLiteral("/bin/sh"),
                                 {QStringLiteral("-lc"), command})) {
        QMessageBox::warning(this, tr("Skewer"),
                             tr("The command could not be started."));
        return;
    }
    command_->clear();
}
