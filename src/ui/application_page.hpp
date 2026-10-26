#pragma once

#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QTreeView>
#include <QVBoxLayout>

namespace skewer::ui {
// Shared Applications layout; platform controllers provide data and actions.
class ApplicationPage final : public QWidget {
public:
    explicit ApplicationPage(QWidget* parent = nullptr) : QWidget(parent) {
        auto* layout = new QVBoxLayout(this);
        layout->setContentsMargins(18, 18, 18, 14);
        layout->setSpacing(10);
        auto* title = new QLabel(tr("Skewer applications through Saslik"), this);
        auto font = title->font();
        font.setPointSize(font.pointSize() + 5);
        font.setBold(true);
        title->setFont(font);
        layout->addWidget(title);
        top = new QVBoxLayout;
        layout->addLayout(top);
        search = new QLineEdit(this);
        search->setObjectName("applicationSearch");
        search->setAccessibleName(tr("Find application"));
        search->setPlaceholderText(tr("Find an application or process…"));
        search->setClearButtonEnabled(true);
        layout->addWidget(search);
        process_layout_ = new QVBoxLayout;
        layout->addLayout(process_layout_, 1);
        tree = new QTreeView(this);
        tree->setObjectName("applicationTree");
        process_layout_->addWidget(tree);
        auto* actions = new QHBoxLayout;
        action_status = new QLabel(tr("Select an application to manage its routing."), this);
        action_status->setObjectName("actionStatus");
        action_status->setWordWrap(true);
        attach = new QPushButton(tr("Attach to Skewer"), this);
        release = new QPushButton(tr("Release"), this);
        attach->setEnabled(false);
        release->setEnabled(false);
        actions->addWidget(action_status, 1);
        actions->addWidget(release);
        actions->addWidget(attach);
        layout->addLayout(actions);
        footer = new QVBoxLayout;
        layout->addLayout(footer);
    }
    void setProcessWidget(QWidget* widget) {
        process_layout_->removeWidget(tree);
        process_layout_->addWidget(widget);
    }
    QVBoxLayout* top{};
    QVBoxLayout* footer{};
    QTreeView* tree{};
    QLineEdit* search{};
    QLabel* action_status{};
    QPushButton* attach{};
    QPushButton* release{};

private:
    QVBoxLayout* process_layout_{};
};
} // namespace skewer::ui
