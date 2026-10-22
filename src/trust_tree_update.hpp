#pragma once
#include <QHash>
#include <QSet>
#include <QTreeWidget>

// Reconcile by stable identity, preserving selection and expansion of survivors.
class TrustTreeUpdate {
public:
    static constexpr int IdentityRole = Qt::UserRole + 1;
    explicit TrustTreeUpdate(QTreeWidget* tree) : tree_(tree) {
        const auto visit = [&](const auto& self, QTreeWidgetItem* item) -> void {
            existing_.insert(item->data(0, IdentityRole).toString(), item);
            for (int i = 0; i < item->childCount(); ++i) self(self, item->child(i));
        };
        for (int i = 0; i < tree_->topLevelItemCount(); ++i) visit(visit, tree_->topLevelItem(i));
    }
    QTreeWidgetItem* get(const QString& key, QTreeWidgetItem* parent = nullptr) {
        auto* item = existing_.value(key);
        if (!item) {
            item = parent ? new QTreeWidgetItem(parent) : new QTreeWidgetItem(tree_);
            item->setData(0, IdentityRole, key);
            item->setExpanded(true);
            existing_.insert(key, item);
        } else if (item->parent() != parent) {
            if (auto* old = item->parent()) old->takeChild(old->indexOfChild(item));
            else tree_->takeTopLevelItem(tree_->indexOfTopLevelItem(item));
            if (parent) parent->addChild(item); else tree_->addTopLevelItem(item);
        }
        retained_.insert(item);
        return item;
    }
    void finish() {
        const auto prune = [&](const auto& self, QTreeWidgetItem* parent) -> void {
            for (int i = parent->childCount() - 1; i >= 0; --i) {
                auto* item = parent->child(i);
                if (!retained_.contains(item)) delete parent->takeChild(i);
                else self(self, item);
            }
        };
        prune(prune, tree_->invisibleRootItem());
    }
private:
    QTreeWidget* tree_;
    QHash<QString, QTreeWidgetItem*> existing_;
    QSet<QTreeWidgetItem*> retained_;
};
