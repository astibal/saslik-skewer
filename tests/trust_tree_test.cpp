#include "trust_tree_update.hpp"
#include <QApplication>

int main(int argc, char** argv)
{
    QApplication app(argc, argv);
    QTreeWidget tree;
    TrustTreeUpdate initial(&tree);
    auto* group = initial.get("app:firefox");
    auto* profile = initial.get("store:profile", group);
    initial.get("store:obsolete", group);
    initial.finish();
    tree.setCurrentItem(profile);
    group->setExpanded(false);
    TrustTreeUpdate refresh(&tree);
    if (refresh.get("app:firefox") != group || refresh.get("store:profile", group) != profile) return 1;
    refresh.get("store:new", group);
    refresh.finish();
    if (tree.currentItem() != profile || group->isExpanded() || group->childCount() != 2) return 2;
    TrustTreeUpdate moved(&tree);
    auto* other = moved.get("app:renamed");
    if (moved.get("store:profile", other) != profile) return 3;
    moved.finish();
    if (tree.topLevelItemCount() != 1 || other->childCount() != 1 || profile->parent() != other) return 4;
    return 0;
}
