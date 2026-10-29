#pragma once

#include <QStandardItemModel>
#include <QTreeView>
#include <QVector>
#include <QStringList>
#include <QWidget>
#include <QSet>
#include <optional>

namespace skewer::ui {

// No Unix IDs, cgroups or Win32 handles cross the presentation boundary.
struct ProcessRecord {
    quint64 pid{}, created{}, parent{};
    QString name, executable;
    QStringList windows;
    bool operator==(const ProcessRecord&) const = default;
    QString identity() const;
};

class ProcessBrowser final : public QWidget {
public:
    enum Role { IdentityRole = Qt::UserRole + 1, ExecutableRole };
    explicit ProcessBrowser(QWidget* parent = nullptr, QTreeView* view = nullptr);
    void setProcesses(QVector<ProcessRecord> processes);
    void setRoutingState(bool available, const QString& routed_identity = {});
    void setRoutingSelections(bool available, const QStringList& identities);
    void setFilterText(const QString& text);
    QStringList launchSuggestions() const;
    const QVector<ProcessRecord>& processes() const { return records_; }
    std::optional<ProcessRecord> selectedProcess() const;
    QTreeView* tree() const { return tree_; }
    QStandardItemModel* model() { return &model_; }

private:
    struct ViewState {
        QSet<QString> expanded;
        QSet<QString> seen;
        QString selected;
        int scroll{};
    };

    ViewState captureViewState() const;
    void restoreViewState(const ViewState& state);
    void rebuildModel();

    QStandardItemModel model_;
    QTreeView* tree_;
    QVector<ProcessRecord> records_;
    bool initialized_{};
    bool routing_available_{};
    QStringList routed_identities_;
    QString filter_;
};
} // namespace skewer::ui
