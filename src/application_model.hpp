#pragma once

#include "process_scanner.hpp"

#include <QAbstractItemModel>
#include <QIcon>
#include <QTimer>

#include <memory>
#include <vector>

class ApplicationModel final : public QAbstractItemModel {
    Q_OBJECT

public:
    enum Column { NameColumn, ProcessIdColumn, CommandColumn, ColumnCount };

    explicit ApplicationModel(QObject* parent = nullptr);

    [[nodiscard]] QModelIndex index(int row, int column,
                                    const QModelIndex& parent = {}) const override;
    [[nodiscard]] QModelIndex parent(const QModelIndex& child) const override;
    [[nodiscard]] int rowCount(const QModelIndex& parent = {}) const override;
    [[nodiscard]] int columnCount(const QModelIndex& parent = {}) const override;
    [[nodiscard]] QVariant data(const QModelIndex& index,
                                int role = Qt::DisplayRole) const override;
    [[nodiscard]] QVariant headerData(int section, Qt::Orientation orientation,
                                      int role) const override;

public slots:
    void refresh();

private:
    struct Node {
        ProcessInfo process;
        Node* parent{};
        std::vector<std::unique_ptr<Node>> children;
    };

    [[nodiscard]] Node* node(const QModelIndex& index) const;
    [[nodiscard]] static bool isLikelyApplication(const ProcessInfo& process);

    ProcessScanner scanner_;
    std::vector<std::unique_ptr<Node>> roots_;
    QTimer refresh_timer_;
};
