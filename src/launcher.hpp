#pragma once
#include <QWidget>
#include <QStringList>

// Shared by the main window and the optional standalone launcher.
class Launcher final : public QWidget {
public:
    explicit Launcher(QWidget* parent = nullptr);
    static QString menuPath();
    static bool menuInstalled();
    static bool setMenuInstalled(bool enabled, QString& error);
};
