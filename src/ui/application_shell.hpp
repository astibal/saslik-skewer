#pragma once

#include <QAction>
#include <QApplication>
#include <QCloseEvent>
#include <QLabel>
#include <QMainWindow>
#include <QMenuBar>
#include <QPainter>
#include <QSettings>
#include <QStatusBar>
#include <QSystemTrayIcon>
#include <QTabWidget>

namespace skewer::ui {
// The shared window owns presentation and lifecycle, never network policy.
// Platform controllers populate pages and handle Preferences themselves.
class ApplicationShell : public QMainWindow {
public:
    explicit ApplicationShell(const QString& version, QWidget* parent = nullptr) : QMainWindow(parent) {
        setWindowTitle(tr("Skewer"));
        resize(980, 680);
        QSettings settings;
        restoreGeometry(settings.value("window/geometry").toByteArray());
        tabs_ = new QTabWidget(this);
        setCentralWidget(tabs_);
        auto* menu = menuBar()->addMenu(tr("Settings"));
        preferences_action_ = menu->addAction(tr("Preferences…"));
        preferences_action_->setObjectName("preferencesAction");
        menu->addSeparator();
        close_to_tray_ = menu->addAction(tr("Close to system tray"));
        close_to_tray_->setObjectName("closeToTray");
        close_to_tray_->setCheckable(true);
        close_to_tray_->setChecked(settings.value("window/closeToTray", true).toBool());
        connect(close_to_tray_, &QAction::toggled, this,
                [](bool enabled) { QSettings().setValue("window/closeToTray", enabled); });
        tray_ = new QSystemTrayIcon(this);
        tray_->setObjectName("skewerTray");
        tray_->setToolTip(tr("Skewer"));
        auto* tray_menu = new QMenu(this);
        const auto restore = [this] {
            showNormal();
            raise();
            activateWindow();
        };
        connect(tray_menu->addAction(tr("Show Skewer")), &QAction::triggered, this, restore);
        tray_menu->addSeparator();
        const auto quit = [this] {
            // Exiting the UI does not release applications or disable routing.
            quitting_ = true;
            close();
            QApplication::quit();
        };
        connect(tray_menu->addAction(tr("Quit")), &QAction::triggered, this, quit);
        connect(menu->addAction(tr("Quit")), &QAction::triggered, this, quit);
        tray_->setContextMenu(tray_menu);
        connect(tray_, &QSystemTrayIcon::activated, this, [restore](auto reason) {
            if (reason == QSystemTrayIcon::Trigger || reason == QSystemTrayIcon::DoubleClick) {
                restore();
            }
        });
        updateTrayIcon();
        if (QSystemTrayIcon::isSystemTrayAvailable()) {
            tray_->show();
        }
        auto* label = new QLabel(tr("Skewer %1").arg(version), this);
        label->setObjectName("applicationVersion");
        label->setTextInteractionFlags(Qt::TextSelectableByMouse);
        statusBar()->addWidget(label);
    }
    QTabWidget* pages() const { return tabs_; }
    QAction* preferencesAction() const { return preferences_action_; }
    void addUnavailablePage(const QString& title, const QString& explanation) {
        auto* label = new QLabel(explanation, tabs_);
        label->setWordWrap(true);
        label->setMargin(24);
        label->setAlignment(Qt::AlignTop | Qt::AlignLeft);
        const int index = tabs_->addTab(label, title);
        tabs_->setTabToolTip(index, explanation);
    }

protected:
    void closeEvent(QCloseEvent* event) override {
        QSettings().setValue("window/geometry", saveGeometry());
        if (!quitting_ && close_to_tray_->isChecked() && QSystemTrayIcon::isSystemTrayAvailable()) {
            event->ignore();
            hide();
            return;
        }
        QMainWindow::closeEvent(event);
    }
    void changeEvent(QEvent* event) override {
        QMainWindow::changeEvent(event);
        if (event->type() == QEvent::PaletteChange) {
            updateTrayIcon();
        }
    }
    void updateTrayIcon() {
        if (!tray_) {
            return;
        }
        QIcon icon(QStringLiteral(":/icons/skewer.svg"));
        if (!icon.isNull() && palette().color(QPalette::Window).lightness() < 128) {
            // Keep the fork silhouette legible without a separate dark-theme asset.
            QIcon monochrome;
            for (const int size : {16, 22, 24, 32, 48, 64, 128}) {
                QPixmap pixmap = icon.pixmap(size, size);
                QPainter painter(&pixmap);
                painter.setCompositionMode(QPainter::CompositionMode_SourceIn);
                painter.fillRect(pixmap.rect(), palette().color(QPalette::WindowText));
                painter.end();
                monochrome.addPixmap(pixmap);
            }
            icon = monochrome;
        }
        setWindowIcon(icon);
        tray_->setIcon(icon);
    }
    QSystemTrayIcon* tray_{};
    QAction* close_to_tray_{};
    bool quitting_{};

private:
    QTabWidget* tabs_{};
    QAction* preferences_action_{};
};
} // namespace skewer::ui
