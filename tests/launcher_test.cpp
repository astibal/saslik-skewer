#include "launcher.hpp"
#include <QApplication>
#include <QTemporaryDir>
#include <QFile>
#include <QDir>
#include <QLineEdit>
#include <QListWidget>
#include <QLabel>
#include <QTimer>
#include <QEventLoop>

int main(int argc, char** argv)
{
    QTemporaryDir directory;
    qputenv("XDG_DATA_HOME", directory.path().toUtf8());
    QDir().mkpath(directory.path() + "/applications");
    QFile desktop(directory.path() + "/applications/test-mail.desktop");
    if (!desktop.open(QIODevice::WriteOnly)) return 1;
    desktop.write("[Desktop Entry]\nType=Application\nName=Test Mail\nExec=/bin/true\nKeywords=thunderbird;email;\n");
    desktop.close();
    QApplication app(argc, argv);
    Launcher launcher;
    launcher.findChild<QLineEdit*>("launcherSearch")->setText("THUNDERBIRD email");
    auto* results = launcher.findChild<QListWidget*>("launcherResults");
    // Typing must not enumerate desktop entries or build an application list.
    if (results) return 2;
    auto* status = launcher.findChild<QLabel*>("launcherStatus");
    auto* timeout = launcher.findChild<QTimer*>("launcherStatusTimeout");
    if (!status || !status->isHidden() || !timeout || !timeout->isSingleShot()
        || timeout->interval() != 5000) return 8;
    status->setText("Launch requested: test");
    status->show();
    timeout->start(1);
    QEventLoop loop;
    QTimer::singleShot(30, &loop, &QEventLoop::quit);
    loop.exec();
    if (!status->isHidden() || !status->text().isEmpty()) return 9;
    auto* input = launcher.findChild<QLineEdit*>("launcherSearch");
    input->setText("skewer-nonexistent-command-7d24");
    QMetaObject::invokeMethod(input, "returnPressed", Qt::DirectConnection);
    if (status->isHidden() || !status->text().contains("Command not found")
        || timeout->isActive() || input->text().isEmpty()) return 10;
    QString error;
    if (Launcher::menuInstalled()) return 3;
    if (!Launcher::setMenuInstalled(true, error) || !Launcher::menuInstalled()) return 4;
    if (!Launcher::setMenuInstalled(false, error) || QFile::exists(Launcher::menuPath())) return 5;
    QFile foreign(Launcher::menuPath());
    if (!foreign.open(QIODevice::WriteOnly)) return 6;
    foreign.write("foreign data"); foreign.close();
    if (Launcher::setMenuInstalled(true, error) || Launcher::setMenuInstalled(false, error)) return 7;
    return 0;
}
