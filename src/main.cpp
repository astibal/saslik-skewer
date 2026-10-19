#include "main_window.hpp"
#include "tui.hpp"

#include <QApplication>
#include <QIcon>
#include <cstdio>
#include <cstring>

int main(int argc, char* argv[])
{
    for (int index = 1; index < argc; ++index) {
        if (std::strcmp(argv[index], "--version") == 0) {
            std::printf("Skewer %s\n", SKEWER_VERSION);
            return 0;
        }
    }
    const QStringList arguments = [&] {
        QStringList values;
        for (int index = 1; index < argc; ++index) values.push_back(QString::fromLocal8Bit(argv[index]));
        return values;
    }();
    const bool force_tui = arguments.contains(QStringLiteral("--tui"));
    const bool force_gui = arguments.contains(QStringLiteral("--gui"));
    const bool headless = qEnvironmentVariableIsEmpty("DISPLAY")
        && qEnvironmentVariableIsEmpty("WAYLAND_DISPLAY");
    const bool tui = force_tui || (!force_gui && headless);
    if (tui) qputenv("QT_QPA_PLATFORM", "offscreen");

    QApplication application(argc, argv);
    QApplication::setApplicationName(QStringLiteral("Skewer"));
    QApplication::setApplicationVersion(QStringLiteral(SKEWER_VERSION));
    QApplication::setOrganizationName(QStringLiteral("Saslik"));
    QApplication::setDesktopFileName(QStringLiteral("org.saslik.Skewer"));
    QApplication::setWindowIcon(QIcon(QStringLiteral(":/icons/skewer.svg")));

    if (tui) {
        Tui interface;
        return interface.run();
    }
    QString connect_url;
    for (const QString& argument : arguments) {
        if (argument.startsWith(QStringLiteral("skewer://"))) {
            connect_url = argument;
            break;
        }
    }
    MainWindow window(connect_url);
    window.show();
    return application.exec();
}
