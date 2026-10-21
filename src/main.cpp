#include "main_window.hpp"
#include "tui.hpp"
#include "launcher.hpp"
#include "session_status.hpp"
#include "pairing.hpp"

#include <QApplication>
#include <QIcon>
#include <cstdio>
#include <cstring>
#include <unistd.h>
#include <vector>
#include <QDir>
#include <QSettings>
#include <QTextStream>
#include <QThread>

static int connectionCommand(const QStringList& arguments)
{
    const bool attach = arguments[1] == "attach";
    bool cleanup = !attach || QSettings().value("connections/cleanupOnAttach",false).toBool();
    bool yes = false, preview = false;
    QVector<pid_t> pids;
    for (const auto& argument : arguments.sliced(2)) {
        if (argument == "--yes") yes = true;
        else if (argument == "--dry-run" && !attach) preview = true;
        else if (argument == "--cleanup" && attach) cleanup = true;
        else if (argument == "--no-cleanup" && attach) cleanup = false;
        else {
            bool valid; int pid = argument.toInt(&valid);
            if (!valid || pid <= 1) { QTextStream(stderr) << "Invalid PID or option: " << argument << '\n'; return 2; }
            if (!pids.contains(pid)) pids << pid;
        }
    }
    if (pids.isEmpty()) {
        QTextStream(stderr) << "Usage: skewer attach PID... [--cleanup|--no-cleanup] [--yes]\n"
            "       skewer cleanup PID... [--dry-run] [--yes]\n"; return 2;
    }
    if (cleanup && !preview && !yes) {
        if (!isatty(STDIN_FILENO)) { QTextStream(stderr) << "TCP cleanup requires --yes in scripts. Transfers may be interrupted; reconnection is not guaranteed.\n"; return 2; }
        QTextStream(stdout) << "Close old TCP connections? Transfers will be interrupted; reconnection is NOT guaranteed. [y/N] " << Qt::flush;
        if (QTextStream(stdin).readLine().trimmed().toLower() != "y") return 1;
    }
    if (attach) {
        const auto result = CgroupManager().route(pids,"cli-attach");
        QTextStream(stdout) << result.detail << '\n';
        if (!result.ok) return 1;
        // systemd job completion is asynchronous; the helper still revalidates membership.
        if (cleanup) QThread::msleep(500);
    }
    if (!cleanup) return 0;
    const auto result = RoutingController().cleanupTcp(pids,RoutingController::Authorization::Terminal,preview);
    QTextStream(result.ok ? stdout : stderr) << result.detail << '\n';
    return result.ok ? 0 : 1;
}

int main(int argc, char* argv[])
{
    if (argc >= 2 && (std::strcmp(argv[1],"pair")==0 || std::strcmp(argv[1],"remote-status")==0)) {
        QCoreApplication application(argc,argv);
        application.setOrganizationName("Saslik");application.setApplicationName("Skewer");
        return pairingCommand(application.arguments());
    }
    if (argc >= 2 && (std::strcmp(argv[1],"attach") == 0 || std::strcmp(argv[1],"cleanup") == 0)) {
        QCoreApplication application(argc,argv);
        application.setOrganizationName("Saslik"); application.setApplicationName("Skewer");
        return connectionCommand(application.arguments());
    }
    if (argc >= 2 && (std::strcmp(argv[1], "status") == 0
        || std::strcmp(argv[1], "env") == 0 || std::strcmp(argv[1], "check") == 0)) {
        QCoreApplication application(argc, argv);
        application.setOrganizationName("Saslik");
        application.setApplicationName("Skewer");
        return sessionCommand(application.arguments());
    }
    // Shell sessions need neither a display server nor QApplication's plugins.
    if (argc >= 2 && (std::strcmp(argv[1], "shell") == 0 || std::strcmp(argv[1], "run") == 0)) {
        QCoreApplication application(argc, argv);
        const bool shell = std::strcmp(argv[1], "shell") == 0;
        QStringList command = application.arguments().sliced(2);
        if (!command.isEmpty() && command.first() == "--") command.removeFirst();
        if ((shell && !command.isEmpty()) || (!shell && command.isEmpty())) {
            std::fprintf(stderr, "usage: skewer shell | skewer run -- PROGRAM [ARGUMENTS...]\n"); return 2;
        }
        QStringList invocation = CgroupManager::routedLaunchPrefix(shell ? "shell" : command.first(), shell);
        // Also support an uninstalled build without changing the user's global PATH.
        qputenv("PATH", (QCoreApplication::applicationDirPath() + ':' + qEnvironmentVariable("PATH")).toLocal8Bit());
        if (!shell) invocation.append(command);
        QList<QByteArray> encoded;
        for (const auto& argument : invocation) encoded << argument.toLocal8Bit();
        std::vector<char*> pointers;
        for (auto& argument : encoded) pointers.push_back(argument.data());
        pointers.push_back(nullptr);
        execvp(pointers[0], pointers.data());
        std::perror("skewer launch"); return 1;
    }
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
    const bool launcher_only = arguments.contains(QStringLiteral("--launcher"));
    const bool headless = qEnvironmentVariableIsEmpty("DISPLAY")
        && qEnvironmentVariableIsEmpty("WAYLAND_DISPLAY");
    const bool tui = force_tui || (!force_gui && !launcher_only && headless);
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
    if (launcher_only) {
        Launcher launcher;
        launcher.setWindowTitle("Skewer Launcher");
        launcher.resize(660, 340);
        launcher.show();
        return application.exec();
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
