#include "main_window.hpp"

#include <QApplication>

int main(int argc, char* argv[])
{
    QApplication application(argc, argv);
    QApplication::setApplicationName(QStringLiteral("Skewer"));
    QApplication::setOrganizationName(QStringLiteral("Saslik"));

    MainWindow window;
    window.show();
    return application.exec();
}
