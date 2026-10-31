#include "../../src/ui/application_shell.hpp"
#include "../../src/ui/application_page.hpp"
#include <QTemporaryDir>
#include <iostream>
#include <stdexcept>

void require(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}
int main(int argc, char** argv) {
    QApplication app(argc, argv);
    app.setOrganizationName("SkewerTests");
    app.setApplicationName("SharedShell");
    QTemporaryDir directory;
    QSettings::setDefaultFormat(QSettings::IniFormat);
    QSettings::setPath(QSettings::IniFormat, QSettings::UserScope, directory.path());
    QSettings().setValue("window/closeToTray", false);
    try {
        skewer::ui::ApplicationShell shell("test-version");
        auto* page = new skewer::ui::ApplicationPage(&shell);
        shell.pages()->addTab(page, "Applications");
        shell.addUnavailablePage("CA Trust", "Unsupported on test backend");
        require(shell.pages()->count() == 2, "Shared tabs missing");
        require(shell.findChild<QLabel*>("applicationVersion")->text().contains("test-version"),
                "Version missing");
        require(!page->attach->isEnabled() && !page->release->isEnabled(),
                "Unsupported actions enabled by default");
        require(shell.preferencesAction()->objectName() == "preferencesAction", "Preferences hook missing");
        shell.show();
        app.processEvents();
        shell.resize(1100, 750);
        app.processEvents();
        require(page->tree->width() > 900, "Shared tree did not grow with window");
        shell.close();
        app.processEvents();
        require(!shell.isVisible(), "Close-to-tray=false did not close window");
        require(!QSettings().value("window/geometry").toByteArray().isEmpty(), "Geometry not saved");
        std::cout << "PASS: shared tabs, version, capability defaults, preferences hook, resize and close "
                     "lifecycle\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
