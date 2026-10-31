#include "launch_catalog.hpp"
#include <QAbstractItemModelTester>
#include <QApplication>
#include <QPersistentModelIndex>
#include <QSignalSpy>
#include <QLineEdit>
#include <QTest>
#include <QAbstractItemView>
#include <iostream>
#include <stdexcept>

namespace {
void require(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}
} // namespace

int main(int argc, char** argv) {
    QApplication application(argc, argv);
    try {
        using namespace skewer::ui;
        LaunchCatalog catalog(nullptr, 3);
        QAbstractItemModelTester tester(&catalog, QAbstractItemModelTester::FailureReportingMode::Fatal);
        const QVector<ProcessRecord> records{
            {1, 1, 0, "renderer", "C:/one/browser.exe", {}},
            {2, 2, 0, "Friendly Browser", "C:/one/browser.exe", {"Window"}},
            {3, 3, 0, "Friendly Browser", "C:/two/browser.exe", {"Other window"}},
            {0, 0, 0, "Invalid", "invalid.exe", {}},
            {4, 4, 0, "Unknown", {}, {}},
        };
        catalog.remember(records);
        require(catalog.rowCount() == 2, "Executable identity was merged or duplicated");
        require(catalog.item(0)->text().startsWith("Friendly Browser"), "Helper label replaced app name");
        ApplicationCompleter completer(&catalog);
        completer.setCompletionPrefix("FRIENDLY");
        require(completer.completionCount() == 2, "Name matching failed");
        require(completer.pathFromIndex(completer.completionModel()->index(0, 0)) == "C:/one/browser.exe",
                "Completion returned a display label instead of executable path");
        completer.setCompletionPrefix("two/browser");
        require(completer.completionCount() == 1, "Path matching failed");

        // Exercise QLineEdit's real completion path, not only the catalog data.
        QLineEdit input;
        input.setCompleter(&completer);
        input.show();
        input.setFocus();
        application.processEvents();
        QTest::keyClicks(&input, "Friendly");
        application.processEvents();
        completer.popup()->setCurrentIndex(completer.completionModel()->index(0, 0));
        QTest::keyClick(completer.popup(), Qt::Key_Return);
        application.processEvents();
        if (input.text() != "C:/one/browser.exe") {
            throw std::runtime_error("Unexpected completed input: " + input.text().toStdString());
        }
        input.hide();

        QPersistentModelIndex stable(catalog.index(0, 0));
        QSignalSpy reset(&catalog, &QAbstractItemModel::modelReset);
        catalog.remember(records);
        require(stable.isValid() && reset.isEmpty(), "Unchanged scan reset completion model");
        catalog.remember({});
        require(catalog.rowCount() == 2, "Exited applications disappeared from session history");
        catalog.remember({{5, 5, 0, "Third", "third.exe", {"Third window"}},
                          {6, 6, 0, "Fourth", "fourth.exe", {"Fourth window"}}});
        require(catalog.rowCount() == 3, "Session history exceeded capacity");
        require(catalog.item(0)->data(LaunchCatalog::ExecutableRole).toString() == "fourth.exe",
                "Currently observed applications did not take precedence");
        require(completer.pathFromIndex({}).isEmpty(), "Invalid completion produced a command");
        std::cout << "PASS: named completion, distinct paths, helper labels, refresh stability and bounded "
                     "history\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
