#include "preferences_dialog.hpp"
#include "preferences_values.hpp"
#include "tuntom_binary.hpp"
#include <QApplication>
#include <QCheckBox>
#include <QDialogButtonBox>
#include <QLineEdit>
#include <QLabel>
#include <QFile>
#include <QPushButton>
#include <QSpinBox>
#include <QTemporaryDir>

int main(int argc, char** argv)
{
    QApplication app(argc, argv);
    QTemporaryDir temporary;
    if (!temporary.isValid()) return 1;
    QSettings::setDefaultFormat(QSettings::IniFormat);
    QSettings::setPath(QSettings::IniFormat, QSettings::UserScope, temporary.path());
    app.setOrganizationName("SkewerTest");
    app.setApplicationName("Preferences");
    {
        PreferencesDialog dialog;
        auto* path = dialog.findChild<QLineEdit*>("tunnel/binary");
        if (!path || path->text() != "/usr/libexec/saslik/tuntom") return 2;
        path->setText("/opt/tuntom/tuntom");
        dialog.reject();
        if (QSettings().contains("tunnel/binary")) return 3;
    }
    {
        PreferencesDialog dialog;
        dialog.findChild<QLineEdit*>("tunnel/binary")->setText("/opt/tuntom/tuntom");
        dialog.findChild<QSpinBox*>("refresh/processSeconds")->setValue(12);
        dialog.findChild<QCheckBox*>("routing/resumeOnStartup")->setChecked(false);
        dialog.findChild<QDialogButtonBox*>()->button(QDialogButtonBox::Ok)->click();
        if (dialog.result() != QDialog::Accepted) return 4;
    }
    if (Preferences::tuntomBinary() != "/opt/tuntom/tuntom"
        || Preferences::number("refresh/processSeconds", 5, 2, 60) != 12
        || QSettings().value("routing/resumeOnStartup").toBool()) return 5;
    {
        PreferencesDialog restored;
        if (restored.findChild<QLineEdit*>("tunnel/binary")->text() != "/opt/tuntom/tuntom") return 6;
        restored.findChild<QDialogButtonBox*>()->button(QDialogButtonBox::RestoreDefaults)->click();
        if (restored.findChild<QSpinBox*>("refresh/processSeconds")->value() != 5) return 12;
        restored.reject();
        if (Preferences::tuntomBinary() != "/opt/tuntom/tuntom") return 13;
    }
    QSettings().setValue("refresh/processSeconds", -100);
    if (Preferences::number("refresh/processSeconds", 5, 2, 60) != 2) return 7;
    QSettings().setValue("refresh/processSeconds", "broken");
    if (Preferences::number("refresh/processSeconds", 5, 2, 60) != 5) return 8;
    QString error;
    if (!Tuntom::checkedBinary("relative/tuntom", error).isEmpty() || error.isEmpty()) return 9;
    if (!Tuntom::checkedBinary("/usr/bin/env", error).isEmpty() || error.isEmpty()) return 10;
    if (!Tuntom::checkedBinary(temporary.path() + "/missing/tuntom", error).isEmpty()) return 11;
    QFile executable(temporary.path() + "/tuntom");
    if (!executable.open(QIODevice::WriteOnly)) return 14;
    executable.write("test executable");
    executable.close();
    executable.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner);
    // Either the file is user-owned or /tmp is writable: neither is safe for root execution.
    if (!Tuntom::checkedBinary(executable.fileName(), error).isEmpty()) return 15;
    {
        PreferencesDialog dialog;
        auto* path = dialog.findChild<QLineEdit*>("tunnel/binary");
        auto* risk = dialog.findChild<QCheckBox*>("tunnelRiskAcknowledged");
        auto* ok = dialog.findChild<QDialogButtonBox*>()->button(QDialogButtonBox::Ok);
        path->setText(executable.fileName());
        if (!risk || risk->isChecked()) return 16;
        if (Tuntom::developmentBinaryAllowed && (risk->isHidden() || ok->isEnabled())) return 21;
        if (!Tuntom::developmentBinaryAllowed && (!risk->isHidden() || !ok->isEnabled())) return 22;
        if (!dialog.findChild<QLabel*>("tunnelBinaryStatus")->text().startsWith("Not ready:")) return 17;
        risk->setChecked(true);
        if (!ok->isEnabled()) return 18;
        path->setText(executable.fileName() + " ");
        if (risk->isChecked() || (Tuntom::developmentBinaryAllowed && ok->isEnabled())) return 19;
        path->setText(temporary.path() + "/missing/tuntom");
        if (!risk->isHidden() || !ok->isEnabled()) return 20;
        dialog.reject();
    }
    {
        PreferencesDialog dialog;
        dialog.findChild<QLineEdit*>("tunnel/binary")->setText(executable.fileName());
        dialog.findChild<QCheckBox*>("tunnelRiskAcknowledged")->setChecked(true);
        dialog.findChild<QDialogButtonBox*>()->button(QDialogButtonBox::Ok)->click();
        if (Preferences::developmentBinaryAcknowledged() != Tuntom::developmentBinaryAllowed) return 23;
        QSettings().setValue("tunnel/binary", executable.fileName()+".other");
        if (Preferences::developmentBinaryAcknowledged()) return 24;
    }
}
