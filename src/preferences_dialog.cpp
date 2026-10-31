#include "preferences_dialog.hpp"
#include "support_package.hpp"
#include <QtConcurrent>
#include <QFutureWatcher>
#include "preferences_values.hpp"
#include "tuntom_binary.hpp"
#include <QCheckBox>
#include <QDialogButtonBox>
#include <QFileDialog>
#include <QFormLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPushButton>
#include <QSpinBox>
#include <QTabWidget>
#include <QVBoxLayout>

PreferencesDialog::PreferencesDialog(QWidget* parent) : QDialog(parent)
{
    setWindowTitle(tr("Preferences"));
    resize(620, 390);
    auto* layout = new QVBoxLayout(this);
    auto* tabs = new QTabWidget(this);
    layout->addWidget(tabs);
    auto page = [&](const QString& title) {
        auto* widget = new QWidget(tabs);
        auto* form = new QFormLayout(widget);
        tabs->addTab(widget, title);
        return form;
    };
    QSettings settings;
    struct Toggle { QCheckBox* widget; QString key; bool fallback; };
    struct Number { QSpinBox* widget; QString key; int fallback; };
    QList<Toggle> toggles;
    QList<Number> numbers;
    auto checkbox = [&](QFormLayout* form, const QString& title, const char* key, bool fallback) {
        auto* widget = new QCheckBox(title, this);
        widget->setObjectName(key);
        widget->setChecked(settings.value(key, fallback).toBool());
        form->addRow(widget);
        toggles.append({widget, key, fallback});
        return widget;
    };
    auto number = [&](QFormLayout* form, const QString& title, const char* key,
                      int fallback, int minimum, int maximum, const QString& suffix) {
        auto* widget = new QSpinBox(this);
        widget->setObjectName(key);
        widget->setRange(minimum, maximum);
        widget->setValue(Preferences::number(key, fallback, minimum, maximum));
        widget->setSuffix(suffix);
        form->addRow(title, widget);
        numbers.append({widget, key, fallback});
    };
    auto* general = page(tr("General"));
    checkbox(general, tr("Close to system tray"), "window/closeToTray", true);
    checkbox(general, tr("Resume requested routing at startup"), "routing/resumeOnStartup", true);
    number(general, tr("Tree font size"), "appearance/treeFontSize", 10, 8, 24, tr(" pt"));
    auto* cleanup = checkbox(general, tr("Reset affected TCP after Attach or exemption changes"), "connections/cleanupOnAttach", false);
    auto* warning = new QLabel(tr("TCP cleanup interrupts transfers. Applications are not guaranteed to reconnect. "
        "Startup resume may ask for authorization once."), this);
    warning->setWordWrap(true);
    general->addRow(warning);

    auto* refresh = page(tr("Refresh"));
    number(refresh, tr("Applications/processes"), "refresh/processSeconds", 5, 2, 60, tr(" s"));
    number(refresh, tr("Connections"), "refresh/connectionSeconds", 5, 2, 60, tr(" s"));
    number(refresh, tr("Routing status"), "refresh/routingSeconds", 5, 2, 60, tr(" s"));
    number(refresh, tr("Saslik status"), "refresh/saslikSeconds", 10, 5, 120, tr(" s"));
    number(refresh, tr("VM names"), "refresh/vmSeconds", 30, 10, 300, tr(" s"));
    auto* refresh_note = new QLabel(tr("These intervals affect UI discovery only. Tunnel health checks, "
        "fail-closed protection and helper recovery are unchanged."), this);
    refresh_note->setWordWrap(true);
    refresh->addRow(refresh_note);

    auto* tunnel = page(tr("Tunnel"));
    auto* binary = new QLineEdit(settings.value("tunnel/binary").toString(), this);
    binary->setPlaceholderText(tr("Automatic detection (leave empty)"));
    binary->setObjectName("tunnel/binary");
    auto* row = new QHBoxLayout;
    row->addWidget(binary, 1);
    auto* browse = new QPushButton(tr("Browse…"), this);
    row->addWidget(browse);
    tunnel->addRow(tr("Tuntom executable"), row);
    auto* check = new QLabel(this);
    check->setObjectName("tunnelBinaryStatus");
    check->setTextFormat(Qt::PlainText);
    check->setWordWrap(true);
    tunnel->addRow(check);
    auto* risk_note = new QLabel(Tuntom::developmentBinaryAllowed
        ? tr("Debug build: this executable can change between launches. Confirming permits running it directly "
             "as root after administrative authorization. Only select development code you trust.")
        : tr("Release build: this executable cannot run as root. Install a protected, root-owned copy. "
             "Development exceptions are disabled in both the client and privileged helper."), this);
    risk_note->setWordWrap(true);
    tunnel->addRow(risk_note);
    auto* risk = new QCheckBox(tr("I understand security risks"), this);
    risk->setObjectName("tunnelRiskAcknowledged");
    risk->setChecked(Preferences::developmentBinaryAcknowledged());
    tunnel->addRow(risk);
    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel
                                       | QDialogButtonBox::RestoreDefaults, this);
    const auto inspect = [binary, check, risk, risk_note, buttons] {
        QString error;
        const auto selected = binary->text().trimmed();
        const auto path = selected.isEmpty() ? Tuntom::detectBinary(error) : Tuntom::checkedBinary(selected, error);
        const bool warning = path.isEmpty() && QFileInfo(selected).exists();
        check->setText(path.isEmpty() ? tr("Not ready: %1").arg(error) : (selected.isEmpty() ? tr("Automatically detected: %1") : tr("Executable checks passed: %1")).arg(path));
        risk->setVisible(warning && Tuntom::developmentBinaryAllowed);
        risk_note->setVisible(warning);
        risk->setProperty("required", warning && Tuntom::developmentBinaryAllowed);
        buttons->button(QDialogButtonBox::Ok)->setEnabled(!risk->property("required").toBool() || risk->isChecked());
        if (warning && Tuntom::developmentBinaryAllowed && risk->isChecked()) {
            QString development_error;
            const auto development = Tuntom::checkedBinary(selected, development_error, true);
            check->setText(development.isEmpty() ? tr("Not ready: %1").arg(development_error)
                : tr("Debug exception enabled: %1 (runs as root)").arg(development));
        }
    };
    connect(binary, &QLineEdit::textChanged, this, [risk, inspect] {
        risk->setChecked(false);
        inspect();
    });
    connect(risk, &QCheckBox::toggled, this, inspect);
    connect(browse, &QPushButton::clicked, this, [this, binary, inspect] {
        const auto path = QFileDialog::getOpenFileName(this, tr("Select Tuntom"), binary->text());
        if (!path.isEmpty()) { binary->setText(path); inspect(); }
    });
    inspect();
    auto* tunnel_note = new QLabel((Tuntom::developmentBinaryAllowed
        ? tr("Debug build: a development executable is allowed only after acknowledging the warning for its path. ")
        : tr("Release build: requires a root-owned tuntom executable in protected directories. "))
        + tr("Leave the path empty to search /usr/bin/tuntom, /usr/libexec/saslik/tuntom, then /usr/libexec/tuntom. "
             "Missing paths may be saved before installation. The new path applies to the next tunnel start; "
             "a running tunnel is not restarted."), this);
    tunnel_note->setWordWrap(true);
    tunnel->addRow(tunnel_note);
    auto* troubleshoot = page(tr("Troubleshoot"));
    auto* explanation = new QLabel(tr("Save logs for a bug report, or include system, routing and DNS diagnostics. "
        "Exports stay on your computer. Review before sharing: they may include local paths, IP addresses and DNS domains. "
        "Credentials and pairing files are excluded."), this);
    explanation->setWordWrap(true);
    troubleshoot->addRow(explanation);
    auto* log_path = new QLabel(tr("Log directory: %1").arg(DiagnosticLog::directory()), this);
    log_path->setTextFormat(Qt::PlainText);
    log_path->setWordWrap(true);
    log_path->setTextInteractionFlags(Qt::TextSelectableByMouse);
    troubleshoot->addRow(log_path);
    auto* download_logs = new QPushButton(tr("Download logs"), this);
    download_logs->setObjectName("downloadLogs");
    auto* download_support = new QPushButton(tr("Download full support package"), this);
    download_support->setObjectName("downloadSupportPackage");
    auto* export_status = new QLabel(this);
    export_status->setObjectName("supportExportStatus");
    export_status->setTextFormat(Qt::PlainText);
    export_status->setWordWrap(true);
    troubleshoot->addRow(download_logs);
    troubleshoot->addRow(download_support);
    troubleshoot->addRow(export_status);
    auto export_package = [this, download_logs, download_support, export_status](bool full) {
        QString destination = QFileDialog::getSaveFileName(this, tr("Save support export"),
            QDir(QStandardPaths::writableLocation(QStandardPaths::DownloadLocation)).filePath(
                QString("skewer-%1-%2.zip").arg(full ? "support" : "logs", QDateTime::currentDateTimeUtc().toString("yyyyMMdd-HHmmss"))),
            tr("ZIP archives (*.zip)"));
        if (destination.isEmpty()) return;
        download_logs->setEnabled(false); download_support->setEnabled(false);
        export_status->setText(tr("Collecting diagnostics…"));
        auto* watcher = new QFutureWatcher<QString>(this);
        connect(watcher, &QFutureWatcher<QString>::finished, this, [=, this] {
            const auto error = watcher->result(); watcher->deleteLater();
            download_logs->setEnabled(true); download_support->setEnabled(true);
            export_status->setText(error.isEmpty() ? tr("Saved to %1").arg(destination) : tr("Export failed: %1").arg(error));
        });
        const auto version = QCoreApplication::applicationVersion();
        // No widgets captured by the worker: closing Preferences during export is safe.
        watcher->setFuture(QtConcurrent::run([full, destination, version] {
            return SupportPackage::save(destination, SupportPackage::collect(full, version));
        }));
    };
    connect(download_logs, &QPushButton::clicked, this, [export_package] { export_package(false); });
    connect(download_support, &QPushButton::clicked, this, [export_package] { export_package(true); });
    layout->addWidget(buttons);
    connect(buttons->button(QDialogButtonBox::RestoreDefaults), &QPushButton::clicked, this, [=] {
        for (const auto& item : toggles) item.widget->setChecked(item.fallback);
        for (const auto& item : numbers) item.widget->setValue(item.fallback);
        binary->clear();
        risk->setChecked(false);
        inspect();
    });
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
    connect(buttons, &QDialogButtonBox::accepted, this, [=, this] {
        inspect();
        if (risk->property("required").toBool() && !risk->isChecked()) return;
        const auto path = binary->text().trimmed();
        if ((!path.isEmpty() && !QDir::isAbsolutePath(path)) || path.contains(QChar::Null)) {
            QMessageBox::warning(this, tr("Tuntom"), tr("Enter an absolute executable path.")); return;
        }
        QSettings saved;
        if (cleanup->isChecked() && !saved.value("connections/cleanupOnAttach", false).toBool()
            && QMessageBox::warning(this, tr("Automatic TCP cleanup"),
                tr("Affected TCP transfers will be interrupted after Attach or destination exemption changes. Reconnection is NOT guaranteed. Enable?"),
                QMessageBox::Yes | QMessageBox::No, QMessageBox::No) != QMessageBox::Yes) return;
        for (const auto& item : toggles) saved.setValue(item.key, item.widget->isChecked());
        for (const auto& item : numbers) saved.setValue(item.key, item.widget->value());
        if (path.isEmpty()) saved.remove("tunnel/binary");
        else saved.setValue("tunnel/binary", path);
        if (Tuntom::developmentBinaryAllowed && risk->isChecked())
            saved.setValue("tunnel/developmentAcknowledgedPath", path);
        else saved.remove("tunnel/developmentAcknowledgedPath");
        accept();
    });
}
