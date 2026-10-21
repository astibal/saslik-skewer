#include "ca_panel.hpp"
#include "desktop_catalog.hpp"
#include "process_scanner.hpp"
#include <unistd.h>
#include <QDateTime>
#include <QFileDialog>
#include <QFile>
#include <QFileInfo>
#include <QCheckBox>
#include <QComboBox>
#include <QSettings>
#include <QSignalBlocker>
#include <QBuffer>
#include <QDir>
#include <QFutureWatcher>
#include <QtConcurrentRun>
#include <QGroupBox>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QJsonArray>
#include <QJsonObject>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QPushButton>
#include <QProgressBar>
#include <QRegularExpression>
#include <QSaveFile>
#include <QSet>
#include <QStyle>
#include <QTableWidget>
#include <QTimer>
#include <QVBoxLayout>

namespace {
QString iconDataUrl(const QIcon& icon)
{
    if (icon.isNull()) return {};
    QByteArray png;
    QBuffer buffer(&png);
    if (!buffer.open(QIODevice::WriteOnly) || !icon.pixmap(32, 32).save(&buffer, "PNG")
        || png.size() > 24576) return {};
    return QStringLiteral("data:image/png;base64,") + QString::fromLatin1(png.toBase64());
}

struct KnownApplication {
    QString binary;
    QString alias;
};

KnownApplication knownApplicationForPath(QString path)
{
    path = path.toLower();
    // Keep this list deliberately exact. It identifies stores already found by
    // bounded cert9.db discovery; it never causes another directory to be read.
    static const std::pair<const char*, KnownApplication> known[] = {
        {"/.mozilla/firefox/", {"firefox", "Firefox"}},
        {"/.thunderbird/", {"thunderbird", "Thunderbird"}},
        {"/.librewolf/", {"librewolf", "LibreWolf"}},
        {"/.waterfox/", {"waterfox", "Waterfox"}},
        {"/.floorp/", {"floorp", "Floorp"}},
        {"/.zen/", {"zen", "Zen Browser"}},
        {"/.config/bravesoftware/brave-browser-beta/", {"brave-browser-beta", "Brave Beta"}},
        {"/.config/bravesoftware/brave-browser-nightly/", {"brave-browser-nightly", "Brave Nightly"}},
        {"/.config/bravesoftware/brave-browser/", {"brave-browser", "Brave"}},
        {"/.config/google-chrome-beta/", {"google-chrome-beta", "Google Chrome Beta"}},
        {"/.config/google-chrome-unstable/", {"google-chrome-unstable", "Google Chrome Dev"}},
        {"/.config/google-chrome-for-testing/", {"google-chrome-for-testing", "Chrome for Testing"}},
        {"/.config/google-chrome/", {"google-chrome", "Google Chrome"}},
        {"/.config/microsoft-edge-beta/", {"microsoft-edge-beta", "Microsoft Edge Beta"}},
        {"/.config/microsoft-edge-dev/", {"microsoft-edge-dev", "Microsoft Edge Dev"}},
        {"/.config/microsoft-edge/", {"microsoft-edge", "Microsoft Edge"}},
        {"/.config/vivaldi-snapshot/", {"vivaldi-snapshot", "Vivaldi Snapshot"}},
        {"/.config/vivaldi/", {"vivaldi", "Vivaldi"}},
        {"/.config/chromium/", {"chromium", "Chromium"}},
    };
    for (const auto& [fragment, application] : known)
        if (path.contains(QLatin1String(fragment))) return application;
    if (path.endsWith(QStringLiteral("/.pki/nssdb")) || path.endsWith(QStringLiteral("/pki/nssdb")))
        return {QStringLiteral("chromium"), QStringLiteral("Chromium family (shared NSS)")};
    return {};
}
}

CaTrustPanel::CaTrustPanel(QWidget* parent) : QWidget(parent)
{
    auto* layout = new QVBoxLayout(this);
    auto* notice = new QLabel(tr("CA trust changes allow TLS interception. Discovery never installs anything. "
        "Shared NSS and system trust may affect corporate applications too. Close affected applications before changes."), this);
    notice->setWordWrap(true); layout->addWidget(notice);
    auto* source_box = new QGroupBox(tr("Certificate — verify its fingerprint with the lab administrator"), this);
    auto* source_layout = new QVBoxLayout(source_box);
    auto* source_row = new QHBoxLayout;
    source_ = new QLineEdit(source_box);
    source_->setPlaceholderText(tr("CA download URL (HTTP(S))"));
    fetch_ = new QPushButton(tr("Fetch CA"), source_box);
    load_ = new QPushButton(tr("Open CA file…"), source_box);
    save_ = new QPushButton(tr("Save CA…"), source_box);
    source_row->addWidget(source_, 1);
    for (auto* button : {fetch_, load_, save_}) source_row->addWidget(button);
    source_layout->addLayout(source_row);
    known_certificates_ = new QComboBox(source_box);
    known_certificates_->setObjectName("knownCertificates");
    known_certificates_->setToolTip(tr("Remembered public CAs. Unused means not currently advertised by a connected Saslik; it does not mean removed from trust stores."));
    source_layout->addWidget(known_certificates_);
    connect(known_certificates_, &QComboBox::activated, this, [this](int index) {
        const auto key = known_certificates_->itemData(index).toString();
        loadCertificate(QSettings().value("knownCa/" + key).toByteArray());
    });
    certificate_info_ = new QLabel(tr("No CA selected. You can open a previously saved CA for offline removal."), source_box);
    certificate_info_->setWordWrap(true); certificate_info_->setTextFormat(Qt::PlainText);
    certificate_info_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    source_layout->addWidget(certificate_info_); layout->addWidget(source_box);
    progress_ = new QProgressBar(this);
    progress_->setRange(0, 0);
    progress_->setObjectName("caSearchProgress");
    layout->addWidget(progress_);
    status_ = new QLabel(this); status_->setWordWrap(true); status_->setTextFormat(Qt::PlainText);
    status_->setTextInteractionFlags(Qt::TextSelectableByMouse); layout->addWidget(status_);
    auto* filters = new QHBoxLayout;
    applicable_ = new QCheckBox(tr("Show only applicable"), this);
    applicable_->setObjectName("caOnlyApplicable");
    applicable_->setToolTip(tr("Show stores that can be managed or contain this CA. Unavailable scan areas remain in the scan summary."));
    current_snap_ = new QCheckBox(tr("Snap: show only current"), this);
    current_snap_->setObjectName("caOnlyCurrentSnap");
    current_snap_->setChecked(true);
    current_snap_->setToolTip(tr("Includes common, which is shared by current and retained revisions."));
    filters->addWidget(applicable_); filters->addWidget(current_snap_); filters->addStretch();
    layout->addLayout(filters);
    connect(applicable_, &QCheckBox::toggled, this, &CaTrustPanel::applyFilters);
    connect(current_snap_, &QCheckBox::toggled, this, &CaTrustPanel::applyFilters);
    table_ = new QTableWidget(0, 5, this);
    table_->setObjectName("caStores");
    table_->setHorizontalHeaderLabels({tr("Application / profile"), tr("Store type"), tr("Snap revision"), tr("CA state"), tr("Exact location")});
    table_->setSortingEnabled(true);
    table_->sortItems(0, Qt::AscendingOrder);
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->setSelectionMode(QAbstractItemView::SingleSelection);
    table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    // Keep long paths and diagnostics from inflating the entire row.
    // Full values remain available through the cell tooltips.
    table_->setWordWrap(false);
    table_->setTextElideMode(Qt::ElideRight);
    table_->setIconSize(QSize(24, 24));
    table_->verticalHeader()->setMinimumSectionSize(0);
    table_->verticalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    table_->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    table_->horizontalHeader()->setStretchLastSection(false);
    const int widths[] = {240, 130, 140, 180, 400};
    for (int col = 0; col < 5; ++col) table_->setColumnWidth(col, widths[col]);
    layout->addWidget(table_, 1);
    auto* actions = new QHBoxLayout;
    scan_ = new QPushButton(tr("Scan stores"), this);
    install_ = new QPushButton(tr("Install into selected…"), this);
    install_->setObjectName("caInstallSelected");
    remove_ = new QPushButton(tr("Remove from selected…"), this);
    remove_all_ = new QPushButton(tr("Scan and remove this CA from all…"), this);
    remove_all_->setObjectName("caRemoveAll");
    for (auto* button : {scan_, install_, remove_}) actions->addWidget(button);
    actions->addStretch(); actions->addWidget(remove_all_); layout->addLayout(actions);
    auto* scope = new QLabel(tr("Scope: current user's NSS cert9.db profiles in Mozilla, Thunderbird, LibreWolf, "
        "Snap, Flatpak, .config and shared NSS locations; system-local .crt anchors. "
        "Other users, Java/custom stores, packaged roots and certificate pinning are not covered. "
                "Snap current identifies the selected revision, not whether an older process is still running. "
                "common is shared across revisions. Retained revisions are scanned too. "
                "An application may need a restart; removal cannot undo already established TLS sessions."), this);
    scope->setWordWrap(true); layout->addWidget(scope);
    auto* apps = new QGroupBox(tr("Other applications — discovery only, no automatic profile modifications"), this);
    apps->setCheckable(true); apps->setChecked(false);
    auto* apps_layout = new QVBoxLayout(apps);
    QStringList candidates;
    const QRegularExpression known("electron|teams|slack|discord|signal|code|proton", QRegularExpression::CaseInsensitiveOption);
    const DesktopCatalog catalog;
    for (const auto& entry : catalog.entries())
        if (known.match(entry.name + ' ' + entry.executable).hasMatch()) candidates << entry.name;
    for (const auto& process : ProcessScanner().scan(getuid()))
        if (known.match(process.name + ' ' + process.executable).hasMatch()) candidates << process.name;
    candidates.removeDuplicates(); candidates.sort();
    auto* app_text = new QLabel(tr("Possible Electron / corporate clients (name-based hints, not verified store mappings):\n%1\n"
        "No dedicated installer is enabled for these applications. Review shared-store impact before granting trust.")
        .arg(candidates.isEmpty() ? tr("None detected") : candidates.join(", ")), apps);
    app_text->setTextFormat(Qt::PlainText); app_text->setWordWrap(true); app_text->hide();
    apps_layout->addWidget(app_text);
    connect(apps, &QGroupBox::toggled, app_text, &QWidget::setVisible); layout->addWidget(apps);
    connect(table_, &QTableWidget::itemSelectionChanged, this, [this] { selectionChanged(); });
    connect(scan_, &QPushButton::clicked, this, [this] { scan(); });
    connect(remove_all_, &QPushButton::clicked, this, [this] { scan(true); });
    connect(install_, &QPushButton::clicked, this, [this] {
        if (const int index = selectedStore(); index >= 0) modify({stores_.at(index)}, false);
    });
    connect(remove_, &QPushButton::clicked, this, [this] {
        if (const int index = selectedStore(); index >= 0) modify({stores_.at(index)}, true);
    });
    connect(load_, &QPushButton::clicked, this, [this] {
        const auto path = QFileDialog::getOpenFileName(this, tr("Select a CA certificate"), {}, tr("Certificates (*.pem *.crt);;All files (*)"));
        if (path.isEmpty()) return;
        QFile file(path);
        if (!file.open(QIODevice::ReadOnly) || file.size() > 65536) { status_->setText(tr("Cannot read CA file (64 KiB maximum).")); return; }
        loadCertificate(file.readAll());
    });
    connect(save_, &QPushButton::clicked, this, [this] {
        const auto path = QFileDialog::getSaveFileName(this, tr("Save CA certificate"), "saslik-ca.pem");
        if (path.isEmpty()) return;
        QSaveFile file(path);
        if (!file.open(QIODevice::WriteOnly) || file.write(certificate_.toPem()) != certificate_.toPem().size() || !file.commit())
            status_->setText(tr("Cannot save certificate."));
    });
    auto* network = new QNetworkAccessManager(this);
    connect(fetch_, &QPushButton::clicked, this, [this, network] {
        const QUrl url(source_->text().trimmed());
        if (!url.isValid() || url.host().isEmpty() || (url.scheme() != "http" && url.scheme() != "https")) {
            status_->setText(tr("Enter a valid HTTP(S) CA URL.")); return;
        }
        busy(true); status_->setText(tr("Fetching CA; trust will not be changed."));
        QNetworkRequest request(url); request.setTransferTimeout(10000);
        auto* reply = network->get(request);
        const auto epoch = remote_epoch_;
        connect(reply, &QNetworkReply::readyRead, reply, [reply] { if (reply->bytesAvailable() > 65536) reply->abort(); });
        connect(reply, &QNetworkReply::finished, this, [this, reply, epoch] {
            busy(false); reply->deleteLater();
            if (epoch != remote_epoch_) return;
            if (reply->error() != QNetworkReply::NoError) { setRemoteDisconnected(); status_->setText(tr("CA download failed: %1").arg(reply->errorString())); return; }
            setRemoteCertificate(reply->readAll());
        });
    });
    busy(false);
    refreshKnownCertificates();
    QTimer::singleShot(0, this, [this] {
        if (certificate_.isNull() && known_certificates_->count())
            loadCertificate(QSettings().value("knownCa/" + known_certificates_->currentData().toString()).toByteArray());
    });
}
void CaTrustPanel::refreshKnownCertificates()
{
    QSignalBlocker blocker(known_certificates_);
    const auto selected = certificate_.digest(QCryptographicHash::Sha256).toHex();
    known_certificates_->clear();
    QSettings settings;
    settings.beginGroup("knownCa");
    for (const auto& key : settings.childKeys()) {
        const auto cert = CaStoreManager::parse(settings.value(key).toByteArray());
        if (cert.isNull()) continue;
        const auto label = tr("%1 · %2 · %3").arg(cert.subjectInfo(QSslCertificate::CommonName).join(", "),
            key.left(12), key == active_fingerprint_ ? tr("active") : tr("unused"));
        known_certificates_->addItem(label, key);
        if (key == selected) known_certificates_->setCurrentIndex(known_certificates_->count() - 1);
    }
}
void CaTrustPanel::setRemoteDisconnected()
{
    ++remote_epoch_;
    if (active_fingerprint_.isEmpty()) return;
    active_fingerprint_.clear();
    refreshKnownCertificates();
}
void CaTrustPanel::disconnectAndOfferRemoval()
{
    // Capture the remote CA, not whichever historical certificate is selected.
    const auto fingerprint = active_fingerprint_.isEmpty() ? last_remote_fingerprint_ : active_fingerprint_;
    const auto pem = fingerprint.isEmpty() ? QByteArray{}
        : QSettings().value("knownCa/" + fingerprint).toByteArray();
    setRemoteDisconnected();
    if (pem.isEmpty()) return;
    if (QMessageBox::question(this, tr("Remove disconnected lab CA?"),
            tr("Scan all supported stores for this lab's CA and offer removal? "
               "You will confirm the exact fingerprint and stores before any changes. "
               "Known CA history will be kept; unsupported or inaccessible stores cannot be guaranteed."),
            QMessageBox::Yes | QMessageBox::No, QMessageBox::No) == QMessageBox::Yes)
        removeWhenIdle(pem);
}
void CaTrustPanel::removeWhenIdle(const QByteArray& pem)
{
    if (working_) {
        QTimer::singleShot(200, this, [this, pem] { removeWhenIdle(pem); });
        return;
    }
    loadCertificate(pem, true);
}
void CaTrustPanel::setSource(const QUrl& url)
{
    // Never replace a certificate already selected for an operation.
    if (!working_ && url.isValid() && !url.host().isEmpty()
        && (source_->text() != url.toString() || active_fingerprint_.isEmpty())) {
        source_->setText(url.toString());
        // Discovery and scanning are read-only.  Populate the Saslik report
        // without requiring the user to open this tab or grant trust.
        const auto epoch = remote_epoch_;
        QTimer::singleShot(0, this, [this, epoch] {
            if (epoch == remote_epoch_) fetch_->click();
        });
    }
}
void CaTrustPanel::busy(bool value)
{
    working_ = value;
    progress_->setVisible(value);
    source_->setEnabled(!value); fetch_->setEnabled(!value); load_->setEnabled(!value);
    save_->setEnabled(!value && !certificate_.isNull());
    scan_->setEnabled(!value && !certificate_.isNull()); remove_all_->setEnabled(scan_->isEnabled());
    table_->setEnabled(!value); selectionChanged();
    known_certificates_->setEnabled(!value);
}
void CaTrustPanel::selectionChanged()
{
    const int row = selectedStore();
    const bool selected = !working_ && row >= 0 && row < stores_.size();
    install_->setEnabled(selected && stores_.at(row).available && !stores_.at(row).installed);
    remove_->setEnabled(selected && !stores_.at(row).matches.isEmpty());
}
int CaTrustPanel::selectedStore() const
{
    const int row = table_->currentRow();
    if (row < 0 || table_->isRowHidden(row)) return -1;
    const auto* item = table_->item(row, 0);
    if (!item) return -1;
    const int index = item->data(Qt::UserRole).toInt();
    return index >= 0 && index < stores_.size() ? index : -1;
}
void CaTrustPanel::applyFilters()
{
    for (int row = 0; row < table_->rowCount(); ++row) {
        const auto* item = table_->item(row, 0);
        if (!item) continue;
        const auto& store = stores_.at(item->data(Qt::UserRole).toInt());
        const bool applicable = store.available || !store.matches.isEmpty();
        const bool current = store.snap_name.isEmpty() || store.snap_state == "current" || store.snap_revision == "common";
        table_->setRowHidden(row, (applicable_->isChecked() && !applicable)
            || (current_snap_->isChecked() && !current));
    }
    selectionChanged();
}
void CaTrustPanel::loadCertificate(const QByteArray& pem, bool remove_all)
{
    const auto cert = CaStoreManager::parse(pem);
    if (cert.isNull()) { status_->setText(tr("Expected exactly one PEM CA certificate with CA basic constraints. Previous selection unchanged.")); return; }
    certificate_ = cert; stores_.clear(); table_->setRowCount(0);
    // Public certificate history is retained independently of trust-store
    // installation, pairing credentials and the current connection lifetime.
    QSettings().setValue("knownCa/" + QString::fromLatin1(cert.digest(QCryptographicHash::Sha256).toHex()), cert.toPem());
    refreshKnownCertificates();
    emit certificateChanged(cert.toPem());
    certificate_info_->setText(tr("CA: %1\nSHA-256: %2\nValid: %3 — %4")
        .arg(cert.subjectInfo(QSslCertificate::CommonName).join(", "), CaStoreManager(cert).fingerprint(),
             cert.effectiveDate().toString(Qt::ISODate), cert.expiryDate().toString(Qt::ISODate)));
    scan(remove_all);
}
void CaTrustPanel::setRemoteCertificate(const QByteArray& pem)
{
    // A scan or trust operation must finish against the certificate it started
    // with. Discovery will retry on its next poll; identical CAs need no rescan.
    if (working_) return;
    const auto certificate = CaStoreManager::parse(pem);
    if (certificate.isNull()) {
        status_->setText(tr("Saslik did not supply a valid CA certificate. Previous selection unchanged."));
        return;
    }
    const auto fingerprint = QString::fromLatin1(certificate.digest(QCryptographicHash::Sha256).toHex());
    if (fingerprint == active_fingerprint_) return;
    active_fingerprint_ = fingerprint;
    last_remote_fingerprint_ = fingerprint;
    loadCertificate(certificate.toPem());
}
void CaTrustPanel::scan(bool remove_all)
{
    if (working_ || certificate_.isNull()) return;
    busy(true); status_->setText(tr("Scanning supported stores… no trust changes."));
    emit caStatusChanged({}, CaStoreManager(certificate_).fingerprint());
    auto* watcher = new QFutureWatcher<QVector<CaStore>>(this);
    connect(watcher, &QFutureWatcher<QVector<CaStore>>::finished, this, [this, watcher, remove_all] {
        table_->setSortingEnabled(false);
        table_->clearSelection();
        stores_ = watcher->result(); watcher->deleteLater(); table_->setRowCount(stores_.size());
        const DesktopCatalog catalog;
        int inaccessible = 0; QVector<CaStore> matches;
        for (int row = 0; row < stores_.size(); ++row) {
            auto& store = stores_[row];
            QIcon icon = style()->standardIcon(store.system ? QStyle::SP_ComputerIcon : QStyle::SP_DirIcon);
            if (!store.snap_name.isEmpty()) {
                QString name = store.snap_name;
                // Use Snap's desktop entry, not a similarly named native app.
                const DesktopEntry* selected = nullptr;
                for (const auto& entry : catalog.entries()) {
                    if (!entry.id.startsWith(store.snap_name + '_')) continue;
                    if (!selected) selected = &entry;
                    if (entry.id == store.snap_name + '_' + store.snap_name) {
                        selected = &entry; break;
                    }
                }
                if (selected) { name = selected->name; icon = selected->icon(); }
                else {
                    static const QHash<QString, QString> names{{"brave", "Brave"}, {"firefox", "Firefox"},
                        {"chromium", "Chromium"}, {"thunderbird", "Thunderbird"}};
                    name = names.value(name, name);
                    icon = QIcon::fromTheme("package-x-generic", icon);
                }
                if (icon.isNull()) icon = style()->standardIcon(QStyle::SP_DirIcon);
                const QString profile = store.path.section('/', -1);
                store.label = name + (profile == "nssdb" ? QString{} : " · " + profile);
            }
            else if (!store.system && store.label.endsWith("/nssdb")) store.label.chop(6);
            if (!store.available) ++inaccessible;
            if (!store.matches.isEmpty()) matches << store;
            for (int col = 0; col < 5; ++col) {
                auto* item = new QTableWidgetItem(col == 0 ? store.label
                    : col == 1 ? (store.system ? tr("System") : tr("NSS"))
                    : col == 2 ? (store.snap_name.isEmpty() ? QStringLiteral("—")
                        : store.snap_revision + " · " + store.snap_state)
                    : col == 3 ? store.detail : store.path);
                if (store.installed && store.available) item->setForeground(QColor("#41b879"));
                if (col == 0) { item->setIcon(icon); item->setData(Qt::UserRole, row); }
                item->setToolTip(store.path + '\n' + store.detail); table_->setItem(row, col, item);
            }
        }
        table_->resizeRowsToContents();
        table_->setSortingEnabled(true);
        applyFilters();
        // Map only known per-application profile locations. Generic Electron
        // and shared NSS stores are deliberately not guessed as app ownership.
        QHash<QString, QString> app_statuses;
        for (const auto& entry : catalog.entries()) {
            QVector<const CaStore*> profiles;
            for (const auto& store : stores_) {
                if (!store.snap_name.isEmpty()) {
                    if (entry.id.startsWith(store.snap_name + '_')
                        && (store.snap_state == "current" || store.snap_revision == "common")) profiles << &store;
                    continue;
                }
                const QString binary = QFileInfo(entry.executable).fileName();
                const QString prefix = binary == "firefox" ? "/.mozilla/firefox/"
                    : binary == "thunderbird" ? "/.thunderbird/"
                    : binary == "librewolf" ? "/.librewolf/" : QString{};
                if (!prefix.isEmpty() && store.path.startsWith(QDir::homePath() + prefix)) profiles << &store;
            }
            if (profiles.isEmpty()) continue;
            int trusted = 0, missing = 0, unknown = 0;
            for (const auto* store : profiles) {
                if (!store->available) ++unknown;
                else if (store->installed) ++trusted;
                else if (store->matches.isEmpty()) ++missing;
                else ++unknown; // Present but trust differs; do not claim absence.
            }
            app_statuses["desktop:" + entry.id] = missing > 0
                ? (missing == profiles.size() ? tr("CA missing · all %1 profiles").arg(missing)
                    : tr("CA missing · %1/%2 profiles").arg(missing).arg(profiles.size()))
                : unknown > 0 ? tr("Not fully verified") : tr("Trusted · %1 profiles").arg(trusted);
        }
        emit caStatusChanged(app_statuses, CaStoreManager(certificate_).fingerprint());
        QJsonArray reported_stores;
        QJsonArray reported_applications;
        QSet<QString> reported_ids;
        const auto desktopFor = [&catalog](const QString& name,
                                           bool prefer_snap = false) -> const DesktopEntry* {
            const DesktopEntry* best = nullptr;
            int best_score = 0;
            for (const auto& entry : catalog.entries()) {
                const QString binary = QFileInfo(entry.executable).fileName();
                int score = 0;
                if (prefer_snap && entry.id == name + '_' + name) score = 1000;
                else if (entry.id == name) score = 500;
                else if (entry.id.startsWith(name + '_')) score = 400;
                else if (binary == name) score = 300;
                else if (binary.startsWith(name + '-')) score = 200;
                if (!score) continue;
                // A resolvable icon is more useful than a slightly stronger
                // textual match which would serialize the folder fallback.
                if (!entry.icon().isNull()) score += 150;
                if (score > best_score) { best = &entry; best_score = score; }
            }
            return best;
        };
        for (const auto& store : stores_) {
            QString application_id, application_alias;
            bool application_recognized = false;
            QIcon application_icon = style()->standardIcon(
                store.system ? QStyle::SP_ComputerIcon : QStyle::SP_DirIcon);
            if (store.system) {
                application_id = "system"; application_alias = tr("System");
                application_recognized = true;
            } else if (!store.snap_name.isEmpty()) {
                static const QSet<QString> browser_families{
                    "firefox", "thunderbird", "librewolf", "waterfox", "floorp", "zen",
                    "chromium", "brave", "google-chrome", "microsoft-edge", "vivaldi"};
                application_id = browser_families.contains(store.snap_name)
                    ? "app:" + store.snap_name : "snap:" + store.snap_name;
                const auto* desktop = desktopFor(store.snap_name, true);
                application_alias = desktop ? desktop->name : store.label.section(" · ", 0, 0);
                if (desktop) { application_icon = desktop->icon(); application_recognized = true; }
            } else {
                const auto known = knownApplicationForPath(store.path);
                const QString binary = known.binary;
                application_id = binary.isEmpty() ? "nss:generic" : "app:" + binary;
                application_recognized = !binary.isEmpty();
                application_alias = binary.isEmpty() ? tr("Other NSS stores")
                    : known.alias;
                if (const auto* desktop = desktopFor(binary)) {
                    application_alias = desktop->name;
                    application_icon = desktop->icon();
                }
            }
            if (!reported_ids.contains(application_id)) {
                reported_ids.insert(application_id);
                reported_applications.append(QJsonObject{{"id", application_id},
                    {"alias", application_alias}, {"recognized", application_recognized},
                    {"icon", iconDataUrl(application_icon)}});
            }
            QJsonObject item{{"key", store.key}, {"label", store.label}, {"path", store.path},
                {"system", store.system}, {"available", store.available},
                {"installed", store.installed}, {"detail", store.detail},
                {"matches", store.matches.size()}, {"application_id", application_id}};
            if (!store.snap_name.isEmpty()) {
                item["snap_name"] = store.snap_name;
                item["snap_revision"] = store.snap_revision;
                item["snap_state"] = store.snap_state;
                item["snap_lifecycle"] = store.snap_revision == "common" ? "common"
                    : store.snap_state == "current" ? "current"
                    : store.snap_state.startsWith("retained") ? "retained" : "unknown";
            }
            reported_stores.append(item);
        }
        emit trustReportReady(QJsonObject{
            {"fingerprint", CaStoreManager(certificate_).fingerprint()},
            {"applications", reported_applications},
            {"stores", reported_stores}});
        busy(false);
        status_->setText(tr("Scan complete: %1 matching stores; %2 unavailable/unverified. Only the documented scope was inspected.")
                         .arg(matches.size()).arg(inaccessible));
        if (remove_all && !matches.isEmpty()) modify(matches, true);
    });
    watcher->setFuture(QtConcurrent::run([certificate = certificate_] { return CaStoreManager(certificate).stores(); }));
}
void CaTrustPanel::modify(QVector<CaStore> targets, bool remove)
{
    if (working_ || targets.isEmpty()) return;
    QStringList preview;
    for (const auto& store : targets)
        preview << store.label + (store.snap_name.isEmpty() ? QString{} : " · " + store.snap_revision + " · " + store.snap_state)
            + "\n" + store.path + (remove ? "\n" + store.matches.join("\n") : QString{});
    int unverified = 0;
    for (const auto& store : stores_) if (!store.available) ++unverified;
    QMessageBox confirmation(QMessageBox::Warning, remove ? tr("Remove this CA") : tr("Grant CA trust"),
        tr("SHA-256: %1\n\n%2\n\n%3")
            .arg(CaStoreManager(certificate_).fingerprint(), preview.join("\n\n"), remove
                ? tr("Remove only these matching entries? Other certificates are preserved. %1 stores/scan areas are unavailable or unverified. Unsupported stores are not covered.").arg(unverified)
                : tr("Trust this CA in the selected store? This enables TLS interception and may affect corporate applications sharing this store. System changes require administrator authorization.")),
        QMessageBox::Yes | QMessageBox::Cancel, this);
    confirmation.setTextFormat(Qt::PlainText); confirmation.setDefaultButton(QMessageBox::Cancel);
    if (confirmation.exec() != QMessageBox::Yes) return;
    busy(true); status_->setText(tr("Applying confirmed changes…"));
    auto* watcher = new QFutureWatcher<QString>(this);
    connect(watcher, &QFutureWatcher<QString>::finished, this, [this, watcher] {
        const QString report = watcher->result(); watcher->deleteLater(); busy(false);
        QMessageBox result(QMessageBox::Information, tr("CA operation results"), report, QMessageBox::Ok, this);
        result.setTextFormat(Qt::PlainText); result.exec(); scan();
    });
    watcher->setFuture(QtConcurrent::run([certificate = certificate_, targets, remove] {
        QStringList report; const CaStoreManager manager(certificate);
        for (const auto& store : targets) {
            QString error;
            const bool ok = remove ? manager.remove(store, error) : manager.install(store, error);
            report << store.label + ": " + (ok ? (remove ? "Removed confirmed matches" : "Installed") : "FAILED / possibly partial: " + error);
        }
        return report.join('\n');
    }));
}
