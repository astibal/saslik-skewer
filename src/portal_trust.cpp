#include "portal_trust.hpp"

#include <QCryptographicHash>
#include <QMessageBox>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QSettings>
#include <QSslCertificate>
#include <QSslConfiguration>
#include <QSslError>
#include <QUrl>

namespace {
QString fingerprint(const QSslCertificate& certificate)
{
    const auto hex = certificate.digest(QCryptographicHash::Sha256).toHex().toUpper();
    QStringList groups;
    for (qsizetype offset = 0; offset < hex.size(); offset += 2)
        groups << QString::fromLatin1(hex.mid(offset, 2));
    return groups.join(':');
}

bool expectedErrors(const QList<QSslError>& errors)
{
    for (const auto& error : errors) {
        switch (error.error()) {
        case QSslError::SelfSignedCertificate:
        case QSslError::SelfSignedCertificateInChain:
        case QSslError::UnableToGetLocalIssuerCertificate:
        case QSslError::CertificateUntrusted:
        case QSslError::HostNameMismatch:
            break;
        default:
            return false;
        }
    }
    return !errors.isEmpty();
}
}

void installPortalTrust(QNetworkAccessManager* manager, QWidget* parent)
{
    QObject::connect(manager, &QNetworkAccessManager::sslErrors, manager,
        [parent](QNetworkReply* reply, const QList<QSslError>& errors) {
            const auto certificate = reply->sslConfiguration().peerCertificate();
            if (certificate.isNull() || !expectedErrors(errors)
                || !certificate.subjectInfo(QSslCertificate::CommonName).contains("Saslik Portal"))
                return;
            const QString authority = reply->url().authority();
            const QString digest = fingerprint(certificate);
            QSettings settings;
            const QString key = "portalPins/" + authority;
            if (settings.value(key).toString() == digest) {
                reply->ignoreSslErrors(errors);
                return;
            }
            const auto answer = QMessageBox::warning(parent, QObject::tr("Saslik certificate"),
                QObject::tr("Saslik at %1 presented an untrusted HTTPS certificate.\n\n"
                            "SHA-256\n%2\n\n"
                            "Verify this fingerprint with the Saslik operator before continuing. "
                            "A changed certificate will always require confirmation again.")
                    .arg(authority, digest),
                QMessageBox::Cancel | QMessageBox::Yes, QMessageBox::Cancel);
            if (answer != QMessageBox::Yes) return;
            settings.setValue(key, digest);
            settings.sync();
            reply->ignoreSslErrors(errors);
        });
}
