// One database per process: no global NSS context shared between GUI workers.
#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDateTime>
#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSslCertificate>
#include <QSslCertificateExtension>
#include <QTextStream>
#include <cert.h>
#include <certdb.h>
#include <nss.h>
#include <pk11pub.h>
#include <prerror.h>
#include <memory>

int main(int argc, char** argv)
{
    QCoreApplication application(argc, argv);
    const auto args = application.arguments();
    if (args.size() != 4 || (args[1] != "inspect" && args[1] != "install" && args[1] != "remove")
        || args[3].size() > 90000 || !QFileInfo::exists(args[2] + "/cert9.db")) return 2;
    const QByteArray der = QByteArray::fromBase64(args[3].toLatin1());
    const auto certificates = QSslCertificate::fromData(der, QSsl::Der);
    if (certificates.size() != 1 || certificates.first().toDer() != der) return 2;
    const auto& selected = certificates.first();
    const QByteArray database = ("sql:" + args[2]).toUtf8();
    auto* context = NSS_InitContext(database.constData(), "", "", "secmod.db", nullptr,
        NSS_INIT_NOMODDB | NSS_INIT_NOROOTINIT | (args[1] == "inspect" ? NSS_INIT_READONLY : 0));
    const auto fail = [] {
        const char* name = PR_ErrorToName(PR_GetError());
        QTextStream(stderr) << "NSS operation failed: " << (name ? name : "unknown error") << '\n';
        return 1;
    };
    if (!context) return fail();
    // Destroy certificates and slots before shutting the context down.
    const auto operation = [&]() -> int {
        SECItem item{siBuffer, reinterpret_cast<unsigned char*>(const_cast<char*>(der.constData())),
                     static_cast<unsigned int>(der.size())};
        auto* db = CERT_GetDefaultCertDB();
        using Certificate = std::unique_ptr<CERTCertificate, decltype(&CERT_DestroyCertificate)>;
        Certificate cert(CERT_FindCertByDERCert(db, &item), CERT_DestroyCertificate);
        const auto exact = [&] { return cert && QByteArray(reinterpret_cast<const char*>(cert->derCert.data),
                                                           cert->derCert.len) == der; };
        if (cert && !exact()) return 2;
        if (args[1] == "inspect") {
            CERTCertTrust trust{};
            if (cert && CERT_GetCertTrust(cert.get(), &trust) != SECSuccess) return fail();
            const bool trusted = cert && (trust.sslFlags & CERTDB_TRUSTED_CA)
                && (trust.sslFlags & CERTDB_TRUSTED_CLIENT_CA);
            const QJsonObject result{{"present", bool(cert)}, {"trusted", trusted},
                {"nickname", cert && cert->nickname ? QString::fromUtf8(cert->nickname) : QString{}}};
            QTextStream(stdout) << QJsonDocument(result).toJson(QJsonDocument::Compact);
            return 0;
        }
        if (args[1] == "remove") {
            if (!cert) { QTextStream(stderr) << "Selected CA no longer present; no other certificate touched\n"; return 1; }
            return SEC_DeletePermCertificate(cert.get()) == SECSuccess ? 0 : fail();
        }
        bool ca = false;
        for (const auto& extension : selected.extensions())
            if (extension.oid() == "2.5.29.19") ca = extension.value().toMap().value("ca").toBool();
        if (!ca || selected.expiryDate() < QDateTime::currentDateTimeUtc()
            || selected.effectiveDate() > QDateTime::currentDateTimeUtc()) return 2;
        if (!cert) {
            const QByteArray nickname = "Skewer CA " + selected.digest(QCryptographicHash::Sha256).toHex();
            Certificate collision(CERT_FindCertByNickname(db, nickname.constData()), CERT_DestroyCertificate);
            if (collision) { QTextStream(stderr) << "Nickname collision; no certificate replaced\n"; return 1; }
            std::unique_ptr<PK11SlotInfo, decltype(&PK11_FreeSlot)> slot(PK11_GetInternalKeySlot(), PK11_FreeSlot);
            if (!slot || PK11_ImportDERCert(slot.get(), &item, CK_INVALID_HANDLE,
                    const_cast<char*>(nickname.constData()), PR_FALSE) != SECSuccess) return fail();
            cert.reset(CERT_FindCertByDERCert(db, &item));
            if (!exact()) return fail();
        }
        CERTCertTrust trust{};
        if (CERT_GetCertTrust(cert.get(), &trust) != SECSuccess) return fail();
        trust.sslFlags &= ~CERTDB_TERMINAL_RECORD;
        trust.sslFlags |= CERTDB_VALID_CA | CERTDB_TRUSTED_CA | CERTDB_TRUSTED_CLIENT_CA;
        return CERT_ChangeCertTrust(db, cert.get(), &trust) == SECSuccess ? 0 : fail();
    };
    const int result = operation();
    const auto shutdown = NSS_ShutdownContext(context);
    return result != 0 ? result : shutdown == SECSuccess ? 0 : fail();
}
