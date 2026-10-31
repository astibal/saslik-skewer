#ifdef _WIN32
#include "pairing_windows.hpp"
#else
#include "pairing_posix.hpp"
#endif
#include "pairing.hpp"
#include "diagnostic_log.hpp"
#include <QCryptographicHash>
#include <QDir>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSaveFile>
#include <QSettings>
#include <QStandardPaths>
#include <QTcpSocket>
#include <QTextStream>
#include <QUrl>
#include <QUrlQuery>
#include <QUuid>
#include <openssl/ssl.h>
#include <stdexcept>
#include <memory>
#include <csignal>
#include <QElapsedTimer>

namespace {
struct Credentials { QByteArray identity, key; };
int providePsk(SSL* ssl, const EVP_MD* digest, const unsigned char** identity,
               size_t* length, SSL_SESSION** output)
{
    if (digest && EVP_MD_type(digest) != NID_sha256) return 0;
    const auto* credentials = static_cast<Credentials*>(SSL_get_app_data(ssl));
    const unsigned char cipher[]{0x13,0x01};
    SSL_SESSION* session = SSL_SESSION_new();
    if (!session || !SSL_SESSION_set1_master_key(session,
            reinterpret_cast<const unsigned char*>(credentials->key.constData()),credentials->key.size())
        || !SSL_SESSION_set_cipher(session,SSL_CIPHER_find(ssl,cipher))
        || !SSL_SESSION_set_protocol_version(session,TLS1_3_VERSION)) {
        SSL_SESSION_free(session); return 0;
    }
    *identity = reinterpret_cast<const unsigned char*>(credentials->identity.constData());
    *length = credentials->identity.size(); *output = session; return 1;
}
QJsonObject exchange(const QUrl& endpoint, const Credentials& credentials, const QJsonObject& request, const QString& connect_host = {})
{
    [[maybe_unused]] PairingPlatform::SignalGuard pipe_guard;
    if (credentials.key.size()!=32 || credentials.identity.isEmpty()) throw std::runtime_error("Invalid pairing credentials");
    QTcpSocket tcp;
    tcp.connectToHost(connect_host.isEmpty() ? endpoint.host() : connect_host, endpoint.port());
    if (!tcp.waitForConnected(5000)) throw std::runtime_error("PSK endpoint unreachable");
    PairingPlatform::Transport transport(tcp);
    std::unique_ptr<SSL_CTX,decltype(&SSL_CTX_free)> context(SSL_CTX_new(TLS_client_method()),SSL_CTX_free);
    if (!context) throw std::runtime_error("Cannot initialize TLS");
    SSL_CTX_set_min_proto_version(context.get(),TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(context.get(),TLS1_3_VERSION);
    SSL_CTX_set_ciphersuites(context.get(),"TLS_AES_128_GCM_SHA256");
    SSL_CTX_clear_options(context.get(),SSL_OP_ALLOW_NO_DHE_KEX);
    SSL_CTX_set_psk_use_session_callback(context.get(),providePsk);
    std::unique_ptr<SSL,decltype(&SSL_free)> ssl(SSL_new(context.get()),SSL_free);
    if (!ssl) throw std::runtime_error("Cannot initialize TLS session");
    SSL_set_app_data(ssl.get(),const_cast<Credentials*>(&credentials));
    if (!SSL_set_fd(ssl.get(), transport.descriptor())) throw std::runtime_error("Cannot bind TLS socket");
    if (SSL_connect(ssl.get())!=1 || SSL_version(ssl.get())!=TLS1_3_VERSION || SSL_get0_peer_certificate(ssl.get()))
        throw std::runtime_error("TLS-PSK authentication failed (no plaintext fallback)");
    // Log the phase only, never the credential-bearing request or pairing URL.
    const bool tunnel_open = request["action"].toString() == "tunnel-open";
    if (tunnel_open) DiagnosticLog::write("control", "TLS-PSK authenticated; sending tunnel-open");
    const auto data = QJsonDocument(request).toJson(QJsonDocument::Compact)+'\n';
    size_t written=0;
    if (!SSL_write_ex(ssl.get(),data.constData(),data.size(),&written) || written!=size_t(data.size()))
        throw std::runtime_error("TLS request failed");
    QByteArray response;
    QElapsedTimer elapsed; elapsed.start();
    // The protocol has exactly one bounded response per connection.
    while (!response.endsWith('\n') && response.size()<=65536) {
        if (elapsed.elapsed()>5000) throw std::runtime_error("TLS response deadline exceeded");
        char buffer[4096]; size_t count=0;
        if (!SSL_read_ex(ssl.get(),buffer,sizeof(buffer),&count)) throw std::runtime_error("TLS response failed");
        response.append(buffer,count);
    }
    QJsonParseError error;
    const auto document = QJsonDocument::fromJson(response,&error);
    if (response.size()>65536 || error.error!=QJsonParseError::NoError || !document.isObject())
        throw std::runtime_error("Invalid control response");
    const auto value = document.object();
    if (tunnel_open) DiagnosticLog::write("control", value.contains("error") ? "Tunnel-open rejected" : "Tunnel-open accepted");
    if (value.contains("error")) throw std::runtime_error("Control request rejected");
    return value;
}
QString statePath(const QUrl& endpoint)
{
    const QString directory = QStandardPaths::writableLocation(QStandardPaths::GenericDataLocation)+"/skewer/pairings";
    if (!QDir().mkpath(directory)) throw std::runtime_error("Cannot create pairing directory");
    if (!QFile::setPermissions(directory,QFile::ReadOwner|QFile::WriteOwner|QFile::ExeOwner))
        throw std::runtime_error("Cannot protect pairing directory");
    return directory+'/'+QString::fromLatin1(QCryptographicHash::hash(endpoint.toEncoded(),QCryptographicHash::Sha256).toHex())+".json";
}
void save(const QString& path,const QJsonObject& value)
{
    QSaveFile file(path);
    if (!file.open(QIODevice::WriteOnly) || !file.setPermissions(QFile::ReadOwner|QFile::WriteOwner))
        throw std::runtime_error("Cannot protect pairing file");
    const auto bytes = PairingPlatform::encode(QJsonDocument(value).toJson());
    if (file.write(bytes)!=bytes.size() || !file.commit()) throw std::runtime_error("Cannot save pairing");
}
}

namespace {
void validateEndpoint(const QUrl& endpoint)
{
    if (!endpoint.isValid() || endpoint.scheme()!="skewer" || endpoint.host().isEmpty() || endpoint.port()<1
        || endpoint.hasFragment() || endpoint.hasQuery() || !endpoint.userInfo().isEmpty() || endpoint.path()!="/pair")
        throw std::runtime_error("Invalid paired endpoint");
}
Credentials loadCredentials(const QUrl& endpoint)
{
    validateEndpoint(endpoint);
    QFile file(statePath(endpoint));
    if (!file.open(QIODevice::ReadOnly)) throw std::runtime_error("No pairing for this endpoint");
    if (file.size() > 65536) throw std::runtime_error("Pairing file exceeds bounds");
    const auto value=QJsonDocument::fromJson(PairingPlatform::decode(file.readAll())).object();
    return {value["identity"].toString().toUtf8(),QByteArray::fromBase64(value["psk"].toString().toLatin1(),QByteArray::Base64UrlEncoding|QByteArray::AbortOnBase64DecodingErrors)};
}
}

struct PairedControl::Impl {
    QUrl endpoint;
    QString connect_host;
    Credentials credentials;
    ~Impl() {
        // Best-effort clearing of this object's owned buffer, not a promise
        // about caller copies, TLS internals, swap or process crash dumps.
        OPENSSL_cleanse(credentials.key.data(), static_cast<size_t>(credentials.key.size()));
    }
};

PairedControl::PairedControl(QUrl endpoint, QByteArray identity, QByteArray key, QString connect_host) {
    validateEndpoint(endpoint);
    if (key.size() != 32 || identity.isEmpty() || identity.size() > 256 || identity.contains('\0')) {
        throw std::invalid_argument("Invalid control credential snapshot");
    }
    impl_ = std::make_unique<Impl>();
    impl_->endpoint = std::move(endpoint);
    impl_->connect_host = std::move(connect_host);
    // Own detached storage: wiping must not mutate a caller's QByteArray.
    impl_->credentials = {std::move(identity), std::move(key)};
    impl_->credentials.key.detach();
}
PairedControl::~PairedControl() = default;

void PairedControl::withCredentials(const CredentialConsumer& consumer) const {
    if (!consumer) {
        throw std::invalid_argument("Credential handoff requires a consumer");
    }
    consumer(impl_->endpoint, impl_->credentials.identity, impl_->credentials.key);
}

std::unique_ptr<PairedControl> PairedControl::load(const QUrl& endpoint, const QString& connect_host) {
    auto credentials = loadCredentials(endpoint);
    return std::make_unique<PairedControl>(endpoint, std::move(credentials.identity),
                                           std::move(credentials.key), connect_host);
}
PairedTunnel PairedControl::open() {
    const auto response = exchange(impl_->endpoint, impl_->credentials, {{"action", "tunnel-open"}}, impl_->connect_host);
    const auto tunnel = Tuntom::endpointFromResponse(response);
    return {tunnel, Tuntom::deriveKey(impl_->credentials.key, tunnel.context.toLatin1())};
}
void PairedControl::renew(const Tuntom::Endpoint& tunnel) {
    const auto renewed = Tuntom::endpointFromResponse(exchange(impl_->endpoint, impl_->credentials,
        {{"action", "tunnel-heartbeat"}, {"context", tunnel.context}}, impl_->connect_host));
    if (renewed.context != tunnel.context || renewed.id != tunnel.id || renewed.leaseSeconds != tunnel.leaseSeconds
        || renewed.serverAddress != tunnel.serverAddress || renewed.clientAddress != tunnel.clientAddress) {
        throw std::runtime_error("Tunnel endpoint changed during renewal");
    }
}
void PairedControl::close(const Tuntom::Endpoint& tunnel) {
    const auto response = exchange(impl_->endpoint, impl_->credentials,
        {{"action", "tunnel-close"}, {"context", tunnel.context}}, impl_->connect_host);
    if (!response.value("ok").toBool()) {
        throw std::runtime_error("Tunnel close rejected");
    }
}

QJsonObject pairedRequest(const QUrl& endpoint, const QJsonObject& request)
{
    return exchange(endpoint, loadCredentials(endpoint), request);
}

PairedTunnel openPairedTunnel(const QUrl& endpoint, const QString& connect_host)
{
    return PairedControl::load(endpoint, connect_host)->open();
}

void heartbeatPairedTunnel(const QUrl& endpoint, const Tuntom::Endpoint& tunnel, const QString& connect_host)
{
    PairedControl::load(endpoint, connect_host)->renew(tunnel);
}

void closePairedTunnel(const QUrl& endpoint, const Tuntom::Endpoint& tunnel, const QString& connect_host)
{
    PairedControl::load(endpoint, connect_host)->close(tunnel);
}

QJsonObject pairedStatus(const QUrl& endpoint)
{
    return pairedRequest(endpoint, {{"action", "status"}});
}

QUrl pairInvitation(const QString& input)
{
    QUrl url(input, QUrl::StrictMode);
    if (!url.isValid() || url.scheme()!="skewer" || url.host().isEmpty() || url.port()<1
        || !url.userInfo().isEmpty() || url.hasQuery() || url.path()!="/pair")
        throw std::runtime_error("Invalid pairing address");
    QUrlQuery fragment(url.fragment());
    url.setFragment({});
    const QString path = statePath(url);
    QJsonObject saved;
    QFile existing(path);
    if (existing.open(QIODevice::ReadOnly)) {
        if (existing.size() > 65536) throw std::runtime_error("Pairing file exceeds bounds");
        saved=QJsonDocument::fromJson(PairingPlatform::decode(existing.readAll())).object();
    }
    if (saved["identity"].toString().isEmpty()) {
        if (fragment.queryItemValue("v")!="1") throw std::runtime_error("Unsupported pairing version");
        Credentials invitation{fragment.queryItemValue("id").toUtf8(),
            QByteArray::fromBase64(fragment.queryItemValue("psk").toLatin1(),QByteArray::Base64UrlEncoding|QByteArray::AbortOnBase64DecodingErrors)};
        QSettings settings;
        QString instance=settings.value("pairing/instance").toString();
        if (instance.isEmpty()) { instance=QUuid::createUuid().toString(QUuid::WithoutBraces);settings.setValue("pairing/instance",instance);settings.sync(); }
        if (saved["invitation"].toString()!=QString::fromUtf8(invitation.identity))
            saved={{"request",QUuid::createUuid().toString(QUuid::WithoutBraces)},{"invitation",QString::fromUtf8(invitation.identity)}};
        save(path,saved);
        const auto enrolled=exchange(url,invitation,{{"action","enroll"},{"instance",instance},{"request",saved["request"]}});
        saved={{"identity",enrolled["identity"]},{"psk",enrolled["psk"]},{"endpoint",url.toString()}};
        // Persist before commit: retry can complete after either process restarts.
        save(path,saved);
    }
    Credentials client{saved["identity"].toString().toUtf8(),QByteArray::fromBase64(saved["psk"].toString().toLatin1(),QByteArray::Base64UrlEncoding)};
    exchange(url,client,{{"action","commit"}});
    return url;
}

int pairingCommand(const QStringList& arguments)
{
    try {
        if (arguments.size()!=3 || (arguments[1]!="pair" && arguments[1]!="remote-status"))
            throw std::runtime_error("Usage: skewer pair - | skewer remote-status skewer://HOST:PORT/pair (paste pairing address on stdin)");
        const QString input = arguments[2]=="-" ? QTextStream(stdin).readLine(8192).trimmed() : arguments[2];
        QUrl url(input,QUrl::StrictMode);
        if (!url.isValid() || url.scheme()!="skewer" || url.host().isEmpty() || url.port()<1
            || !url.userInfo().isEmpty() || url.hasQuery() || url.path()!="/pair")
            throw std::runtime_error("Invalid pairing address");
        if (arguments[1]=="pair") {
            url = pairInvitation(input);
            QTextStream(stdout)<<"Paired: "<<url.toString()<<'\n';
            return 0;
        }
        url.setFragment({});
        const QString path = statePath(url);
        QJsonObject saved;
        QFile existing(path);
        if (existing.open(QIODevice::ReadOnly)) {
            if (existing.size() > 65536) throw std::runtime_error("Pairing file exceeds bounds");
            saved=QJsonDocument::fromJson(PairingPlatform::decode(existing.readAll())).object();
        }
        Credentials client{saved["identity"].toString().toUtf8(),QByteArray::fromBase64(saved["psk"].toString().toLatin1(),QByteArray::Base64UrlEncoding)};
        const auto status=exchange(url,client,{{"action","status"}});
        QTextStream(stdout)<<QJsonDocument(status).toJson(QJsonDocument::Compact)<<'\n';
        return 0;
    } catch (const std::exception& error) {
        DiagnosticLog::write("pairing", QString::fromUtf8(error.what()), "error");
        QTextStream(stderr)<<error.what()<<'\n'; return 1;
    }
}
