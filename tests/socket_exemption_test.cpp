// Exercise real netlink snapshot/destroy with a test scope. Production derives
// its scope exclusively from the caller's routed slice; no cgroups are modified.
#include "../src/socket_cleanup.cpp"
#include <QCoreApplication>
#include <QProcess>

struct Pair {
    int listener = -1, client = -1, peer = -1;
    quint16 port = 0;
    ~Pair() { for (int fd : {client, peer, listener}) if (fd >= 0) close(fd); }
    bool open(quint32 address) {
        listener = socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in local{}; local.sin_family = AF_INET; local.sin_addr.s_addr = htonl(address);
        if (::bind(listener, reinterpret_cast<sockaddr*>(&local), sizeof(local)) || listen(listener, 2)) return false;
        socklen_t length = sizeof(local);
        if (getsockname(listener, reinterpret_cast<sockaddr*>(&local), &length)) return false;
        port = local.sin_port;
        client = socket(AF_INET, SOCK_STREAM, 0);
        auto source = local; source.sin_port = 0;
        if (::bind(client, reinterpret_cast<sockaddr*>(&source), sizeof(source))
            || ::connect(client, reinterpret_cast<sockaddr*>(&local), sizeof(local))) return false;
        peer = accept(listener, nullptr, nullptr);
        timeval timeout{1, 0}; setsockopt(peer, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        return peer >= 0;
    }
    bool alive() { char byte{}; return send(client, "x", 1, MSG_NOSIGNAL) == 1 && recv(peer, &byte, 1, 0) == 1; }
};

int main(int argc, char** argv)
{
    QCoreApplication app(argc, argv);
    if (argc != 2 || QFile::symLinkTarget("/proc/self/ns/net") == QString::fromLocal8Bit(argv[1])) return 2;
    if (QProcess::execute("ip", {"link", "set", "lo", "up"})) return 3;
    Pair affected, untouched, fresh;
    if (!affected.open(0x7f000001) || !untouched.open(0x7f000002)) return 4;
    QVector<Socket> sockets;
    if (!query(AF_INET, nullptr, false, sockets)) return 5;
    QSet<quint64> groups;
    for (const auto& socket : sockets)
        if (socket.message.id.idiag_dport == affected.port && socket.group) groups.insert(socket.group);
    if (groups.isEmpty()) return 77;
    QString error;
    // Wrong owner/scope and unchanged effective routing must not reset sockets.
    for (const auto& cleanup : {
            prepareScopedExemptionCleanup(getuid() + 1, groups, {}, {"127.0.0.1"}, error),
            prepareScopedExemptionCleanup(getuid(), {}, {}, {"127.0.0.1"}, error),
            prepareScopedExemptionCleanup(getuid(), groups, {"127.0.0.0/8"}, {"127.0.0.0/8", "127.0.0.1"}, error)}) {
        if (!cleanup || cleanup() || !affected.alive() || !untouched.alive()) return 6;
    }
    auto cleanup = prepareScopedExemptionCleanup(getuid(), groups, {}, {"127.0.0.1"}, error);
    if (!cleanup || !fresh.open(0x7f000001)) return 7;
    // Checkbox-off behavior: taking a snapshot alone has no side effects.
    if (!affected.alive() || !untouched.alive()) return 8;
    if (cleanup() || affected.alive() || !untouched.alive() || !fresh.alive()) return 9;
    int listening = 0; socklen_t length = sizeof(listening);
    getsockopt(affected.listener, SOL_SOCKET, SO_ACCEPTCONN, &listening, &length);
    if (!listening) return 10;
    cleanup = prepareScopedExemptionCleanup(getuid(), groups, {"127.0.0.1"}, {}, error);
    if (!cleanup || cleanup() || fresh.alive() || !untouched.alive()) return 11;
    return 0;
}
