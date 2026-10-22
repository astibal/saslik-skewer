#include "socket_cleanup.hpp"
#include "cgroup_manager.hpp"
#include "routing_guard.hpp"
#include <QCoreApplication>
#include <QTcpServer>
#include <QTcpSocket>
#include <QFile>
#include <QThread>
#include <unistd.h>

int main(int argc, char** argv)
{
    QCoreApplication app(argc,argv);
    if (!RoutingGuard::installed(getuid())) return 77;
    QTcpServer server;
    if (!server.listen(QHostAddress::LocalHost)) return 1;
    QTcpSocket client;
    client.connectToHost(QHostAddress::LocalHost,server.serverPort());
    if (!client.waitForConnected(1000) || !server.waitForNewConnection(1000)) return 2;
    auto* peer = server.nextPendingConnection();
    if (!peer) return 3;
    const auto moved = CgroupManager().route({getpid()},"cleanup-preview-test");
    if (!moved.ok) return 4;
    QThread::msleep(500);
    QFile stat(QString("/proc/%1/stat").arg(getpid()));
    if (!stat.open(QIODevice::ReadOnly)) return 5;
    const auto bytes = stat.readAll();
    const auto start = bytes.mid(bytes.lastIndexOf(')')+2).split(' ').value(19);
    int count = 0;
    const int result = cleanupSockets(getuid(),{QString::number(getpid())+':'+QString::fromLatin1(start)},true,&count);
    // Both ends were created outside the slice; the listener must not be counted.
    if (result || count != 2) return 6;
    client.write("alive"); client.waitForBytesWritten(1000);
    if (!peer->waitForReadyRead(1000) || peer->readAll() != "alive") return 7;
    return 0;
}
