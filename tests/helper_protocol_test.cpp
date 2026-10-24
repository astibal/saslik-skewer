#include "helper_protocol.hpp"
#include "tunnel_helper_session.hpp"
#include <QElapsedTimer>
#include <QTextStream>
#include <unistd.h>
#include <iostream>

int main(int argc, char** argv)
{
    QCoreApplication app(argc, argv);
    // Harmless stand-in for the controller: no root, systemd, or routing.
    if (app.arguments().contains("tunnel-session")) {
        QTextStream input(stdin), output(stdout);
        if (input.readLine() != "{}") return 10;
        output << "ready\n" << Qt::flush;
        while (!input.atEnd()) {
            const auto line = input.readLine();
            if (line == "stop") return 0;
            if (line == "keepalive") output << "renewed\n" << Qt::flush;
        }
        return 0;
    }
    TunnelHelperSession session(getuid());
    // An authorized session is healthy even before any tunnel exists.
    const auto idle = session.request({"tunnel-poll"});
    if (idle.exit_code || QJsonDocument::fromJson(idle.output).object()["running"].toBool()) return 18;
    if (!session.request({"tunnel-start", "broken"}).exit_code) return 11;
    for (int cycle = 0; cycle < 2; ++cycle) {
        if (session.request({"tunnel-start", "{}"}).exit_code) return 12;
        if (!session.request({"tunnel-start", "{}"}).exit_code) return 13;
        QElapsedTimer timer; timer.start();
        QByteArray output;
        while (!output.contains("ready") && timer.elapsed() < 3000) {
            const auto reply = session.request({"tunnel-poll"});
            output += QJsonDocument::fromJson(reply.output).object()["stdout"].toString().toUtf8();
        }
        if (!output.contains("ready")) return 14;
        if (session.request({"tunnel-renew"}).exit_code) return 15;
        if (session.request({"tunnel-stop"}).exit_code) return 16;
        if (QJsonDocument::fromJson(session.request({"tunnel-poll"}).output).object()["running"].toBool()) return 17;
    }
    QStringList args;
    for (const auto* op : {"tunnel-start", "tunnel-poll", "tunnel-renew", "tunnel-stop"}) {
        const auto frame = QJsonDocument(QJsonObject{{"args", QJsonArray{op}}}).toJson(QJsonDocument::Compact);
        if (!HelperProtocol::decode(frame, args)) return 5;
    }
    if (!HelperProtocol::decode(R"({"args":["resume"]})", args)
        || args != QStringList{"resume"}) return 4;
    if (!HelperProtocol::decode(R"({"args":["up","192.0.2.2"]})", args)
        || args != QStringList{"up", "192.0.2.2"}) return 1;
    for (const auto* value : {
        R"({"args":["serve"]})", R"({"args":["tunnel-worker"]})",
        R"({"args":["ca-install","x","y"]})", R"({"args":["/bin/sh","-c","id"]})",
        R"({"args":["status"],"uid":0})", R"({"args":["status",0]})",
        R"({"args":["status","\u0000"]})", R"({"args":[]})", "broken"}) {
        if (HelperProtocol::decode(value, args)) return 2;
    }
    if (HelperProtocol::decode(QByteArray(HelperProtocol::maxRequest + 1, ' '), args)) return 3;
    std::cout << "Helper protocol validates bounded commands without identity overrides\n";
}
