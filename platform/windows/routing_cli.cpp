#include "routing_client.hpp"
#include "routed_launch.hpp"
#include "destination_exemption_settings.hpp"
#include "stored_pairing_handoff.hpp"
#include <QCoreApplication>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QHostAddress>
#include <QTextStream>

using namespace skewer::windows;
int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    const auto args = app.arguments();
    if (args.size() < 3) {
        QTextStream(stderr) << "Usage: skewer-routing-control status SERVICE\n"
                               "       skewer-routing-control start SERVICE GENERATION [--exempt IPV4_CIDR]...\n"
                               "       skewer-routing-control stop|release|pause|resume SERVICE GENERATION\n"
                               "       skewer-routing-control start-direct SERVICE GENERATION IPV4_GATEWAY [--exempt IPV4_CIDR]...\n"
                               "       skewer-routing-control pair SERVICE PAIRED_ENDPOINT\n"
                               "       skewer-routing-control attach SERVICE GENERATION PID BIRTH [--exempt IPV4_CIDR]...\n"
                               "       skewer-routing-control add|remove SERVICE GENERATION PID BIRTH\n"
                               "       skewer-routing-control run SERVICE [--exempt IPV4_CIDR]... EXECUTABLE [ARGUMENTS...]\n"
                               "       (aliases: start-process=attach, launch=run)\n";
        return 2;
    }
    try {
        const auto action = args[1];
        const bool launching = action == "launch" || action == "run";
        if (launching) {
            qsizetype executable_index = 3;
            QStringList exemption_text;
            while (executable_index < args.size() && args[executable_index] == "--exempt") {
                if (++executable_index >= args.size()) {
                    throw std::invalid_argument("Missing IPv4 CIDR after --exempt");
                }
                exemption_text.push_back(args[executable_index++]);
            }
            if (executable_index >= args.size()) {
                throw std::invalid_argument("Routed launch requires an executable");
            }
            const auto exemptions = parseDestinationExemptions(exemption_text);
            Handle cancel(CreateEventW(nullptr, TRUE, FALSE, nullptr));
            if (!cancel) {
                throw std::runtime_error("Cannot create cancellation event");
            }
            std::vector<std::wstring> arguments;
            for (qsizetype i = executable_index + 1; i < args.size(); ++i) {
                arguments.push_back(args[i].toStdWString());
            }
            QTextStream(stderr) << "Preparing selected-process routing before launch...\n";
            const auto launched =
                launchRouted(args[2].toStdWString(), args[executable_index].toStdWString(), arguments,
                             cancel.get(), {}, 30000, LaunchConsole::Inherit, exemptions);
            Handle process(launched.process.hProcess), thread(launched.process.hThread);
            QTextStream(stdout) << "{\"pid\":" << launched.identity.pid << ",\"birth\":\""
                                << launched.identity.created << "\",\"generation\":\"" << launched.generation
                                << "\"}\n";
            return 0;
        }
        const bool pairing = action == "pair";
        const bool selected = action == "start-process" || action == "attach";
        const bool change = action == "add" || action == "remove";
        const bool direct = action == "start-direct";
        const bool stopping = action == "stop" || action == "release";
        const bool pausing = action == "pause" || action == "resume";
        const int expected = (selected || change) ? 6 : direct ? 5 : action == "status" ? 3 : 4;
        const bool accepts_exemptions = action == "start" || selected || direct;
        if (args.size() < expected || (!accepts_exemptions && args.size() != expected) ||
            (accepts_exemptions && (args.size() - expected) % 2) ||
            (action != "status" && action != "start" && !stopping && !pausing && !pairing && !selected && !change && !direct)) {
            throw std::invalid_argument("Invalid routing command");
        }
        QStringList exemption_text;
        for (qsizetype index = expected; index < args.size(); index += 2) {
            if (args[index] != "--exempt") {
                throw std::invalid_argument("Expected --exempt IPV4_CIDR");
            }
            exemption_text.push_back(args[index + 1]);
        }
        const auto exemptions = parseDestinationExemptions(exemption_text);
        Handle cancel(CreateEventW(nullptr, TRUE, FALSE, nullptr));
        if (!cancel) {
            throw std::runtime_error("Cannot create cancellation event");
        }
        const auto name = args[2].toStdWString();
        auto pipe = connectRoutingService(name, pairing, cancel.get(), 3000);
        if (pairing) {
            sendStoredPairing(pipe->get(), name, QUrl(args[3]), cancel.get(), 3000);
            QTextStream(stdout) << "Pairing delivered; routing has not been started.\n";
            return 0;
        }
        std::uint64_t generation{};
        if (action != "status") {
            bool valid{};
            generation = args[3].toULongLong(&valid);
            if (!valid) {
                throw std::invalid_argument("Invalid routing generation");
            }
        }
        const auto operation = action == "start" ? RoutingCommand::Start
                               : stopping        ? RoutingCommand::Stop
                                                 : RoutingCommand::Status;
        RoutingReply response;
        if (pausing) {
            response = exchangePauseChange(pipe->get(), name, action == "pause", generation,
                                           cancel.get(), 30000);
        } else if (selected || change) {
            bool pid_valid{}, birth_valid{};
            const auto pid = args[4].toULongLong(&pid_valid);
            const auto birth = args[5].toULongLong(&birth_valid);
            if (!pid_valid || !birth_valid || !pid || pid > MAXDWORD || !birth) {
                throw std::invalid_argument("Invalid selected process identity");
            }
            if (change) {
                response = exchangeSelectionChange(pipe->get(), name,
                    action == "add" ? SelectionOperation::Add : SelectionOperation::Remove,
                    {static_cast<DWORD>(pid), birth}, generation, cancel.get(), 30000);
            } else {
                response = exchangeSelectedRouting(pipe->get(), name, {static_cast<DWORD>(pid), birth},
                                                   generation, cancel.get(), 3000, exemptions);
            }
        } else if (direct) {
            QHostAddress address;
            if (!address.setAddress(args[4]) || address.protocol() != QAbstractSocket::IPv4Protocol ||
                address.toString() != args[4]) {
                throw std::invalid_argument("Direct routing requires a canonical IPv4 gateway");
            }
            const auto value = address.toIPv4Address();
            response = exchangeDirectRouting(
                pipe->get(), name,
                {static_cast<std::uint8_t>(value >> 24), static_cast<std::uint8_t>(value >> 16),
                 static_cast<std::uint8_t>(value >> 8), static_cast<std::uint8_t>(value)},
                generation, cancel.get(), 3000, exemptions);
        } else {
            response = exchangeRoutingCommand(pipe->get(), name, operation, generation, cancel.get(), 3000,
                                              exemptions);
        }
        QJsonObject output{{"result", static_cast<int>(response.result)},
                           {"phase", static_cast<int>(response.phase)},
                           {"generation", QString::number(response.generation)},
                           {"scope", static_cast<int>(response.scope)},
                           {"transport", static_cast<int>(response.transport)},
                           {"paired", response.paired},
                           {"tunnelAvailable", response.tunnel_available},
                           {"directAvailable", response.direct_available},
                           {"pauseAvailable", response.pause_available},
                           {"paused", response.paused}};
        if (response.selected) {
            output["selected"] = QJsonObject{{"pid", static_cast<qint64>(response.selected->pid)},
                                               {"birth", QString::number(response.selected->created)}};
        }
        if (!response.detail.empty()) output["detail"] = QString::fromUtf8(response.detail);
        QJsonArray selections;
        for (const auto process : response.selections) {
            selections.append(QJsonObject{{"pid", static_cast<qint64>(process.pid)},
                                           {"birth", QString::number(process.created)}});
        }
        output["selections"] = selections;
        QJsonArray members;
        for (const auto process : response.selection_members) {
            members.append(QJsonObject{{"pid", static_cast<qint64>(process.pid)},
                                       {"birth", QString::number(process.created)}});
        }
        output["members"] = members;
        output["membersTruncated"] = response.members_truncated;
        QJsonArray exemption_output;
        for (const auto prefix : response.exemptions) {
            exemption_output.append(QString::fromStdString(prefix.text()));
        }
        output["exemptions"] = exemption_output;
        QTextStream(stdout) << QJsonDocument(output).toJson(QJsonDocument::Compact) << '\n';
        return response.result == RoutingResult::Ok ? 0 : 1;
    } catch (const std::exception& error) {
        QTextStream(stderr) << error.what() << '\n';
        return 1;
    }
}
