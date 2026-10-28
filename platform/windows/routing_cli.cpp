#include "routing_client.hpp"
#include "routed_launch.hpp"
#include "stored_pairing_handoff.hpp"
#include <QCoreApplication>
#include <QJsonDocument>
#include <QJsonObject>
#include <QTextStream>

using namespace skewer::windows;
int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    const auto args = app.arguments();
    if (args.size() < 3) {
        QTextStream(stderr) << "Usage: skewer-routing-control status SERVICE\n"
                               "       skewer-routing-control start|stop|release SERVICE GENERATION\n"
                               "       skewer-routing-control pair SERVICE PAIRED_ENDPOINT\n"
                               "       skewer-routing-control attach SERVICE GENERATION PID BIRTH\n"
                               "       skewer-routing-control run SERVICE EXECUTABLE [ARGUMENTS...]\n"
                               "       (aliases: start-process=attach, launch=run)\n";
        return 2;
    }
    try {
        const auto action = args[1];
        const bool launching = action == "launch" || action == "run";
        if (launching) {
            if (args.size() < 4) {
                throw std::invalid_argument("Routed launch requires an executable");
            }
            Handle cancel(CreateEventW(nullptr, TRUE, FALSE, nullptr));
            if (!cancel) {
                throw std::runtime_error("Cannot create cancellation event");
            }
            std::vector<std::wstring> arguments;
            for (qsizetype i = 4; i < args.size(); ++i) {
                arguments.push_back(args[i].toStdWString());
            }
            QTextStream(stderr) << "Preparing selected-process routing before launch...\n";
            const auto launched =
                launchRouted(args[2].toStdWString(), args[3].toStdWString(), arguments, cancel.get());
            Handle process(launched.process.hProcess), thread(launched.process.hThread);
            QTextStream(stdout) << "{\"pid\":" << launched.identity.pid << ",\"birth\":\""
                                << launched.identity.created << "\",\"generation\":\"" << launched.generation
                                << "\"}\n";
            return 0;
        }
        const bool pairing = action == "pair";
        const bool selected = action == "start-process" || action == "attach";
        const bool stopping = action == "stop" || action == "release";
        const int expected = selected ? 6 : action == "status" ? 3 : 4;
        if (args.size() != expected ||
            (action != "status" && action != "start" && !stopping && !pairing && !selected)) {
            throw std::invalid_argument("Invalid routing command");
        }
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
        if (selected) {
            bool pid_valid{}, birth_valid{};
            const auto pid = args[4].toULongLong(&pid_valid);
            const auto birth = args[5].toULongLong(&birth_valid);
            if (!pid_valid || !birth_valid || !pid || pid > MAXDWORD || !birth) {
                throw std::invalid_argument("Invalid selected process identity");
            }
            response = exchangeSelectedRouting(pipe->get(), name, {static_cast<DWORD>(pid), birth},
                                               generation, cancel.get(), 3000);
        } else {
            response = exchangeRoutingCommand(pipe->get(), name, operation, generation, cancel.get(), 3000);
        }
        QJsonObject output{{"result", static_cast<int>(response.result)},
                           {"phase", static_cast<int>(response.phase)},
                           {"generation", QString::number(response.generation)},
                           {"scope", static_cast<int>(response.scope)},
                           {"paired", response.paired}};
        if (response.selected) {
            output["selected"] = QJsonObject{{"pid", static_cast<qint64>(response.selected->pid)},
                                               {"birth", QString::number(response.selected->created)}};
        }
        if (!response.detail.empty()) output["detail"] = QString::fromUtf8(response.detail);
        QTextStream(stdout) << QJsonDocument(output).toJson(QJsonDocument::Compact) << '\n';
        return response.result == RoutingResult::Ok ? 0 : 1;
    } catch (const std::exception& error) {
        QTextStream(stderr) << error.what() << '\n';
        return 1;
    }
}
