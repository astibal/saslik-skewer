#include "routing_client.hpp"
#include "stored_pairing_handoff.hpp"
#include <QCoreApplication>
#include <QTextStream>

using namespace skewer::windows;
int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    const auto args = app.arguments();
    if (args.size() < 3 || args.size() > 6) {
        QTextStream(stderr) << "Usage: skewer-routing-control status SERVICE\n"
                               "       skewer-routing-control start|stop SERVICE GENERATION\n"
                               "       skewer-routing-control pair SERVICE PAIRED_ENDPOINT\n"
                               "       skewer-routing-control start-process SERVICE GENERATION PID BIRTH\n"
                               "       (experimental: fresh IPv4 TCP, one process, no descendants)\n";
        return 2;
    }
    try {
        const auto action = args[1];
        const bool pairing = action == "pair";
        const bool selected = action == "start-process";
        const int expected = selected ? 6 : action == "status" ? 3 : 4;
        if (args.size() != expected ||
            (action != "status" && action != "start" && action != "stop" && !pairing && !selected)) {
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
        const auto operation = action == "start"  ? RoutingCommand::Start
                               : action == "stop" ? RoutingCommand::Stop
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
        QTextStream(stdout) << "{\"result\":" << unsigned(response.result)
                            << ",\"phase\":" << unsigned(response.phase) << ",\"generation\":\""
                            << response.generation << "\"}\n";
        return response.result == RoutingResult::Ok ? 0 : 1;
    } catch (const std::exception& error) {
        QTextStream(stderr) << error.what() << '\n';
        return 1;
    }
}
