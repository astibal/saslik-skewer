#include "routing_client.hpp"
#include "stored_pairing_handoff.hpp"
#include <QCoreApplication>
#include <QTextStream>

using namespace skewer::windows;
int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    const auto args = app.arguments();
    if (args.size() < 3 || args.size() > 4) {
        QTextStream(stderr) << "Usage: skewer-routing-control status SERVICE\n"
                               "       skewer-routing-control start|stop SERVICE GENERATION\n"
                               "       skewer-routing-control pair SERVICE PAIRED_ENDPOINT\n";
        return 2;
    }
    try {
        const auto action = args[1];
        const bool pairing = action == "pair";
        if ((action == "status" && args.size() != 3) || (action != "status" && args.size() != 4) ||
            (action != "status" && action != "start" && action != "stop" && !pairing)) {
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
        const auto response =
            exchangeRoutingCommand(pipe->get(), name, operation, generation, cancel.get(), 3000);
        QTextStream(stdout) << "{\"result\":" << unsigned(response.result)
                            << ",\"phase\":" << unsigned(response.phase) << ",\"generation\":\""
                            << response.generation << "\"}\n";
        return response.result == RoutingResult::Ok ? 0 : 1;
    } catch (const std::exception& error) {
        QTextStream(stderr) << error.what() << '\n';
        return 1;
    }
}
