#include "routing_service.hpp"

namespace skewer::windows {
void serveRoutingService(const std::wstring& name, HANDLE owner_token, HANDLE stop,
                         PairedRoutingRunner runner) {
    if (!runner) {
        throw std::invalid_argument("Routing service requires a session runner");
    }
    auto commands = createSelectionPipe(name, owner_token);
    auto pairings = createSelectionPipe(name + L"-pair", owner_token);
    std::unique_ptr<PairingHandoff> pairing;
    // Declared after pairing: cancel/join the runner before wiping credentials.
    RoutingController controller(
        [&](HANDLE cancel, RoutingSignals& state) { runner(*pairing, cancel, state); });
    for (;;) {
        const auto wait = WaitForSingleObject(stop, 0);
        if (wait == WAIT_OBJECT_0) {
            return;
        }
        if (wait != WAIT_TIMEOUT) {
            throw std::runtime_error("Cannot inspect routing service stop event");
        }
        try {
            acceptSelection(commands->get(), stop, 100);
            serveRoutingCommand(commands->get(), owner_token, stop, 2000,
                                [&](RoutingCommand command, std::uint64_t generation) {
                                    if (command == RoutingCommand::Start && !pairing) {
                                        throw std::runtime_error("Pair before starting routing");
                                    }
                                    return controller.command(command, generation);
                                });
            finishSelection(commands->get(), stop, 500);
        } catch (const std::exception&) {
            // Malformed, disconnected and unauthorized clients affect only
            // their request. They cannot tear down a service-owned session.
        }
        DisconnectNamedPipe(commands->get());
        try {
            acceptSelection(pairings->get(), stop, 100);
            const auto state = controller.command(RoutingCommand::Status, 0);
            if (state.phase != RoutingPhase::Idle && state.phase != RoutingPhase::Failed) {
                throw std::runtime_error("Cannot replace pairing during a routing generation");
            }
            pairing = receivePairingHandoff(pairings->get(), owner_token, stop, 2000);
            finishSelection(pairings->get(), stop, 500);
        } catch (const std::exception&) {
            // Failed handoff preserves the previous complete credential set.
        }
        DisconnectNamedPipe(pairings->get());
    }
}
} // namespace skewer::windows
