#include "routing_service.hpp"

namespace skewer::windows {
void serveRoutingService(const std::wstring& name, HANDLE owner_token, HANDLE stop,
                         PairedRoutingRunner runner) {
    serveRoutingService(name, ServiceOwner::fromToken(owner_token), stop, std::move(runner));
}
void serveRoutingService(const std::wstring& name, const ServiceOwner& owner, HANDLE stop,
                         PairedRoutingRunner runner, SelectedRoutingRunner selected,
                         DirectRoutingRunner direct) {
    if (!runner) {
        throw std::invalid_argument("Routing service requires a session runner");
    }
    auto commands = createSelectionPipe(name, owner);
    auto pairings = createSelectionPipe(name + L"-pair", owner);
    std::unique_ptr<PairingHandoff> pairing;
    std::unique_ptr<ProcessTarget> target;
    std::optional<std::array<std::uint8_t, 4>> direct_gateway;
    RoutingScope scope{RoutingScope::None};
    RoutingTransport transport{RoutingTransport::None};
    std::optional<ProcessKey> selected_identity;
    const auto describe = [&](RoutingReply state) {
        if (state.phase == RoutingPhase::Idle || state.phase == RoutingPhase::Failed) {
            scope = RoutingScope::None;
            transport = RoutingTransport::None;
            selected_identity.reset();
            direct_gateway.reset();
        }
        state.scope = scope;
        state.transport = transport;
        state.selected = selected_identity;
        state.paired = bool(pairing);
        return state;
    };
    // Declared after pairing: cancel/join the runner before wiping credentials.
    RoutingController controller([&](HANDLE cancel, RoutingSignals& state) {
        if (target) {
            selected(*pairing, std::move(target), cancel, state);
        } else if (direct_gateway) {
            direct(*direct_gateway, cancel, state);
        } else {
            runner(*pairing, cancel, state);
        }
    });
    SelectedRoutingHandler startSelected;
    if (selected) {
        startSelected = [&](std::unique_ptr<ProcessTarget> next, std::uint64_t generation) {
            // Status joins a finished generation before replacing its pinned
            // target. Only this command thread may start or replace a session.
            auto state = controller.command(RoutingCommand::Status, 0);
            if (generation != state.generation) {
                state.result = RoutingResult::Stale;
                return describe(state);
            }
            if (state.phase != RoutingPhase::Idle && state.phase != RoutingPhase::Failed) {
                state.result = RoutingResult::Busy;
                return describe(state);
            }
            if (!pairing || !next || !next->running()) {
                throw std::runtime_error("Pair and select a live process before routing");
            }
            const auto identity = next->key();
            direct_gateway.reset();
            target = std::move(next);
            try {
                auto started = controller.command(RoutingCommand::Start, generation);
                if (started.result == RoutingResult::Ok) {
                    scope = RoutingScope::SelectedProcess;
                    transport = RoutingTransport::Tunnel;
                    selected_identity = identity;
                }
                return describe(started);
            } catch (...) {
                target.reset();
                throw;
            }
        };
    }
    DirectRoutingHandler startDirect;
    if (direct) {
        startDirect = [&](std::array<std::uint8_t, 4> gateway, std::uint64_t generation) {
            auto state = controller.command(RoutingCommand::Status, 0);
            if (generation != state.generation) {
                state.result = RoutingResult::Stale;
                return describe(state);
            }
            if (state.phase != RoutingPhase::Idle && state.phase != RoutingPhase::Failed) {
                state.result = RoutingResult::Busy;
                return describe(state);
            }
            target.reset();
            direct_gateway = gateway;
            auto started = controller.command(RoutingCommand::Start, generation);
            if (started.result == RoutingResult::Ok) {
                scope = RoutingScope::WholeHost;
                transport = RoutingTransport::Direct;
                selected_identity.reset();
            }
            return describe(started);
        };
    }
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
            serveRoutingCommand(commands->get(), owner, stop, 2000,
                                [&](RoutingCommand command, std::uint64_t generation) {
                                    if (command == RoutingCommand::Start && !pairing) {
                                        throw std::runtime_error("Pair before starting routing");
                                    }
                                    if (command == RoutingCommand::Start) {
                                        const auto current = describe(
                                            controller.command(RoutingCommand::Status, 0));
                                        if ((current.phase == RoutingPhase::Idle ||
                                             current.phase == RoutingPhase::Failed) &&
                                            generation == current.generation) {
                                            target.reset();
                                            direct_gateway.reset();
                                        }
                                    }
                                    auto state = controller.command(command, generation);
                                    if (command == RoutingCommand::Start && state.result == RoutingResult::Ok) {
                                        scope = RoutingScope::WholeHost;
                                        transport = RoutingTransport::Tunnel;
                                        selected_identity.reset();
                                    }
                                    return describe(state);
                                }, startSelected, startDirect);
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
            pairing = receivePairingHandoff(pairings->get(), owner, stop, 2000);
            finishSelection(pairings->get(), stop, 500);
        } catch (const std::exception&) {
            // Failed handoff preserves the previous complete credential set.
        }
        DisconnectNamedPipe(pairings->get());
    }
}
} // namespace skewer::windows
