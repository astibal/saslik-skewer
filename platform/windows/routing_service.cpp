#include "routing_service.hpp"
#include <algorithm>

namespace skewer::windows {
void serveRoutingService(const std::wstring& name, HANDLE owner_token, HANDLE stop,
                         PairedRoutingRunner runner) {
    serveRoutingService(name, ServiceOwner::fromToken(owner_token), stop, std::move(runner));
}
void serveRoutingService(const std::wstring& name, const ServiceOwner& owner, HANDLE stop,
                         PairedRoutingRunner runner, SelectedRoutingRunner selected,
                         DirectRoutingRunner direct) {
    if (!runner && !direct) {
        throw std::invalid_argument("Routing service requires a tunnel or direct runner");
    }
    auto commands = createSelectionPipe(name, owner);
    auto pairings = createSelectionPipe(name + L"-pair", owner);
    std::unique_ptr<PairingHandoff> pairing;
    std::unique_ptr<ProcessTarget> target;
    std::optional<std::array<std::uint8_t, 4>> direct_gateway;
    RoutingScope scope{RoutingScope::None};
    RoutingTransport transport{RoutingTransport::None};
    std::vector<skewer::traffic::Ipv4Prefix> active_exemptions;
    std::optional<ProcessKey> selected_identity;
    const auto describe = [&](RoutingReply state) {
        if (state.phase == RoutingPhase::Idle || state.phase == RoutingPhase::Failed) {
            scope = RoutingScope::None;
            transport = RoutingTransport::None;
            selected_identity.reset();
            direct_gateway.reset();
            active_exemptions.clear();
        }
        state.scope = scope;
        state.transport = transport;
        if (scope == RoutingScope::SelectedProcess) {
            if (!state.selections.empty()) selected_identity = state.selections.front();
            else if (state.phase == RoutingPhase::Starting && selected_identity) {
                state.selections.push_back(*selected_identity);
            }
        } else {
            state.selections.clear();
        }
        state.selected = selected_identity;
        state.exemptions = active_exemptions;
        state.paired = bool(pairing);
        state.tunnel_available = bool(runner);
        state.direct_available = bool(direct);
        return state;
    };
    // Declared after pairing: cancel/join the runner before wiping credentials.
    RoutingController controller([&](HANDLE cancel, RoutingSignals& state) {
        if (target) {
            if (!selected || !pairing) {
                throw std::logic_error("Selected routing has no configured tunnel runner");
            }
            selected(*pairing, std::move(target), active_exemptions, cancel, state);
        } else if (direct_gateway) {
            direct(*direct_gateway, active_exemptions, cancel, state);
        } else {
            if (!runner || !pairing) {
                throw std::logic_error("Tunnel routing is not configured");
            }
            runner(*pairing, active_exemptions, cancel, state);
        }
    });
    SelectedRoutingHandler startSelected;
    if (selected) {
        startSelected = [&](std::unique_ptr<ProcessTarget> next,
                            std::vector<skewer::traffic::Ipv4Prefix> exemptions,
                            std::uint64_t generation) {
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
            active_exemptions = std::move(exemptions);
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
                active_exemptions.clear();
                throw;
            }
        };
    }
    const PauseChangeHandler changePause = [&](bool paused, std::uint64_t generation) {
        auto current = describe(controller.command(RoutingCommand::Status, 0));
        if (current.generation != generation) {
            current.result = RoutingResult::Stale;
            return current;
        }
        if (!current.pause_available)
            throw std::runtime_error("This routing worker does not support protected pause");
        const auto request = controller.changePause(paused, generation);
        const auto deadline = GetTickCount64() + 25000;
        for (;;) {
            current = describe(controller.command(RoutingCommand::Status, 0));
            const auto phase = request->phase.load();
            if (phase == PauseChange::Phase::Complete) {
                if (!request->error.empty()) throw std::runtime_error(request->error);
                return describe(controller.command(RoutingCommand::Status, 0));
            }
            if (phase == PauseChange::Phase::Cancelled)
                throw std::runtime_error("Pause change cancelled");
            if (WaitForSingleObject(stop, 10) != WAIT_TIMEOUT || GetTickCount64() >= deadline) {
                const bool cancelled = request->cancel();
                throw std::runtime_error(cancelled ? "Pause change cancelled before execution"
                                                  : "Pause outcome uncertain; inspect routing status");
            }
        }
    };
    DirectRoutingHandler startDirect;
    const SelectionChangeHandler changeSelection = [&](SelectionOperation operation, ProcessKey process,
                                                        std::uint64_t generation) {
        auto current = describe(controller.command(RoutingCommand::Status, 0));
        if (current.generation != generation) {
            current.result = RoutingResult::Stale;
            return current;
        }
        if (current.scope != RoutingScope::SelectedProcess ||
            (current.phase != RoutingPhase::Active && current.phase != RoutingPhase::Blocked)) {
            current.result = RoutingResult::Busy;
            return current;
        }
        const bool present = std::ranges::find(current.selections, process) != current.selections.end();
        if ((operation == SelectionOperation::Add && present) ||
            (operation == SelectionOperation::Remove && !present)) return current;
        const auto request = controller.changeSelection(operation, process, generation);
        const auto deadline = GetTickCount64() + 25000;
        for (;;) {
            // Reap joins a failed worker and completes any abandoned request.
            current = describe(controller.command(RoutingCommand::Status, 0));
            const auto phase = request->phase.load();
            if (phase == SelectionChange::Phase::Complete) {
                if (!request->error.empty()) throw std::runtime_error(request->error);
                break;
            }
            if (phase == SelectionChange::Phase::Cancelled) throw std::runtime_error("Selection change cancelled");
            if (WaitForSingleObject(stop, 10) != WAIT_TIMEOUT || GetTickCount64() >= deadline) {
                const bool cancelled = request->cancel();
                throw std::runtime_error(cancelled ? "Selection change cancelled before execution"
                    : "Selection result uncertain; inspect status before retrying");
            }
        }
        current = describe(controller.command(RoutingCommand::Status, 0));
        if (operation == SelectionOperation::Remove && current.selections.empty()) {
            controller.command(RoutingCommand::Stop, generation);
        }
        return describe(controller.command(RoutingCommand::Status, 0));
    };
    if (direct) {
        startDirect = [&](std::array<std::uint8_t, 4> gateway,
                          std::vector<skewer::traffic::Ipv4Prefix> exemptions,
                          std::uint64_t generation) {
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
            active_exemptions = std::move(exemptions);
            try {
                auto started = controller.command(RoutingCommand::Start, generation);
                if (started.result == RoutingResult::Ok) {
                    scope = RoutingScope::WholeHost;
                    transport = RoutingTransport::Direct;
                    selected_identity.reset();
                }
                return describe(started);
            } catch (...) {
                direct_gateway.reset();
                active_exemptions.clear();
                throw;
            }
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
            serveRoutingCommand(commands->get(), owner, stop, 30000,
                                [&](RoutingCommand command, std::uint64_t generation,
                                    std::vector<skewer::traffic::Ipv4Prefix> exemptions) {
                                    if (command == RoutingCommand::Start && !runner) {
                                        throw std::runtime_error(
                                            "Upgrade the service with a pairing endpoint before tunnel routing");
                                    }
                                    if (command == RoutingCommand::Start && !pairing) {
                                        throw std::runtime_error("Pair before starting tunnel routing");
                                    }
                                    if (command == RoutingCommand::Start) {
                                        const auto current = describe(
                                            controller.command(RoutingCommand::Status, 0));
                                        if ((current.phase == RoutingPhase::Idle ||
                                             current.phase == RoutingPhase::Failed) &&
                                            generation == current.generation) {
                                            target.reset();
                                            direct_gateway.reset();
                                            active_exemptions = std::move(exemptions);
                                        }
                                    }
                                    auto state = controller.command(command, generation);
                                    if (command == RoutingCommand::Start && state.result == RoutingResult::Ok) {
                                        scope = RoutingScope::WholeHost;
                                        transport = RoutingTransport::Tunnel;
                                        selected_identity.reset();
                                    }
                                    return describe(state);
                                }, startSelected, startDirect, changeSelection, changePause);
            finishSelection(commands->get(), stop, 500);
        } catch (const std::exception&) {
            // Malformed, disconnected and unauthorized clients affect only
            // their request. They cannot tear down a service-owned session.
        }
        DisconnectNamedPipe(commands->get());
        try {
            acceptSelection(pairings->get(), stop, 100);
            if (!runner) {
                throw std::runtime_error(
                    "Direct-only service cannot accept pairing; configure tunnel support first");
            }
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
