#include "routing_control.hpp"
#include <iostream>

using namespace skewer::windows;
namespace {
void require(bool ok, const char* message) {
    if (!ok) {
        throw std::runtime_error(message);
    }
}
RoutingReply awaitPhase(RoutingController& controller, RoutingPhase phase) {
    for (unsigned i = 0; i < 200; ++i) {
        const auto result = controller.command(RoutingCommand::Status, 0);
        if (result.phase == phase) {
            return result;
        }
        Sleep(5);
    }
    throw std::runtime_error("Controller phase timeout");
}
} // namespace
int main() {
    try {
        std::atomic_uint starts{};
        std::atomic_bool finish_cleanup{};
        RoutingController controller([&](HANDLE stop, RoutingSignals& signals) {
            ++starts;
            signals.ready = true; // Synthetic readiness; no networking in this test.
            WaitForSingleObject(stop, INFINITE);
            signals.ready = false;
            while (!finish_cleanup) {
                Sleep(1);
            }
        });
        struct Finish {
            std::atomic_bool& flag;
            ~Finish() { flag = true; }
        } finish{finish_cleanup};
        const auto initial = controller.command(RoutingCommand::Status, 0);
        require(initial.phase == RoutingPhase::Idle, "Initial state");
        const auto first = controller.command(RoutingCommand::Start, initial.generation);
        require(first.generation == initial.generation + 1, "Generation not advanced");
        awaitPhase(controller, RoutingPhase::Active);
        require(controller.command(RoutingCommand::Start, first.generation).result == RoutingResult::Busy,
                "Duplicate start");
        require(controller.command(RoutingCommand::Stop, initial.generation).result == RoutingResult::Stale,
                "Stale stop");
        controller.command(RoutingCommand::Stop, first.generation);
        Sleep(20);
        require(controller.command(RoutingCommand::Status, 0).phase == RoutingPhase::Stopping,
                "Cleanup prematurely reported idle");
        finish_cleanup = true;
        awaitPhase(controller, RoutingPhase::Idle);
        const auto second = controller.command(RoutingCommand::Start, first.generation);
        require(second.generation == first.generation + 1, "Generation reused");
        awaitPhase(controller, RoutingPhase::Active);
        require(controller.command(RoutingCommand::Stop, first.generation).result == RoutingResult::Stale,
                "Old stop affected restart");
        controller.command(RoutingCommand::Stop, second.generation);
        awaitPhase(controller, RoutingPhase::Idle);
        require(starts == 2, "Duplicate runner launched");
        RoutingController failed(
            [](HANDLE, RoutingSignals&) { throw std::runtime_error("Fixture failure"); });
        const auto fresh = failed.command(RoutingCommand::Status, 0);
        require(fresh.generation != second.generation, "New service incarnation reused generation");
        failed.command(RoutingCommand::Start, fresh.generation);
        awaitPhase(failed, RoutingPhase::Failed);
        std::cout
            << "PASS: controller generations, duplicate start, stale stop, cleanup wait and fatal failure\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
