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
        const auto failure = awaitPhase(failed, RoutingPhase::Failed);
        require(failure.detail == "Fixture failure", "Fatal worker detail was lost");
        std::atomic_bool recover{};
        RoutingController retrying([&](HANDLE stop, RoutingSignals& signals) {
            signals.stage = RoutingStage::Connecting;
            signals.retry_error = std::make_shared<const std::string>("Fixture retry failure");
            signals.blocked = true;
            while (!recover && WaitForSingleObject(stop, 1) == WAIT_TIMEOUT) {
            }
            if (WaitForSingleObject(stop, 0) == WAIT_OBJECT_0) return;
            signals.retry_error.store({});
            signals.blocked = false;
            signals.ready = true;
            WaitForSingleObject(stop, INFINITE);
            signals.ready = false;
        });
        const auto retry_initial = retrying.command(RoutingCommand::Status, 0);
        retrying.command(RoutingCommand::Start, retry_initial.generation);
        const auto blocked = awaitPhase(retrying, RoutingPhase::Blocked);
        require(blocked.detail == "Fixture retry failure", "Blocked retry detail was lost");
        recover = true;
        const auto recovered = awaitPhase(retrying, RoutingPhase::Active);
        require(recovered.detail.empty(), "Recovered session retained stale retry detail");
        retrying.command(RoutingCommand::Stop, recovered.generation);
        awaitPhase(retrying, RoutingPhase::Idle);
        std::cout
            << "PASS: controller generations, cleanup, failure and retry diagnostics\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
