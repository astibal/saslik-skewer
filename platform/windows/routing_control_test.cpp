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
        {
            std::atomic_uint generations{};
            std::atomic_bool parked{}, release{};
            RoutingController finished([&](HANDLE, RoutingSignals& signals) {
                if (++generations != 1) return; // Unmarked return is still a failure.
                signals.ready = true;
                signals.completed = true;
                parked = true;
                while (!release) Sleep(1);
            });
            struct ReleaseWorker {
                std::atomic_bool& release;
                ~ReleaseWorker() { release = true; }
            } release_worker{release};
            const auto initial = finished.command(RoutingCommand::Status, 0);
            finished.command(RoutingCommand::Start, initial.generation);
            for (unsigned i = 0; i < 200 && !parked; ++i) Sleep(5);
            require(parked && finished.command(RoutingCommand::Status, 0).phase == RoutingPhase::Active,
                    "Completion intent published Idle before the worker joined");
            release = true;
            const auto idle = awaitPhase(finished, RoutingPhase::Idle);
            require(idle.detail.empty(),
                    "Normal selected-group completion was reported as failure");
            finished.command(RoutingCommand::Start, idle.generation);
            require(awaitPhase(finished, RoutingPhase::Failed).generation == idle.generation + 1,
                    "Previous completion hid an unexpected return in the next generation");
            RoutingController failed([](HANDLE, RoutingSignals& signals) {
                signals.completed = true;
                throw std::runtime_error("cleanup failed");
            });
            const auto before = failed.command(RoutingCommand::Status, 0);
            failed.command(RoutingCommand::Start, before.generation);
            require(awaitPhase(failed, RoutingPhase::Failed).detail == "cleanup failed",
                    "Completion hid a worker cleanup error");
        }
        {
            RoutingReply state;
            state.scope = RoutingScope::SelectedProcess;
            state.paused = true;
            for (const auto phase : {RoutingPhase::Idle, RoutingPhase::Starting, RoutingPhase::Active,
                                     RoutingPhase::Stopping, RoutingPhase::Failed}) {
                state.phase = phase;
                require(!state.protectedPause(), "Retained pause hid the authoritative lifecycle phase");
            }
            state.phase = RoutingPhase::Blocked;
            require(state.protectedPause(), "Acknowledged selected pause was not presented");
            state.paused = false;
            require(!state.protectedPause(), "Transport failure was presented as user pause");
            state.paused = true;
            state.scope = RoutingScope::WholeHost;
            require(!state.protectedPause(), "Unsupported whole-host pause was presented");
            state.transport = RoutingTransport::Tunnel;
            state.pause_available = true;
            require(state.protectedPause(), "Supported host tunnel pause was not presented");
            state.transport = RoutingTransport::Direct;
            require(!state.protectedPause(), "Direct routing falsely advertised protected pause");
        }
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
        const auto acknowledged = failed.command(RoutingCommand::Stop, failure.generation);
        require(acknowledged.phase == RoutingPhase::Idle && acknowledged.detail.empty(),
                "Explicit stop did not acknowledge the terminal failure");
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
        std::atomic_bool apply_changes{};
        std::atomic_bool parked{};
        std::atomic_uint changes{};
        RoutingController selections([&](HANDLE stop, RoutingSignals& signals) {
            signals.selection_supported = true;
            signals.selection_snapshot = std::make_shared<const SelectionSnapshot>(
                SelectionSnapshot{{{42, 100}}, {{42, 100}, {43, 101}}});
            signals.ready = true;
            while (WaitForSingleObject(stop, 1) == WAIT_TIMEOUT) {
                if (!apply_changes) { parked = true; continue; }
                parked = false;
                const auto change = signals.selection_change.load();
                if (change && change->claim()) {
                    ++changes;
                    change->complete();
                }
            }
        });
        const auto selection_initial = selections.command(RoutingCommand::Status, 0);
        const auto selection_started = selections.command(RoutingCommand::Start, selection_initial.generation);
        const auto selected_state = awaitPhase(selections, RoutingPhase::Active);
        require(selected_state.selections == std::vector<ProcessKey>{{42, 100}} &&
                    selected_state.selection_members == std::vector<ProcessKey>{{42, 100}, {43, 101}},
                "Controller lost authoritative root/member snapshot");
        auto cancelled = selections.changeSelection(SelectionOperation::Add, {42, 100}, selection_started.generation);
        require(cancelled->cancel(), "Pending selection could not be cancelled");
        auto pending = selections.changeSelection(SelectionOperation::Add, {43, 101}, selection_started.generation);
        bool busy{};
        try {
            selections.changeSelection(SelectionOperation::Remove, {43, 101}, selection_started.generation);
        } catch (const std::runtime_error&) { busy = true; }
        require(busy, "In-flight selection was overwritten");
        apply_changes = true;
        for (unsigned i = 0; i < 200 && pending->phase != SelectionChange::Phase::Complete; ++i) Sleep(5);
        require(pending->phase == SelectionChange::Phase::Complete && pending->error.empty() && changes == 1,
                "Selection completion or cancellation was not honored");
        require(!pending->cancel(), "Completed selection reported cancellation");
        bool stale{};
        try {
            selections.changeSelection(SelectionOperation::Remove, {43, 101}, selection_initial.generation);
        } catch (const std::runtime_error&) { stale = true; }
        require(stale, "Stale generation changed selection");
        apply_changes = false;
        for (unsigned i = 0; i < 200 && !parked; ++i) Sleep(5);
        require(parked, "Selection worker did not reach test barrier");
        auto stopped = selections.changeSelection(SelectionOperation::Remove, {43, 101}, selection_started.generation);
        selections.command(RoutingCommand::Stop, selection_started.generation);
        const auto idle_state = awaitPhase(selections, RoutingPhase::Idle);
        require(idle_state.selections.empty() && idle_state.selection_members.empty(),
                "Stopped controller exposed stale Job membership");
        require(stopped->phase == SelectionChange::Phase::Cancelled,
                "Stopped worker left a selection pending forever");
        std::atomic_bool apply_pause{};
        RoutingController pauses([&](HANDLE stop, RoutingSignals& signals) {
            signals.pause_supported = true;
            signals.ready = true;
            while (WaitForSingleObject(stop, 1) == WAIT_TIMEOUT) {
                if (!apply_pause) continue;
                const auto request = signals.pause_change.load();
                if (!request || !request->claim()) continue;
                signals.paused = request->paused;
                request->complete();
            }
        });
        const auto pauseInitial = pauses.command(RoutingCommand::Status, 0);
        const auto pauseStarted = pauses.command(RoutingCommand::Start, pauseInitial.generation);
        awaitPhase(pauses, RoutingPhase::Active);
        auto pauseRequest = pauses.changePause(true, pauseStarted.generation);
        require(pauses.command(RoutingCommand::Status, 0).phase == RoutingPhase::Active,
                "Unacknowledged pause claimed protection");
        bool pauseBusy{};
        try { pauses.changePause(false, pauseStarted.generation); }
        catch (const std::runtime_error&) { pauseBusy = true; }
        require(pauseBusy, "Pending pause was overwritten");
        apply_pause = true;
        awaitPhase(pauses, RoutingPhase::Blocked);
        for (unsigned i = 0; i < 200 && pauseRequest->phase != PauseChange::Phase::Complete; ++i) Sleep(5);
        require(pauseRequest->phase == PauseChange::Phase::Complete && !pauseRequest->cancel(),
                "Applied pause did not complete exactly once");
        bool pauseStale{};
        try { pauses.changePause(false, pauseInitial.generation); }
        catch (const std::runtime_error&) { pauseStale = true; }
        require(pauseStale, "Stale generation resumed routing");
        auto resumeRequest = pauses.changePause(false, pauseStarted.generation);
        awaitPhase(pauses, RoutingPhase::Active);
        for (unsigned i = 0; i < 200 && resumeRequest->phase != PauseChange::Phase::Complete; ++i) Sleep(5);
        require(resumeRequest->phase == PauseChange::Phase::Complete, "Resume was not acknowledged");
        pauses.command(RoutingCommand::Stop, pauseStarted.generation);
        awaitPhase(pauses, RoutingPhase::Idle);
        bool idlePause{};
        try { pauses.changePause(true, pauseStarted.generation); }
        catch (const std::runtime_error&) { idlePause = true; }
        require(idlePause, "Idle routing accepted protected pause");
        RoutingController cancelledPause([](HANDLE stop, RoutingSignals& signals) {
            signals.pause_supported = true;
            signals.ready = true;
            WaitForSingleObject(stop, INFINITE); // Deliberately never claim the request.
        });
        const auto cancelledInitial = cancelledPause.command(RoutingCommand::Status, 0);
        const auto cancelledStarted = cancelledPause.command(RoutingCommand::Start, cancelledInitial.generation);
        awaitPhase(cancelledPause, RoutingPhase::Active);
        auto abandoned = cancelledPause.changePause(true, cancelledStarted.generation);
        cancelledPause.command(RoutingCommand::Stop, cancelledStarted.generation);
        awaitPhase(cancelledPause, RoutingPhase::Idle);
        require(abandoned->phase == PauseChange::Phase::Cancelled && !abandoned->claim(),
                "Stopped generation left a claimable pause request");
        RoutingController failedPause([](HANDLE stop, RoutingSignals& signals) {
            signals.pause_supported = true;
            signals.ready = true;
            while (WaitForSingleObject(stop, 1) == WAIT_TIMEOUT) {
                const auto request = signals.pause_change.load();
                if (request && request->claim()) throw std::runtime_error("Injected pause worker failure");
            }
        });
        const auto failedInitial = failedPause.command(RoutingCommand::Status, 0);
        const auto failedStarted = failedPause.command(RoutingCommand::Start, failedInitial.generation);
        awaitPhase(failedPause, RoutingPhase::Active);
        auto interrupted = failedPause.changePause(true, failedStarted.generation);
        const auto pauseFailure = awaitPhase(failedPause, RoutingPhase::Failed);
        require(interrupted->phase == PauseChange::Phase::Complete && !interrupted->error.empty(),
                "Worker failure stranded an applying pause request");
        require(!pauseFailure.paused && !pauseFailure.pause_available,
                "Failed worker still claimed protected pause");
        std::cout
            << "PASS: controller generations, cleanup, failure and retry diagnostics\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
