#include "routing_control.hpp"
#include <limits>
#include <bcrypt.h>

namespace skewer::windows {
namespace {
std::string stageDetail(RoutingStage stage) {
    switch (stage) {
    case RoutingStage::Preparing: return "Preparing protected packet path";
    case RoutingStage::Connecting: return "Connecting encrypted tunnel";
    case RoutingStage::Intercepting: return "Activating packet interception";
    case RoutingStage::StartingSession: return "Starting encrypted packet session";
    case RoutingStage::None: return {};
    }
    return {};
}
} // namespace
RoutingController::RoutingController(Runner runner)
    : runner_(std::move(runner)), stop_(CreateEventW(nullptr, TRUE, FALSE, nullptr)) {
    if (!runner_ || !stop_) {
        throw std::invalid_argument("Invalid routing controller");
    }
    // Do not reuse generation 1 after a service restart. This opaque seed is
    // correlation, not authentication; the pipe still authenticates each call.
    if (BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(&generation_), sizeof(generation_),
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) {
        throw std::runtime_error("Cannot initialize routing generation");
    }
    generation_ &= 0x7fffffffffffffffULL;
}
RoutingController::~RoutingController() {
    if (const auto pending = signals_.pause_change.load()) pending->cancel();
    if (const auto pending = signals_.selection_change.load()) pending->cancel();
    SetEvent(stop_.get());
    if (work_.valid()) {
        work_.wait();
    }
}
void RoutingController::reap() {
    if (!work_.valid() || work_.wait_for(std::chrono::seconds(0)) != std::future_status::ready) {
        return;
    }
    terminal_ = stopping_ ? RoutingPhase::Idle : RoutingPhase::Failed;
    try {
        detail_ = work_.get();
        if (detail_.empty() && signals_.completed.load()) terminal_ = RoutingPhase::Idle;
    } catch (...) {
        detail_ = "Routing worker failed with an unknown exception";
        terminal_ = RoutingPhase::Failed;
    }
    if (terminal_ == RoutingPhase::Idle) detail_.clear();
    signals_.ready = false;
    signals_.blocked = false;
    signals_.stage = RoutingStage::None;
    signals_.retry_error.store({});
    signals_.selection_supported = false;
    signals_.pause_supported = false;
    signals_.paused = false;
    if (const auto pending = signals_.pause_change.load()) {
        const auto phase = pending->phase.load();
        if (phase == PauseChange::Phase::Pending || phase == PauseChange::Phase::Applying)
            pending->complete("Routing worker stopped before confirming pause change");
    }
    if (const auto pending = signals_.selection_change.load()) {
        const auto phase = pending->phase.load();
        if (phase == SelectionChange::Phase::Pending || phase == SelectionChange::Phase::Applying) {
            // work_.get() above joined the only consumer; no request can still
            // be executing when its terminal failure is published here.
            pending->complete("Routing worker stopped before confirming selection change");
        }
    }
    stopping_ = false;
}
RoutingReply RoutingController::command(RoutingCommand command, std::uint64_t generation) {
    if (command > RoutingCommand::Stop) {
        throw std::invalid_argument("Unknown routing command");
    }
    reap();
    RoutingResult result = RoutingResult::Ok;
    if (command != RoutingCommand::Status && generation != generation_) {
        result = RoutingResult::Stale;
    } else if (command == RoutingCommand::Start) {
        if (work_.valid()) {
            result = RoutingResult::Busy;
        } else {
            if (generation_ == std::numeric_limits<std::uint64_t>::max() || !ResetEvent(stop_.get())) {
                throw std::runtime_error("Cannot start routing generation");
            }
            signals_.ready = false;
            signals_.completed = false;
            signals_.pause_supported = false;
            signals_.paused = false;
            signals_.pause_change.store({});
            signals_.selection_supported = false;
            signals_.selection_change.store({});
            signals_.selection_snapshot.store({});
            signals_.blocked = false;
            signals_.stage = RoutingStage::None;
            signals_.retry_error.store({});
            detail_.clear();
            work_ = std::async(std::launch::async, [this] {
                try {
                    runner_(stop_.get(), signals_);
                    return std::string{};
                } catch (const std::exception& error) {
                    return std::string(error.what());
                } catch (...) {
                    return std::string("Routing worker failed with an unknown exception");
                }
            });
            ++generation_;
        }
    } else if (command == RoutingCommand::Stop && work_.valid()) {
        if (!SetEvent(stop_.get())) {
            throw std::runtime_error("Cannot stop routing generation");
        }
        if (const auto pending = signals_.selection_change.load()) pending->cancel();
        if (const auto pending = signals_.pause_change.load()) pending->cancel();
        stopping_ = true;
    } else if (command == RoutingCommand::Stop) {
        terminal_ = RoutingPhase::Idle;
        detail_.clear();
    }
    const auto phase = !work_.valid()            ? terminal_
                       : stopping_               ? RoutingPhase::Stopping
                       : signals_.paused.load() || signals_.blocked.load() ? RoutingPhase::Blocked
                       : signals_.ready.load()   ? RoutingPhase::Active
                                                 : RoutingPhase::Starting;
    auto detail = detail_;
    if (detail.empty() && work_.valid()) {
        const auto retry = phase == RoutingPhase::Blocked ? signals_.retry_error.load() : nullptr;
        if (retry) {
            detail = *retry;
        } else if (phase == RoutingPhase::Starting) {
            detail = stageDetail(signals_.stage.load());
        }
    }
    if (work_.valid() && !stopping_ && signals_.paused.load())
        detail = "Routing paused; protected traffic remains blocked";
    RoutingReply reply{result, phase, generation_, RoutingScope::None, RoutingTransport::None,
            std::nullopt, detail, false, false, false};
    if (work_.valid()) {
        reply.pause_available = signals_.pause_supported.load();
        reply.paused = signals_.paused.load();
        if (const auto snapshot = signals_.selection_snapshot.load()) {
            reply.selections = snapshot->roots;
            reply.selection_members = snapshot->members;
        }
    }
    return reply;
}
std::shared_ptr<PauseChange> RoutingController::changePause(bool paused, std::uint64_t generation) {
    const auto state = command(RoutingCommand::Status, 0);
    if (generation != state.generation) throw std::runtime_error("Stale pause generation");
    if (!signals_.pause_supported ||
        (state.phase != RoutingPhase::Active && state.phase != RoutingPhase::Blocked))
        throw std::runtime_error("Routing does not support protected pause in this state");
    if (const auto previous = signals_.pause_change.load()) {
        const auto phase = previous->phase.load();
        if (phase == PauseChange::Phase::Pending || phase == PauseChange::Phase::Applying)
            throw std::runtime_error("Another pause change is still pending");
    }
    auto request = std::make_shared<PauseChange>(paused);
    signals_.pause_change = request;
    return request;
}
std::shared_ptr<SelectionChange> RoutingController::changeSelection(SelectionOperation operation,
                                                                   ProcessKey process,
                                                                   std::uint64_t generation) {
    const auto state = command(RoutingCommand::Status, 0);
    if (generation != state.generation) throw std::runtime_error("Stale selection generation");
    if (!signals_.selection_supported ||
        (state.phase != RoutingPhase::Active && state.phase != RoutingPhase::Blocked)) {
        throw std::runtime_error("Selected routing is not ready for changes");
    }
    if (operation != SelectionOperation::Add && operation != SelectionOperation::Remove) {
        throw std::invalid_argument("Invalid selection operation");
    }
    if (!process.pid || !process.created) throw std::invalid_argument("Invalid selection identity");
    auto previous = signals_.selection_change.load();
    if (previous) {
        const auto phase = previous->phase.load();
        if (phase == SelectionChange::Phase::Pending || phase == SelectionChange::Phase::Applying) {
            throw std::runtime_error("Another selection change is still pending");
        }
    }
    auto request = std::make_shared<SelectionChange>(operation, process);
    signals_.selection_change = request;
    return request;
}
} // namespace skewer::windows
