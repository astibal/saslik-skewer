#include "routing_control.hpp"
#include <limits>
#include <bcrypt.h>

namespace skewer::windows {
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
        work_.get();
    } catch (...) {
        terminal_ = RoutingPhase::Failed;
    }
    signals_.ready = false;
    signals_.blocked = false;
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
            signals_.blocked = false;
            work_ = std::async(std::launch::async, [this] { runner_(stop_.get(), signals_); });
            ++generation_;
        }
    } else if (command == RoutingCommand::Stop && work_.valid()) {
        if (!SetEvent(stop_.get())) {
            throw std::runtime_error("Cannot stop routing generation");
        }
        stopping_ = true;
    }
    const auto phase = !work_.valid()            ? terminal_
                       : stopping_               ? RoutingPhase::Stopping
                       : signals_.blocked.load() ? RoutingPhase::Blocked
                       : signals_.ready.load()   ? RoutingPhase::Active
                                                 : RoutingPhase::Starting;
    return {result, phase, generation_};
}
} // namespace skewer::windows
