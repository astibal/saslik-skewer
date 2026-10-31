#pragma once
#include <chrono>
#include <cstdint>
#include <limits>
#include <map>
#include <optional>
#include <span>
#include <stdexcept>
#include <type_traits>
#include <vector>

namespace skewer::traffic {

// Single-consumer holding buffer, not an ownership oracle or routing policy.
// Unknown ownership must stay here or be discarded, never implicitly forwarded.
// Context is fixed-size capture metadata, with no pointers to borrowed storage.
template <typename Context> class PendingPackets final {
    static_assert(std::is_trivially_copyable_v<Context>);

public:
    using Clock = std::chrono::steady_clock;
    using Time = Clock::time_point;
    using Ticket = std::uint64_t;
    struct Packet {
        std::vector<std::uint8_t> bytes;
        Context context;
    };

    // Byte budget covers retained payload + sizeof(Context); count bounds map
    // and allocator overhead separately. Neither limit is an OS memory quota.
    PendingPackets(std::size_t count, std::size_t bytes, Clock::duration lifetime)
        : count_limit_(count), byte_limit_(bytes), lifetime_(lifetime) {
        if (!count || bytes <= sizeof(Context) || lifetime <= Clock::duration::zero()) {
            throw std::invalid_argument("Invalid pending packet limits");
        }
    }
    PendingPackets(const PendingPackets&) = delete;
    PendingPackets& operator=(const PendingPackets&) = delete;

    std::optional<Ticket> hold(std::span<const std::uint8_t> bytes, Context context, Time now) {
        expire(now);
        if (stopped_ || !next_ || bytes.empty() || records_.size() >= count_limit_ ||
            bytes.size() > byte_limit_ - sizeof(Context)) {
            return std::nullopt;
        }
        const auto charge = bytes.size() + sizeof(Context);
        if (charge > byte_limit_ - used_) {
            return std::nullopt;
        }
        const auto deadline = now > Time::max() - lifetime_ ? Time::max() : now + lifetime_;
        const auto ticket = next_;
        // Construct before updating accounting; allocation failure leaves the
        // retained packets and their tickets intact.
        records_.emplace(ticket, Record{{{bytes.begin(), bytes.end()}, context}, deadline});
        used_ += charge;
        next_ = ticket == std::numeric_limits<Ticket>::max() ? 0 : ticket + 1;
        return ticket;
    }

    // Explicit ownership transfer only. The caller must independently validate
    // process identity, ambiguity and tunnel readiness before selecting a route.
    // Expired, discarded and previously consumed tickets cannot be resurrected.
    std::optional<Packet> take(Ticket ticket, Time now) {
        expire(now);
        const auto found = records_.find(ticket);
        if (found == records_.end()) {
            return std::nullopt;
        }
        used_ -= charge(found->second);
        auto packet = std::move(found->second.packet);
        records_.erase(found);
        return packet;
    }

    bool discard(Ticket ticket) {
        const auto found = records_.find(ticket);
        if (found == records_.end()) {
            return false;
        }
        used_ -= charge(found->second);
        records_.erase(found);
        return true;
    }

    // Copy metadata only; never expose a borrowed reference into the queue.
    std::optional<Context> context(Ticket ticket, Time now) {
        expire(now);
        const auto found = records_.find(ticket);
        if (found == records_.end()) {
            return std::nullopt;
        }
        return found->second.packet.context;
    }

    std::size_t expire(Time now) {
        if (last_ && now < *last_) {
            throw std::invalid_argument("Pending packet clock moved backwards");
        }
        last_ = now;
        std::size_t removed{};
        // Tickets and deadlines are monotonically ordered. A fixed lifetime
        // makes it sufficient to remove only the expired prefix.
        while (!records_.empty() && records_.begin()->second.deadline <= now) {
            used_ -= charge(records_.begin()->second);
            records_.erase(records_.begin());
            ++removed;
        }
        return removed;
    }

    // Observer loss/service shutdown drops pending work, never drains it onto
    // the network. A replacement observation epoch needs a new queue object.
    void stop() {
        stopped_ = true;
        records_.clear();
        used_ = 0;
    }
    std::size_t size() const { return records_.size(); }
    std::size_t bytes() const { return used_; }

private:
    struct Record {
        Packet packet;
        Time deadline;
    };
    static std::size_t charge(const Record& record) { return record.packet.bytes.size() + sizeof(Context); }
    const std::size_t count_limit_, byte_limit_;
    const Clock::duration lifetime_;
    std::map<Ticket, Record> records_;
    std::optional<Time> last_;
    Ticket next_{1};
    std::size_t used_{};
    bool stopped_{};
};
} // namespace skewer::traffic
