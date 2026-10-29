#include <winsock2.h>
#include "selected_group_resolver.hpp"
#include <algorithm>
#include <chrono>

namespace skewer::windows::traffic {
namespace {
const ProcessTarget& checkedRoot(const std::unique_ptr<ProcessTarget>& root) {
    if (!root) throw std::invalid_argument("Selected process group requires a root target");
    return *root;
}
} // namespace
SelectedGroupResolver::SelectedGroupResolver(const std::wstring& dll,
                                             std::unique_ptr<ProcessTarget> root,
                                             const ServiceOwner& owner, TargetAdded added)
    : dll_(dll), added_(std::move(added)), group_(checkedRoot(root), owner) {
    enroll(std::move(root));
}

bool SelectedGroupResolver::contains(skewer::traffic::ProcessIdentity process) const {
    return std::ranges::any_of(members_, [&](const auto& member) {
        return member.process.pid == process.pid && member.process.created == process.created &&
               member.resolver->running();
    });
}

std::vector<ProcessKey> SelectedGroupResolver::memberKeys() {
    refresh();
    std::vector<ProcessKey> result;
    result.reserve(members_.size());
    for (const auto& member : members_) result.push_back(member.process);
    return result;
}

void SelectedGroupResolver::enroll(std::unique_ptr<ProcessTarget> target) {
    if (!target || !target->running()) return;
    const auto identity = target->key();
    if (std::ranges::any_of(members_, [&](const auto& member) { return member.process == identity; })) return;
    if (added_) added_(*target); // Install fail-closed guards before observing this member.
    members_.push_back({identity, std::make_unique<SelectedOwnerResolver>(dll_, std::move(target))});
}

void SelectedGroupResolver::refresh() {
    while (auto target = group_.next()) enroll(std::move(target));
    std::erase_if(members_, [](const auto& member) { return !member.resolver->running(); });
}

SelectedGroupResolver::Candidates
SelectedGroupResolver::ownerCandidates(skewer::traffic::PacketTuple tuple) const {
    using Clock = TcpOwnerSnapshot::Clock;
    const auto valid = [](auto started, auto completed) {
        const auto now = Clock::now();
        return completed >= started && now >= completed &&
               now - started < std::chrono::milliseconds(250);
    };
    if (tuple.protocol == IPPROTO_TCP) {
        const auto snapshot = captureTcpOwners();
        auto candidates = tcpOwnerCandidates(snapshot.rows, tuple);
        return {candidates, false, valid(snapshot.started, snapshot.completed), candidates.size()};
    }
    if (tuple.protocol == IPPROTO_UDP) {
        const auto snapshot = captureUdpOwners();
        auto candidates = udpOwnerCandidates(snapshot.rows, tuple);
        return {std::move(candidates.pids), candidates.unknown_owner,
                valid(snapshot.started, snapshot.completed), candidates.matching_rows};
    }
    return {{}, true, false, 0};
}

skewer::traffic::FlowIdentity
SelectedGroupResolver::groupFlow(ProcessKey process, skewer::traffic::PacketTuple tuple) const {
    // A Job Object member plus a fresh unique TCP owner row is stronger than a
    // PID lookup alone, but WinDivert may have emitted CONNECT before the child
    // observer existed. Derive a stable non-zero epoch-local socket identity;
    // the complete tuple remains part of TunnelFlows' key.
    std::uint64_t endpoint = 1469598103934665603ULL;
    const auto mix = [&](std::uint64_t value) {
        for (unsigned byte = 0; byte < 8; ++byte) {
            endpoint ^= static_cast<std::uint8_t>(value >> (byte * 8));
            endpoint *= 1099511628211ULL;
        }
    };
    mix(process.pid);
    mix(process.created);
    mix(tuple.protocol);
    mix(tuple.source_port);
    mix(tuple.destination_port);
    for (const auto byte : tuple.source) mix(byte);
    for (const auto byte : tuple.destination) mix(byte);
    if (!endpoint) endpoint = 1;
    return {{process.pid, process.created}, endpoint};
}

SelectedOwnerResolver::Result SelectedGroupResolver::resolve(skewer::traffic::PacketTuple tuple,
                                                              HANDLE cancel) {
    using Disposition = SelectedOwnerResolver::Disposition;
    refresh();
    const auto evidence = ownerCandidates(tuple);
    const auto& candidates = evidence.pids;
    const auto unknown = evidence.unknown;
    bool group_candidate{};
    for (const auto pid : candidates) {
        if (std::ranges::any_of(members_, [&](const auto& member) { return member.process.pid == pid; })) {
            group_candidate = true;
            continue;
        }
        if (group_.contains(pid)) {
            group_candidate = true;
            if (auto target = group_.member(pid)) enroll(std::move(target));
        }
    }
    // The selected tunnel currently carries IPv4 only. IPv6 from a positively
    // excluded owner may continue directly; group/ambiguous IPv6 remains held.
    if (tuple.ipv6) {
        return {skewer::traffic::OwnerEvidence::MissingLifecycle, std::nullopt,
                evidence.fresh && !unknown && !candidates.empty() && !group_candidate
                    ? Disposition::Direct
                    : Disposition::Hold};
    }

    // Newly inherited children can create CONNECT before the service
    // consumes JOB_OBJECT_MSG_NEW_PROCESS. Capture already holds their SYN.
    // A fresh, single owner row plus retained Job membership safely bridges
    // that observation gap. UDP requires exactly one matching bind row, not
    // merely one distinct PID, so same-process shared binds remain held.
    const bool unique_group_socket = evidence.fresh && !unknown && candidates.size() == 1 &&
                                     evidence.rows == 1;
    if ((tuple.protocol == IPPROTO_TCP || tuple.protocol == IPPROTO_UDP) && unique_group_socket) {
        const auto found = std::ranges::find_if(members_,
            [&](const auto& member) { return member.process.pid == candidates.front(); });
        if (found != members_.end() && found->process != group_.root()) {
            const auto flow = groupFlow(found->process, tuple);
            return {skewer::traffic::OwnerEvidence::GroupCorroborated, flow,
                    Disposition::Tunnel};
        }
    }

    std::optional<SelectedOwnerResolver::Result> held;
    bool all_direct = !members_.empty();
    for (auto& member : members_) {
        const auto result = member.resolver->resolve(tuple, cancel);
        if (result.disposition == Disposition::Tunnel) return result;
        if (result.disposition == Disposition::Hold && !held) held = result;
        all_direct &= result.disposition == Disposition::Direct;
    }
    if (held || group_candidate || unknown || candidates.empty() || !evidence.fresh) {
        return held.value_or(SelectedOwnerResolver::Result{});
    }
    return {skewer::traffic::OwnerEvidence::MissingLifecycle, std::nullopt,
            all_direct ? Disposition::Direct : Disposition::Hold};
}

} // namespace skewer::windows::traffic
