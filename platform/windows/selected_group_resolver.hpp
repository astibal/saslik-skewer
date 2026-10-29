#pragma once

#include "process_group.hpp"
#include "selected_owner_resolver.hpp"
#include <functional>

namespace skewer::windows::traffic {

// Extends the conservative single-process resolver to descendants inherited
// through a Windows Job Object. Unknown or not-yet-observed members are held;
// only positive exclusion of the complete group permits direct reinjection.
class SelectedGroupResolver final {
public:
    using TargetAdded = std::function<void(const ProcessTarget&)>;

    SelectedGroupResolver(const std::wstring& dll, std::unique_ptr<ProcessTarget> root,
                          const ServiceOwner& owner, TargetAdded added = {});
    SelectedOwnerResolver::Result resolve(skewer::traffic::PacketTuple tuple, HANDLE cancel);
    bool running() const { return group_.running(); }
    bool contains(skewer::traffic::ProcessIdentity process) const;
    // Drains initial Job Object membership before activation. Retained process
    // handles keep every returned PID bound to its creation-time identity.
    std::vector<ProcessKey> memberKeys();
    // Packet-thread only. The caller installs guards through TargetAdded and
    // resets existing TCP sockets before acknowledging a newly added tree.
    void add(std::unique_ptr<ProcessTarget> root);
    // Returns identities whose guards must be retired by the caller. Existing
    // tunnel flow callbacks reject these identities immediately after removal.
    std::vector<ProcessKey> remove(ProcessKey root);
    std::size_t size() const { return members_.size(); }

private:
    struct Candidates {
        std::vector<std::uint32_t> pids;
        bool unknown{};
        bool fresh{};
        std::size_t rows{};
    };
    struct Member {
        ProcessKey process;
        std::unique_ptr<SelectedOwnerResolver> resolver;
    };

    void refresh();
    void enroll(std::unique_ptr<ProcessTarget> target);
    Candidates ownerCandidates(skewer::traffic::PacketTuple tuple) const;
    skewer::traffic::FlowIdentity groupFlow(ProcessKey process,
                                            skewer::traffic::PacketTuple tuple) const;

    std::wstring dll_;
    TargetAdded added_;
    ProcessSelection group_;
    std::vector<Member> members_;
};

} // namespace skewer::windows::traffic
