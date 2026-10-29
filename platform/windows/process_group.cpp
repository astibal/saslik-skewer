#include "process_group.hpp"
#include <tlhelp32.h>
#include <algorithm>
#include <stdexcept>
#include <unordered_map>

namespace skewer::windows {
namespace {
[[noreturn]] void fail(const char* operation) {
    throw std::runtime_error(std::string(operation) + ": Win32 error " + std::to_string(GetLastError()));
}

HANDLE openAssignable(ProcessKey expected) {
    const auto process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SET_QUOTA |
                                         PROCESS_TERMINATE | SYNCHRONIZE,
                                     FALSE, expected.pid);
    if (!process) fail("Open process for job assignment");
    if (processKey(process, expected.pid) != expected) {
        CloseHandle(process);
        throw std::runtime_error("Process identity changed before job assignment");
    }
    return process;
}
} // namespace

ProcessGroup::ProcessGroup(const ProcessTarget& root, const ServiceOwner& owner)
    : owner_(owner), root_(root.key()), job_(CreateJobObjectW(nullptr, nullptr)),
      completion_(CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, 0, 1)) {
    if (!root.running()) throw std::runtime_error("Cannot group an exited process");
    if (!job_) fail("Create process job");
    if (!completion_) fail("Create process job completion port");

    JOBOBJECT_ASSOCIATE_COMPLETION_PORT association{this, completion_.get()};
    if (!SetInformationJobObject(job_.get(), JobObjectAssociateCompletionPortInformation,
                                 &association, sizeof(association))) {
        fail("Associate process job completion port");
    }
    Handle process(openAssignable(root_));
    if (!AssignProcessToJobObject(job_.get(), process.get())) {
        fail("Assign selected process to routing job");
    }
    if (!root.running()) throw std::runtime_error("Selected process exited during job assignment");
    // Existing children do not retroactively inherit a newly assigned Job.
    // Repeat until one complete snapshot adds nothing. New children of already
    // adopted members inherit automatically; unbounded churn fails closed.
    for (unsigned pass = 0; pass < 8; ++pass) {
        if (!adoptExistingDescendants()) return;
    }
    throw std::runtime_error("Selected process tree kept changing during routing setup");
}

std::size_t ProcessGroup::adoptExistingDescendants() {
    struct Node {
        ProcessKey key;
        DWORD parent{};
    };
    Handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (!snapshot) fail("Snapshot selected process tree");
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (!Process32FirstW(snapshot.get(), &entry)) fail("Read selected process tree");

    std::unordered_map<DWORD, Node> nodes;
    do {
        Handle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE,
                                   entry.th32ProcessID));
        if (!process) continue;
        try {
            const auto key = processKey(process.get(), entry.th32ProcessID);
            [[maybe_unused]] ProcessTarget authorized(key, owner_);
            nodes.emplace(key.pid, Node{key, entry.th32ParentProcessID});
        } catch (const std::runtime_error&) {
            // Exited, inaccessible and foreign-owner entries cannot be adopted.
        }
    } while (Process32NextW(snapshot.get(), &entry));
    if (GetLastError() != ERROR_NO_MORE_FILES) fail("Finish selected process tree snapshot");
    nodes.insert_or_assign(root_.pid, Node{root_, 0});

    std::vector<Node> descendants;
    for (const auto& [pid, candidate] : nodes) {
        if (pid == root_.pid || contains(pid)) continue;
        auto current = candidate;
        std::size_t depth{};
        while (current.parent && depth++ <= nodes.size()) {
            if (current.parent == root_.pid) {
                if (root_.created <= current.key.created) descendants.push_back(candidate);
                break;
            }
            const auto parent = nodes.find(current.parent);
            if (parent == nodes.end() || parent->second.key.created > current.key.created ||
                parent->second.key.pid == current.key.pid) {
                break;
            }
            current = parent->second;
        }
    }
    std::ranges::sort(descendants, {}, [](const Node& node) {
        return std::pair{node.key.created, node.key.pid};
    });

    std::size_t adopted{};
    for (const auto& descendant : descendants) {
        if (contains(descendant.key.pid)) continue;
        try {
            [[maybe_unused]] ProcessTarget authorized(descendant.key, owner_);
            Handle process(openAssignable(descendant.key));
            if (!AssignProcessToJobObject(job_.get(), process.get())) {
                fail("Assign existing descendant to routing job");
            }
            ++adopted;
        } catch (const std::runtime_error&) {
            // Exit between snapshot and assignment is harmless. A still-live
            // descendant that cannot be assigned makes partial routing unsafe.
            bool live{};
            try {
                ProcessTarget still_live(descendant.key, owner_);
                live = still_live.running();
            } catch (const std::runtime_error&) {
            }
            if (live) throw;
        }
    }
    return adopted;
}

bool ProcessGroup::contains(DWORD pid) const {
    if (!pid) return false;
    Handle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
    if (!process) return false;
    BOOL member{};
    if (!IsProcessInJob(process.get(), job_.get(), &member)) fail("Query process job membership");
    return member != FALSE;
}

bool ProcessGroup::running() const {
    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION accounting{};
    if (!QueryInformationJobObject(job_.get(), JobObjectBasicAccountingInformation,
                                   &accounting, sizeof(accounting), nullptr)) {
        fail("Query process job accounting");
    }
    return accounting.ActiveProcesses != 0;
}

std::unique_ptr<ProcessTarget> ProcessGroup::member(DWORD pid) const {
    if (!pid) return {};
    Handle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, pid));
    if (!process) return {};
    BOOL member{};
    if (!IsProcessInJob(process.get(), job_.get(), &member)) fail("Query process job membership");
    if (!member) return {};
    const auto identity = processKey(process.get(), pid);
    try {
        return std::make_unique<ProcessTarget>(identity, owner_);
    } catch (const std::runtime_error&) {
        // The PID may have exited/recycled between the membership query and
        // reopening. The expected creation time prevents adopting its reuse.
        return {};
    }
}

std::unique_ptr<ProcessTarget> ProcessGroup::next(DWORD timeout_ms) {
    for (;;) {
        DWORD message{};
        ULONG_PTR key{};
        LPOVERLAPPED value{};
        if (!GetQueuedCompletionStatus(completion_.get(), &message,
                                       &key, &value, timeout_ms)) {
            const auto error = GetLastError();
            if (error == WAIT_TIMEOUT) return {};
            fail("Read process job notification");
        }
        if (key != reinterpret_cast<ULONG_PTR>(this)) {
            throw std::runtime_error("Unexpected process job completion key");
        }
        if (message != JOB_OBJECT_MSG_NEW_PROCESS) {
            timeout_ms = 0;
            continue;
        }
        const auto pid = static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(value));
        try {
            Handle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, pid));
            if (!process) continue;
            return std::make_unique<ProcessTarget>(processKey(process.get(), pid), owner_);
        } catch (const std::runtime_error&) {
            // A short-lived, inaccessible or foreign-token child cannot become
            // an authorized target. Its traffic must remain fail-closed.
            timeout_ms = 0;
        }
    }
}

void ProcessSelection::add(ProcessKey root) {
    // Revalidate ownership and creation time before assigning any process.
    ProcessTarget authorized(root, owner_);
    if (!authorized.running()) throw std::runtime_error("Cannot select an exited application");
    if (std::ranges::any_of(groups_, [&](const auto& group) { return group->root() == root; })) return;
    if (contains(root.pid)) {
        throw std::runtime_error("Application is already covered by a selected tree");
    }
    auto candidate = std::make_unique<ProcessGroup>(authorized, owner_);
    // Reject overlapping trees instead of giving Release ambiguous semantics.
    // Job assignment alone changes no packet policy and never kills on close.
    for (const auto& group : groups_) {
        const auto overlapping = candidate->member(group->root().pid);
        if (overlapping && overlapping->key() == group->root()) {
            throw std::runtime_error("Application contains an already selected tree");
        }
    }
    groups_.push_back(std::move(candidate));
}

bool ProcessSelection::remove(ProcessKey root) {
    return std::erase_if(groups_, [&](const auto& group) { return group->root() == root; }) != 0;
}

bool ProcessSelection::running() const {
    return std::ranges::any_of(groups_, [](const auto& group) { return group->running(); });
}

bool ProcessSelection::contains(DWORD pid) const {
    return std::ranges::any_of(groups_, [&](const auto& group) { return group->contains(pid); });
}

std::unique_ptr<ProcessTarget> ProcessSelection::member(DWORD pid) const {
    for (const auto& group : groups_) {
        if (auto process = group->member(pid)) return process;
    }
    return {};
}

std::unique_ptr<ProcessTarget> ProcessSelection::next() {
    // Round-robin avoids starving another application during a fork burst.
    for (std::size_t checked = 0; checked < groups_.size(); ++checked) {
        cursor_ %= groups_.size();
        auto& group = groups_[cursor_++];
        if (auto process = group->next()) return process;
    }
    return {};
}

std::vector<ProcessKey> ProcessSelection::roots() const {
    std::vector<ProcessKey> result;
    result.reserve(groups_.size());
    for (const auto& group : groups_) result.push_back(group->root());
    return result;
}

bool ProcessSelection::isRoot(ProcessKey process) const {
    return std::ranges::any_of(groups_, [&](const auto& group) { return group->root() == process; });
}

} // namespace skewer::windows
