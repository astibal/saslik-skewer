#include "process_group.hpp"
#include <stdexcept>

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
}

bool ProcessGroup::contains(DWORD pid) const {
    if (!pid) return false;
    Handle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
    if (!process) return false;
    BOOL member{};
    if (!IsProcessInJob(process.get(), job_.get(), &member)) fail("Query process job membership");
    return member != FALSE;
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

} // namespace skewer::windows
