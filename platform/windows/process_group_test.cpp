#include "process_group.hpp"
#include <iostream>

using namespace skewer::windows;
namespace {
void require(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}
struct Child {
    PROCESS_INFORMATION process{};
    ~Child() {
        if (process.hProcess) {
            TerminateProcess(process.hProcess, 0);
            WaitForSingleObject(process.hProcess, 5000);
            CloseHandle(process.hThread);
            CloseHandle(process.hProcess);
        }
    }
};
std::wstring executable() {
    std::wstring path(32768, L'\0');
    const auto size = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
    require(size && size < path.size(), "Cannot resolve test executable");
    path.resize(size);
    return path;
}
} // namespace

int wmain(int argc, wchar_t** argv) {
    try {
        if (argc == 2 && std::wstring(argv[1]) == L"--try-breakaway") {
            // An explicit breakaway request must not escape our routing job.
            // Keep any unexpectedly created child suspended and owned by RAII
            // so a failed assertion cannot execute unselected application code.
            auto command = L"\"" + executable() + L"\" --leaf";
            STARTUPINFOW startup{};
            startup.cb = sizeof(startup);
            Child child;
            const auto created = CreateProcessW(nullptr, command.data(), nullptr, nullptr,
                FALSE, CREATE_BREAKAWAY_FROM_JOB | CREATE_SUSPENDED, nullptr, nullptr,
                &startup, &child.process);
            const auto error = GetLastError();
            require(!created, "Selected process escaped its job through explicit breakaway");
            require(error == ERROR_ACCESS_DENIED, "Breakaway failed for an unexpected reason");
            return 0;
        }
        if (argc == 4 && std::wstring(argv[1]) == L"--broker") {
            Handle request(OpenEventW(SYNCHRONIZE, FALSE, argv[2]));
            Handle reply(OpenEventW(EVENT_MODIFY_STATE, FALSE, argv[3]));
            require(request && reply, "Cannot open singleton handoff events");
            require(WaitForSingleObject(request.get(), 10000) == WAIT_OBJECT_0,
                    "Singleton broker received no request");
            require(SetEvent(reply.get()), "Cannot acknowledge singleton request");
            Sleep(15000);
            return 0;
        }
        if (argc == 3 && std::wstring(argv[1]) == L"--handoff") {
            Handle request(OpenEventW(EVENT_MODIFY_STATE, FALSE, argv[2]));
            require(request && SetEvent(request.get()), "Cannot send singleton handoff");
            return 0;
        }
        if (argc == 2 && std::wstring(argv[1]) == L"--leaf") {
            Sleep(5000);
            return 0;
        }
        if (argc == 4 && std::wstring(argv[1]) == L"--leaf-wait") {
            Handle ready(OpenEventW(EVENT_MODIFY_STATE, FALSE, argv[2]));
            Handle release(OpenEventW(SYNCHRONIZE, FALSE, argv[3]));
            require(ready && release && SetEvent(ready.get()), "Cannot signal stable leaf readiness");
            require(WaitForSingleObject(release.get(), 15000) == WAIT_OBJECT_0,
                    "Stable leaf was not released by fixture");
            return 0;
        }
        if (argc == 4 && std::wstring(argv[1]) == L"--parent-wait") {
            Child leaf{launch(executable(), {L"--leaf-wait", argv[2], argv[3]})};
            WaitForSingleObject(leaf.process.hProcess, 20000);
            return 0;
        }
        if ((argc == 2 || argc == 3) && std::wstring(argv[1]) == L"--parent") {
            Child leaf{launch(executable(), {L"--leaf"})};
            if (argc == 3) {
                Handle ready(OpenEventW(EVENT_MODIFY_STATE, FALSE, argv[2]));
                require(bool(ready) && SetEvent(ready.get()), "Cannot signal existing child readiness");
            }
            Sleep(20000);
            return 0;
        }
        require(argc == 1, "Unexpected process group test arguments");
        Child parent{launch(executable(), {L"--parent"}, LaunchMode::Suspended)};
        const auto identity = processKey(parent.process.hProcess, parent.process.dwProcessId);
        HANDLE token_raw{};
        require(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token_raw),
                "Cannot open current process token");
        Handle token(token_raw);
        {
            Child probe{launch(executable(), {L"--try-breakaway"}, LaunchMode::Suspended)};
            ProcessTarget target(processKey(probe.process.hProcess, probe.process.dwProcessId));
            ProcessGroup group(target, ServiceOwner::fromToken(token.get()));
            require(ResumeThread(probe.process.hThread) == 1, "Cannot resume breakaway probe");
            require(WaitForSingleObject(probe.process.hProcess, 5000) == WAIT_OBJECT_0,
                    "Breakaway probe timed out");
            DWORD code{};
            require(GetExitCodeProcess(probe.process.hProcess, &code) && code == 0,
                    "Routing job did not reject explicit child breakaway");
            std::cout << "PASS: selected job rejects explicit child breakaway\n";
        }
        {
            // Existing singleton brokers are not descendants of the new
            // launcher. IPC handoff must never grant them a routing badge.
            const auto prefix = L"Local\\SkewerHandoff-" + std::to_wstring(GetCurrentProcessId()) +
                                L"-" + std::to_wstring(GetTickCount64());
            const auto request_name = prefix + L"-request";
            const auto reply_name = prefix + L"-reply";
            Handle request(CreateEventW(nullptr, TRUE, FALSE, request_name.c_str()));
            Handle reply(CreateEventW(nullptr, TRUE, FALSE, reply_name.c_str()));
            require(request && reply, "Cannot create singleton handoff events");
            Child broker{launch(executable(), {L"--broker", request_name, reply_name})};
            Child launcher{launch(executable(), {L"--handoff", request_name}, LaunchMode::Suspended)};
            const auto launcher_key = processKey(launcher.process.hProcess, launcher.process.dwProcessId);
            ProcessSelection selection(ServiceOwner::fromToken(token.get()));
            selection.add(launcher_key);
            require(!selection.contains(broker.process.dwProcessId), "Existing singleton was selected before handoff");
            require(ResumeThread(launcher.process.hThread) == 1, "Cannot resume singleton launcher");
            require(WaitForSingleObject(reply.get(), 5000) == WAIT_OBJECT_0,
                    "Existing singleton did not receive the handoff");
            require(WaitForSingleObject(launcher.process.hProcess, 5000) == WAIT_OBJECT_0,
                    "Singleton launcher did not exit");
            DWORD code{};
            require(GetExitCodeProcess(launcher.process.hProcess, &code) && code == 0,
                    "Singleton launcher failed");
            require(!selection.contains(broker.process.dwProcessId), "IPC handoff silently adopted an existing instance");
            require(WaitForSingleObject(broker.process.hProcess, 0) == WAIT_TIMEOUT,
                    "Existing singleton exited with its launcher");
        }
        {
            Child first{launch(executable(), {L"--parent"}, LaunchMode::Suspended)};
            const auto prefix = L"Local\\SkewerSurvivingChild-" + std::to_wstring(GetCurrentProcessId()) +
                                L"-" + std::to_wstring(GetTickCount64());
            const auto ready_name = prefix + L"-ready", release_name = prefix + L"-release";
            Handle ready(CreateEventW(nullptr, TRUE, FALSE, ready_name.c_str()));
            Handle release(CreateEventW(nullptr, TRUE, FALSE, release_name.c_str()));
            require(ready && release, "Cannot create surviving-child barriers");
            struct ReleaseLeaf {
                HANDLE event;
                ~ReleaseLeaf() { SetEvent(event); }
            } release_leaf{release.get()};
            Child second{launch(executable(), {L"--parent-wait", ready_name, release_name}, LaunchMode::Suspended)};
            const auto first_key = processKey(first.process.hProcess, first.process.dwProcessId);
            const auto second_key = processKey(second.process.hProcess, second.process.dwProcessId);
            ProcessSelection selection(ServiceOwner::fromToken(token.get()));
            selection.add(first_key);
            selection.add(second_key);
            selection.add(first_key);
            require(selection.roots().size() == 2, "Duplicate selection created another tree");
            require(selection.contains(first_key.pid) && selection.contains(second_key.pid),
                    "Independent applications are not both selected");
            auto stale = first_key;
            ++stale.created;
            require(!selection.remove(stale), "Stale identity released a current selection");
            require(selection.remove(first_key), "Cannot release first application");
            require(!selection.contains(first_key.pid) && selection.contains(second_key.pid),
                    "Release affected the wrong application tree");
            require(selection.running(), "Release stopped remaining selection");
            require(WaitForSingleObject(first.process.hProcess, 0) == WAIT_TIMEOUT,
                    "Release terminated the first application");
            require(ResumeThread(second.process.hThread) == 1, "Cannot resume second application");
            bool descendant{};
            std::unique_ptr<ProcessTarget> surviving_child;
            const auto until = GetTickCount64() + 3000;
            while (GetTickCount64() < until && !descendant) {
                if (auto member = selection.next()) {
                    descendant = member->key() != second_key;
                    if (descendant) surviving_child = std::move(member);
                } else {
                    Sleep(10);
                }
            }
            require(descendant, "Remaining tree lost descendant tracking after Release");
            // A Job NEW_PROCESS notification can precede completion of child
            // startup. Do not kill its parent inside CreateProcess, and do not
            // rely on a five-second sleep to keep the child alive under load.
            require(WaitForSingleObject(ready.get(), 5000) == WAIT_OBJECT_0,
                    "Surviving child did not finish startup");
            require(TerminateProcess(second.process.hProcess, 0) &&
                        WaitForSingleObject(second.process.hProcess, 3000) == WAIT_OBJECT_0,
                    "Cannot retire fixture root");
            require(selection.running() && selection.roots() == std::vector<ProcessKey>{second_key} &&
                        selection.contains(surviving_child->key().pid),
                    "Exited root lost its surviving routing group");
            require(selection.remove(second_key) && !selection.running(), "Final Release left selection active");
            require(surviving_child->running(), "Release of exited root killed its surviving child");
            require(SetEvent(release.get()), "Cannot finish surviving child fixture");
        }
        {
            ProcessTarget root(identity);
            ProcessGroup group(root, ServiceOwner::fromToken(token.get()));
            require(group.contains(identity.pid), "Root is not in its routing job");
            require(ResumeThread(parent.process.hThread) == 1, "Cannot resume grouped parent");

            bool saw_root{}, saw_child{};
            const auto deadline = GetTickCount64() + 5000;
            while (GetTickCount64() < deadline && (!saw_root || !saw_child)) {
                if (auto process = group.next(250)) {
                    require(group.contains(process->key().pid), "Notification process is outside routing job");
                    saw_root |= process->key() == identity;
                    saw_child |= process->key() != identity;
                }
            }
            require(saw_root, "Missing root process job notification");
            require(saw_child, "Descendant did not inherit routing job");
        }
        require(WaitForSingleObject(parent.process.hProcess, 0) == WAIT_TIMEOUT,
                "Closing the routing job terminated its application");

        const auto event_name = L"Local\\SkewerExistingTree-" +
                                std::to_wstring(GetCurrentProcessId()) + L"-" +
                                std::to_wstring(GetTickCount64());
        Handle ready(CreateEventW(nullptr, TRUE, FALSE, event_name.c_str()));
        require(bool(ready), "Cannot create existing-child readiness event");
        Child existing{launch(executable(), {L"--parent", event_name})};
        require(WaitForSingleObject(ready.get(), 3000) == WAIT_OBJECT_0,
                "Existing child was not created");
        const auto existing_identity = processKey(existing.process.hProcess, existing.process.dwProcessId);
        {
            ProcessTarget root(existing_identity);
            ProcessGroup group(root, ServiceOwner::fromToken(token.get()));
            bool saw_existing_child{};
            const auto deadline = GetTickCount64() + 3000;
            while (GetTickCount64() < deadline && !saw_existing_child) {
                if (auto process = group.next(250)) {
                    saw_existing_child = process->key() != existing_identity;
                }
            }
            require(saw_existing_child, "Pre-existing descendant was not adopted into routing job");
        }
        require(WaitForSingleObject(existing.process.hProcess, 0) == WAIT_TIMEOUT,
                "Closing adopted routing job terminated its application");
        Sleep(5200); // Let both intentionally unowned leaf fixtures finish.
        std::cout << "PASS: process job inherits new and adopts existing descendants without kill-on-close\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL: " << error.what() << '\n';
        return 1;
    }
}
