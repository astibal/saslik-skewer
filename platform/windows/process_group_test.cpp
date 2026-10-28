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
        if (argc == 2 && std::wstring(argv[1]) == L"--leaf") {
            Sleep(5000);
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
