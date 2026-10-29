#include "routing_client.hpp"
#include "routed_launch.hpp"
#include <iostream>

using namespace skewer::windows;
namespace {
void require(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
std::wstring executable() {
    std::wstring path(32768, L'\0');
    const auto size = GetModuleFileNameW(nullptr, path.data(), 32768);
    require(size && size < path.size(), "Cannot locate fixture executable");
    path.resize(size);
    return path;
}
struct Child {
    PROCESS_INFORMATION process;
    ~Child() {
        TerminateProcess(process.hProcess, 0);
        WaitForSingleObject(process.hProcess, 5000);
        CloseHandle(process.hThread);
        CloseHandle(process.hProcess);
    }
    ProcessKey key() const { return processKey(process.hProcess, process.dwProcessId); }
};
}
// Elevated disposable service fixture. Each independent root launches fresh curl
// descendants only when explicitly signalled after authoritative selection.
int wmain(int argc, wchar_t** argv) {
    try {
        if (argc == 6 && std::wstring_view(argv[1]) == L"--child") {
            Handle go(OpenEventW(SYNCHRONIZE, FALSE, argv[2]));
            Handle done(OpenEventW(EVENT_MODIFY_STATE, FALSE, argv[3]));
            require(bool(go) && bool(done), "Cannot open child events");
            wchar_t system[MAX_PATH]{};
            require(GetSystemDirectoryW(system, MAX_PATH) != 0, "Cannot locate curl");
            while (WaitForSingleObject(go.get(), 60000) == WAIT_OBJECT_0) {
                Child curl{launch(std::wstring(system) + L"\\curl.exe",
                    {L"--noproxy", L"*", L"-4", L"-k", L"--fail", L"--silent", L"--show-error",
                     L"--max-time", L"15", L"--resolve", std::wstring(argv[4]) + L":443:" + argv[5],
                     L"--output", L"NUL", L"https://" + std::wstring(argv[4]) + L"/"})};
                require(WaitForSingleObject(curl.process.hProcess, 20000) == WAIT_OBJECT_0, "curl timed out");
                DWORD code{};
                require(GetExitCodeProcess(curl.process.hProcess, &code) && !code, "curl failed");
                require(SetEvent(done.get()), "Cannot signal HTTPS completion");
            }
            return 0;
        }
        require(argc == 4, "Usage: multi_selection_live SERVICE HOST IPV4");
        const std::wstring service(argv[1]);
        Handle cancel(CreateEventW(nullptr, TRUE, FALSE, nullptr));
        const auto status = [&](RoutingCommand operation, std::uint64_t generation) {
            auto pipe = connectRoutingService(service, false, cancel.get(), 3000);
            return exchangeRoutingCommand(pipe->get(), service, operation, generation, cancel.get(), 3000);
        };
        const auto change = [&](SelectionOperation operation, ProcessKey key, std::uint64_t generation) {
            auto pipe = connectRoutingService(service, false, cancel.get(), 3000);
            return exchangeSelectionChange(pipe->get(), service, operation, key, generation, cancel.get(), 30000);
        };
        const auto prefix = L"Local\\SkewerMulti-" + std::to_wstring(GetCurrentProcessId()) + L"-" +
                            std::to_wstring(GetTickCount64());
        const auto first_go = prefix + L"-first-go", first_done = prefix + L"-first-done";
        const auto second_go = prefix + L"-second-go", second_done = prefix + L"-second-done";
        Handle go1(CreateEventW(nullptr, FALSE, FALSE, first_go.c_str()));
        Handle done1(CreateEventW(nullptr, FALSE, FALSE, first_done.c_str()));
        Handle go2(CreateEventW(nullptr, FALSE, FALSE, second_go.c_str()));
        Handle done2(CreateEventW(nullptr, FALSE, FALSE, second_done.c_str()));
        require(bool(go1) && bool(done1) && bool(go2) && bool(done2), "Cannot create fixture events");
        Child first{launch(executable(), {L"--child", first_go, first_done, argv[2], argv[3]}, LaunchMode::Suspended)};
        const auto initial = status(RoutingCommand::Status, 0);
        require(initial.phase == RoutingPhase::Idle || initial.phase == RoutingPhase::Failed, "Service is busy");
        struct Cleanup {
            decltype(status)& command;
            ~Cleanup() { try { const auto s = command(RoutingCommand::Status, 0); command(RoutingCommand::Stop, s.generation); } catch (...) {} }
        } cleanup{status};
        auto pipe = connectRoutingService(service, false, cancel.get(), 3000);
        auto state = exchangeSelectedRouting(pipe->get(), service, first.key(), initial.generation, cancel.get(), 3000);
        pipe.reset();
        const auto generation = state.generation;
        const auto deadline = GetTickCount64() + 30000;
        while (state.phase != RoutingPhase::Active && GetTickCount64() < deadline) {
            Sleep(50);
            state = status(RoutingCommand::Status, 0);
        }
        require(state.phase == RoutingPhase::Active, "First selection did not activate");
        const auto joined = launchRouted(service, executable(),
            {L"--child", second_go, second_done, argv[2], argv[3]}, cancel.get());
        Child second{joined.process};
        state = status(RoutingCommand::Status, 0);
        require(state.result == RoutingResult::Ok && state.generation == generation && state.selections.size() == 2,
                "Second selection replaced or failed to join the active generation");
        require(ResumeThread(first.process.hThread) == 1,
                "Cannot resume selected applications");
        require(SetEvent(go1.get()) && SetEvent(go2.get()), "Cannot trigger HTTPS");
        require(WaitForSingleObject(done1.get(), 20000) == WAIT_OBJECT_0 &&
                WaitForSingleObject(done2.get(), 20000) == WAIT_OBJECT_0, "Both applications did not complete HTTPS");
        state = change(SelectionOperation::Remove, first.key(), generation);
        require(state.result == RoutingResult::Ok && state.selections.size() == 1 && state.selections.front() == second.key(),
                "Release affected the wrong selection");
        require(WaitForSingleObject(first.process.hProcess, 0) == WAIT_TIMEOUT, "Release killed first application");
        require(SetEvent(go2.get()) && WaitForSingleObject(done2.get(), 20000) == WAIT_OBJECT_0,
                "Remaining application's fresh HTTPS failed after Release");
        require(change(SelectionOperation::Remove, second.key(), initial.generation).result == RoutingResult::Stale,
                "Stale Release was accepted");
        state = change(SelectionOperation::Remove, second.key(), generation);
        require(state.result == RoutingResult::Ok && state.selections.empty(), "Final Release retained selections");
        require(WaitForSingleObject(second.process.hProcess, 0) == WAIT_TIMEOUT, "Final Release killed application");
        std::cout << "PASS: two application trees, concurrent HTTPS, independent Release and stale-generation rejection\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL: " << error.what() << '\n';
        return 1;
    }
}
