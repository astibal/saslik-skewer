#include "routed_launch.hpp"
#include <iostream>

using namespace skewer::windows;
namespace {
void require(bool ok, const char* message) {
    if (!ok) {
        throw std::runtime_error(message);
    }
}
} // namespace
// Explicit VM fixture against a newly installed, unpaired service. The child
// signals an event as its first action; a rejected launch must never reach it.
int wmain(int argc, wchar_t** argv) {
    try {
        if (argc == 3 && std::wstring(argv[1]) == L"--signal") {
            Handle event(OpenEventW(EVENT_MODIFY_STATE, FALSE, argv[2]));
            require(bool(event) && SetEvent(event.get()), "Cannot signal child execution");
            return 0;
        }
        require(argc == 2, "Usage: routed_launch_test UNPAIRED_SERVICE");
        wchar_t executable[32768]{};
        const auto length = GetModuleFileNameW(nullptr, executable, 32768);
        require(length && length < 32768, "Cannot resolve fixture executable");
        const auto name = L"Local\\SkewerLaunchTest-" + std::to_wstring(GetCurrentProcessId()) + L"-" +
                          std::to_wstring(GetTickCount64());
        Handle event(CreateEventW(nullptr, TRUE, FALSE, name.c_str()));
        Handle cancel(CreateEventW(nullptr, TRUE, FALSE, nullptr));
        require(bool(event) && bool(cancel), "Cannot create fixture events");
        bool rejected = false;
        try {
            const auto child = launchRouted(argv[1], executable, {L"--signal", name}, cancel.get(), {}, 5000);
            Handle process(child.process.hProcess), thread(child.process.hThread);
            // Own child only, in case a regression incorrectly resumed it.
            TerminateProcess(process.get(), 1);
            WaitForSingleObject(process.get(), 2000);
        } catch (const std::exception&) {
            rejected = true;
        }
        require(rejected, "Unpaired service unexpectedly allowed routed launch");
        require(WaitForSingleObject(event.get(), 100) == WAIT_TIMEOUT,
                "Rejected child executed before routing readiness");

        // Positive control: prove the fixture really signals when allowed to run.
        const auto plain = launch(executable, {L"--signal", name}, LaunchMode::Suspended);
        Handle process(plain.hProcess), thread(plain.hThread);
        struct Cleanup {
            HANDLE process;
            ~Cleanup() {
                if (WaitForSingleObject(process, 0) == WAIT_TIMEOUT) {
                    TerminateProcess(process, 1);
                    WaitForSingleObject(process, 2000);
                }
            }
        } cleanup{process.get()};
        require(WaitForSingleObject(event.get(), 100) == WAIT_TIMEOUT, "Suspended launch executed");
        require(ResumeThread(thread.get()) == 1, "Cannot resume positive control");
        require(WaitForSingleObject(event.get(), 3000) == WAIT_OBJECT_0,
                "Positive control did not signal execution");
        require(WaitForSingleObject(process.get(), 3000) == WAIT_OBJECT_0, "Positive control did not exit");
        std::cout
            << "PASS: rejected routed launch executes no child code; suspended positive control resumes\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL: " << error.what() << '\n';
        return 1;
    }
}
