#include "selected_group_resolver.hpp"
#include <iostream>

using namespace skewer::windows;
namespace {
void require(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
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

// Explicit elevated VM fixture: installs WinDivert socket observers, not routes.
int wmain(int argc, wchar_t** argv) {
    try {
        require(argc == 2, "Usage: selected_group_live WINDIVERT_DLL");
        wchar_t executable[32768]{};
        const auto size = GetModuleFileNameW(nullptr, executable, 32768);
        require(size && size < 32768, "Cannot locate fixture executable");
        // Both children remain suspended, so they neither recurse nor perform IO.
        Child first{launch(executable, {}, LaunchMode::Suspended)};
        Child second{launch(executable, {}, LaunchMode::Suspended)};
        HANDLE raw{};
        require(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw), "Cannot open owner token");
        Handle token(raw);
        const auto owner = ServiceOwner::fromToken(token.get());
        unsigned additions{};
        traffic::SelectedGroupResolver resolver(argv[1], std::make_unique<ProcessTarget>(first.key(), owner),
                                                owner, [&](const ProcessTarget&) { ++additions; });
        resolver.add(std::make_unique<ProcessTarget>(second.key(), owner));
        resolver.add(std::make_unique<ProcessTarget>(second.key(), owner));
        const auto selected = [&](ProcessKey key) { return resolver.contains({key.pid, key.created}); };
        require(additions == 2 && resolver.size() == 2, "Duplicate enrollment or missing application");
        require(selected(first.key()) && selected(second.key()), "Both applications must be selected");
        auto stale = first.key();
        ++stale.created;
        require(resolver.remove(stale).empty() && selected(first.key()), "Stale Release changed selection");
        const auto removed = resolver.remove(first.key());
        require(removed.size() == 1 && removed.front() == first.key(), "Wrong guard retirement identities");
        require(!selected(first.key()) && selected(second.key()) && resolver.running(),
                "Release invalidated the wrong application's live-flow membership");
        require(WaitForSingleObject(first.process.hProcess, 0) == WAIT_TIMEOUT, "Release killed application");
        require(resolver.remove(second.key()).size() == 1 && !resolver.running() && resolver.size() == 0,
                "Final Release left live membership");
        std::cout << "PASS: independent resolver enrollment, stale Release and per-tree flow retirement\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL: " << error.what() << '\n';
        return 1;
    }
}
