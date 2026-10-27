#include "selection_registry.hpp"
#include <iostream>
#include <stdexcept>

using namespace skewer::windows;
namespace {
void require(bool value, const char* message) {
    if (!value) {
        throw std::runtime_error(message);
    }
}
template <typename Function> void rejects(Function action) {
    bool rejected{};
    try {
        action();
    } catch (const std::exception&) {
        rejected = true;
    }
    require(rejected, "Invalid registry operation succeeded");
}

// Only this fixture's own child can be terminated; no PID-based kill helper.
struct Child {
    PROCESS_INFORMATION info;
    ~Child() {
        TerminateProcess(info.hProcess, 0);
        WaitForSingleObject(info.hProcess, 5000);
        CloseHandle(info.hThread);
        CloseHandle(info.hProcess);
    }
};
} // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc == 2 && std::wstring(argv[1]) == L"--child") {
        Sleep(20000);
        return 0;
    }
    try {
        wchar_t path[32768]{};
        const auto length = GetModuleFileNameW(nullptr, path, 32768);
        require(length && length < 32768, "Cannot locate fixture");
        Child child{launch(path, {L"--child"})};
        const auto key = processKey(child.info.hProcess, child.info.dwProcessId);
        const auto self = processKey(GetCurrentProcess(), GetCurrentProcessId());
        rejects([] { SelectionRegistry invalid(0); });
        rejects([] { SelectionRegistry invalid(65537); });
        SelectionRegistry registry(1);
        rejects([&] { registry.retain(nullptr); });
        const auto first = registry.retain(std::make_unique<ProcessTarget>(key));
        require(registry.current(first), "Selected process lost");
        require(registry.retain(std::make_unique<ProcessTarget>(key)) == first, "Retry changed generation");
        rejects([&] { registry.retain(std::make_unique<ProcessTarget>(self)); });
        auto stale = first;
        ++stale.process.created;
        require(!registry.release(stale) && registry.current(first),
                "Stale process identity released target");
        require(registry.release(first), "Release failed");
        require(WaitForSingleObject(child.info.hProcess, 0) == WAIT_TIMEOUT, "Release killed application");
        const auto second = registry.retain(std::make_unique<ProcessTarget>(key));
        require(second.generation > first.generation && !registry.current(first),
                "Old work remained current");
        require(!registry.release(first) && registry.current(second),
                "Delayed release removed new selection");
        require(registry.snapshot() == std::vector{second}, "Wrong selection snapshot");
        auto exiting = std::make_unique<ProcessTarget>(key);
        require(TerminateProcess(child.info.hProcess, 0), "Cannot stop fixture child");
        require(WaitForSingleObject(child.info.hProcess, 5000) == WAIT_OBJECT_0, "Child did not exit");
        require(!registry.current(second) && registry.snapshot().empty(), "Exited process remained live");
        rejects([&] { registry.retain(std::move(exiting)); });
        require(registry.reap() == 1 && registry.reap() == 0, "Dead target cleanup failed");
        {
            SelectionRegistry temporary;
            temporary.retain(std::make_unique<ProcessTarget>(self));
        }
        std::cout << "PASS: pinned selection, bounded capacity, generations, release and process exit\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
