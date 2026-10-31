#include "flow_tracking.hpp"
#include <iostream>
#include <limits>
#include <stdexcept>

namespace {
using namespace skewer::windows;
using namespace skewer::windows::traffic;

// This event deliberately lives until process teardown: Windows can already
// be executing a control handler when it is unregistered. No borrowed object
// or closeable RAII handle is exposed to that concurrent callback.
HANDLE stop_event = nullptr;

BOOL WINAPI stopHandler(DWORD control) {
    if (control != CTRL_C_EVENT && control != CTRL_BREAK_EVENT) {
        return FALSE;
    }
    SetEvent(stop_event);
    return TRUE;
}

DWORD parsePid(std::wstring_view text) {
    if (text.empty()) {
        throw std::invalid_argument("PID must be a positive decimal integer");
    }
    DWORD value{};
    for (const auto character : text) {
        if (character < L'0' || character > L'9') {
            throw std::invalid_argument("PID must contain decimal digits only");
        }
        const auto digit = static_cast<DWORD>(character - L'0');
        if (value > (std::numeric_limits<DWORD>::max() - digit) / 10) {
            throw std::invalid_argument("PID is out of range");
        }
        value = value * 10 + digit;
    }
    if (!value) {
        throw std::invalid_argument("PID zero is not an application");
    }
    return value;
}

void printEvent(const FlowEvent& event, skewer::traffic::FlowIndex::Status status) {
    const char* correlation = "unreliable";
    using Status = skewer::traffic::FlowIndex::Status;
    switch (status) {
    case Status::Unknown:
        correlation = "unknown";
        break;
    case Status::Observed:
        correlation = "observed";
        break;
    case Status::Ambiguous:
        correlation = "ambiguous";
        break;
    case Status::Unreliable:
        break;
    }
    // Addresses are formatted by WinDivert, never application-supplied text.
    std::cout << (event.kind == FlowEvent::Kind::Established ? "OPEN " : "CLOSE ")
              << "pid=" << event.process.pid << " created=" << event.process.created
              << " endpoint=" << event.endpoint_id << (event.protocol == 6 ? " TCP " : " UDP ")
              << (event.ipv6 ? "IPv6 " : "IPv4 ") << '[' << event.local.address << "]:" << event.local.port
              << (event.outbound ? " -> " : " <- ") << '[' << event.remote.address
              << "]:" << event.remote.port << (event.loopback ? " loopback" : "")
              << " correlation=" << correlation << std::endl;
}

void watch(DWORD pid, const std::wstring& dll) {
    // Keep this handle alive through observer construction. The second open
    // validates the same creation time instead of adopting a recycled PID.
    Handle selected(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, pid));
    if (!selected) {
        throw std::runtime_error("Cannot open target PID (Win32 " + std::to_string(GetLastError()) + ")");
    }
    const auto key = processKey(selected.get(), pid);
    TrackedFlowObserver observer(dll, key);
    std::cerr << "Watching PID " << key.pid << " (creation " << key.created << ").\n"
              << "Passive, future flows only; children and existing sockets are not included.\n"
              << "Events may be lost under load. This is not a routing/security decision source.\n"
              << "Ctrl+C stops observation, not the application.\n";
    for (;;) {
        const auto result = observer.next(stop_event, INFINITE);
        if (result.status == FlowObserver::Status::Event) {
            const auto tuple = flowTuple(*result.event);
            const auto status =
                tuple ? observer.lookup(*tuple).status : skewer::traffic::FlowIndex::Status::Unreliable;
            printEvent(*result.event, status);
            if (!std::cout) {
                throw std::runtime_error("Cannot write flow output");
            }
            continue;
        }
        if (result.status == FlowObserver::Status::Timeout) {
            continue;
        }
        std::cerr << (result.status == FlowObserver::Status::TargetExited
                          ? "Target exited; observation stopped.\n"
                          : "Observation cancelled; application remains untouched.\n");
        return;
    }
}

void selfTest() {
    if (parsePid(L"42") != 42 || parsePid(L"4294967295") != MAXDWORD) {
        throw std::runtime_error("PID parsing regression");
    }
    for (const auto input : {L"", L"0", L"-1", L"+1", L" 42", L"42x", L"4294967296"}) {
        bool rejected = false;
        try {
            (void)parsePid(input);
        } catch (const std::invalid_argument&) {
            rejected = true;
        }
        if (!rejected) {
            throw std::runtime_error("Invalid PID accepted");
        }
    }
    std::cout << "PASS: flow watcher PID validation (no driver loaded)\n";
}
} // namespace

int wmain(int argc, wchar_t** argv) {
    try {
        if (argc == 2 && std::wstring_view(argv[1]) == L"--self-test") {
            selfTest();
            return 0;
        }
        if (argc != 3) {
            std::cerr << "Usage: skewer-flow-watch PID ABSOLUTE_WINDIVERT_DLL\n";
            return 2;
        }
        const auto pid = parsePid(argv[1]);
        stop_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!stop_event || !SetConsoleCtrlHandler(stopHandler, TRUE)) {
            throw std::runtime_error("Cannot initialize console cancellation");
        }
        watch(pid, argv[2]);
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "ERROR: " << error.what() << '\n';
        return 1;
    }
}
