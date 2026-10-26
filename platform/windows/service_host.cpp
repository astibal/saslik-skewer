#include "service_host.hpp"
#include <atomic>
#include <memory>
#include <stdexcept>
#include <utility>

namespace skewer::windows {
namespace {
struct Host {
    std::wstring name;
    ServiceWorker worker;
    HANDLE stop{};
    HANDLE done{};
    SERVICE_STATUS_HANDLE status{};
    DWORD result{};
};
// Published once before the dispatcher starts. SCM callbacks can outlive
// ServiceMain's stack. Keep their context/events alive until process teardown;
// Windows reclaims them on exit. No callback touches GUI or worker-owned data.
std::atomic<Host*> active{};

bool report(Host& host, DWORD state, DWORD checkpoint = 0) {
    SERVICE_STATUS status{};
    status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    status.dwCurrentState = state;
    status.dwControlsAccepted = state == SERVICE_RUNNING ? SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN : 0;
    status.dwCheckPoint = checkpoint;
    status.dwWaitHint = state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING ? 5000 : 0;
    if (state == SERVICE_STOPPED && host.result) {
        status.dwWin32ExitCode = ERROR_SERVICE_SPECIFIC_ERROR;
        status.dwServiceSpecificExitCode = host.result;
    }
    return SetServiceStatus(host.status, &status) != FALSE;
}

DWORD WINAPI control(DWORD command, DWORD, void*, void* context) {
    auto& host = *static_cast<Host*>(context);
    if (command == SERVICE_CONTROL_STOP || command == SERVICE_CONTROL_SHUTDOWN) {
        return SetEvent(host.stop) ? NO_ERROR : GetLastError();
    }
    return command == SERVICE_CONTROL_INTERROGATE ? NO_ERROR : ERROR_CALL_NOT_IMPLEMENTED;
}

DWORD WINAPI work(void* context) {
    auto& host = *static_cast<Host*>(context);
    try {
        host.result = host.worker(host.stop);
    } catch (...) {
        // Exceptions must never cross the Win32 thread entry boundary.
        host.result = ERROR_EXCEPTION_IN_SERVICE;
    }
    SetEvent(host.done);
    return 0;
}

void WINAPI serviceMain(DWORD, wchar_t**) {
    auto& host = *active.load(std::memory_order_acquire);
    host.status = RegisterServiceCtrlHandlerExW(host.name.c_str(), control, &host);
    if (!host.status) {
        return;
    }
    if (!report(host, SERVICE_START_PENDING, 1)) {
        return;
    }
    const auto thread = CreateThread(nullptr, 0, work, &host, 0, nullptr);
    if (!thread) {
        host.result = GetLastError();
        report(host, SERVICE_STOPPED);
        return;
    }
    if (!report(host, SERVICE_RUNNING)) {
        SetEvent(host.stop);
    }
    const HANDLE events[]{host.stop, host.done};
    const auto outcome = WaitForMultipleObjects(2, events, FALSE, INFINITE);
    if (outcome != WAIT_OBJECT_0 + 1) {
        SetEvent(host.stop);
    }
    DWORD checkpoint = 1;
    report(host, SERVICE_STOP_PENDING, checkpoint);
    // Wait on the thread, not just its completion event: resources must be
    // destroyed and worker code returned before SCM sees SERVICE_STOPPED.
    while (WaitForSingleObject(thread, 1000) == WAIT_TIMEOUT) {
        report(host, SERVICE_STOP_PENDING, ++checkpoint);
    }
    CloseHandle(thread);
    report(host, SERVICE_STOPPED);
}
} // namespace

int runService(const std::wstring& name, ServiceWorker worker) {
    if (name.empty() || name.size() > 200 || name.find_first_of(L"/\\") != std::wstring::npos ||
        name.find(L'\0') != std::wstring::npos || !worker) {
        throw std::invalid_argument("Invalid service name or worker");
    }
    auto host = std::make_unique<Host>();
    host->name = name;
    host->worker = std::move(worker);
    host->stop = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    host->done = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!host->stop || !host->done) {
        if (host->stop) {
            CloseHandle(host->stop);
        }
        if (host->done) {
            CloseHandle(host->done);
        }
        throw std::runtime_error("Cannot create service events");
    }
    Host* expected = nullptr;
    if (!active.compare_exchange_strong(expected, host.get(), std::memory_order_release)) {
        CloseHandle(host->stop);
        CloseHandle(host->done);
        throw std::logic_error("Only one service host may run per process");
    }
    auto* resident = host.release();
    SERVICE_TABLE_ENTRYW table[]{{resident->name.data(), serviceMain}, {nullptr, nullptr}};
    if (!StartServiceCtrlDispatcherW(table)) {
        return static_cast<int>(GetLastError());
    }
    return 0; // Worker failure is reported through SCM's service-specific code.
}
} // namespace skewer::windows
