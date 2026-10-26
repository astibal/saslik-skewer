#include "wintun_device.hpp"
#include <array>
#include <iostream>
#include <stdexcept>
#include <system_error>

using namespace skewer::windows;
namespace {
void require(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

template <typename Error, typename Action> void expectError(Action action, const char* message) {
    try {
        action();
    } catch (const Error&) {
        return;
    }
    throw std::runtime_error(message);
}

struct Event {
    HANDLE handle = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    Event() { require(handle != nullptr, "CreateEvent failed"); }
    ~Event() { CloseHandle(handle); }
    Event(const Event&) = delete;
    Event& operator=(const Event&) = delete;
};

// Win32 function pointers have no context argument. This single-threaded fixture
// supplies that context only for tests; production has no global API state.
struct Mock;
thread_local Mock* active{};
struct Mock {
    Event ready;
    std::string calls;
    bool fail_create{}, fail_start{}, fail_event{}, full{}, empty{};
    DWORD receive_error{}, send_error{};
    int released{}, sent{};
    std::array<BYTE, 4> incoming{0x45, 1, 2, 3}, outgoing{};
    std::shared_ptr<WintunApi> api = std::make_shared<WintunApi>();

    Mock() {
        active = this;
        api->create = [](LPCWSTR, LPCWSTR, const GUID*) WINAPI -> WINTUN_ADAPTER_HANDLE {
            active->calls += 'C';
            SetLastError(ERROR_ACCESS_DENIED);
            return active->fail_create ? nullptr : reinterpret_cast<WINTUN_ADAPTER_HANDLE>(active);
        };
        api->close = [](WINTUN_ADAPTER_HANDLE) WINAPI { active->calls += 'c'; };
        api->start = [](WINTUN_ADAPTER_HANDLE, DWORD) WINAPI -> WINTUN_SESSION_HANDLE {
            active->calls += 'S';
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
            return active->fail_start ? nullptr : reinterpret_cast<WINTUN_SESSION_HANDLE>(active);
        };
        api->end = [](WINTUN_SESSION_HANDLE) WINAPI { active->calls += 's'; };
        api->read_event = [](WINTUN_SESSION_HANDLE) WINAPI -> HANDLE {
            SetLastError(ERROR_INVALID_HANDLE);
            return active->fail_event ? nullptr : active->ready.handle;
        };
        api->receive = [](WINTUN_SESSION_HANDLE, DWORD* size) WINAPI -> BYTE* {
            if (active->empty || active->receive_error) {
                SetLastError(active->receive_error ? active->receive_error : ERROR_NO_MORE_ITEMS);
                return nullptr;
            }
            *size = static_cast<DWORD>(active->incoming.size());
            return active->incoming.data();
        };
        api->release = [](WINTUN_SESSION_HANDLE, const BYTE*) WINAPI { ++active->released; };
        api->allocate = [](WINTUN_SESSION_HANDLE, DWORD size) WINAPI -> BYTE* {
            if (active->full || active->send_error || size > active->outgoing.size()) {
                SetLastError(active->send_error ? active->send_error : ERROR_BUFFER_OVERFLOW);
                return nullptr;
            }
            return active->outgoing.data();
        };
        api->send = [](WINTUN_SESSION_HANDLE, const BYTE*) WINAPI { ++active->sent; };
        api->luid = [](WINTUN_ADAPTER_HANDLE, NET_LUID* id) WINAPI { id->Value = 42; };
    }
    ~Mock() { active = nullptr; }
};

void testRollback() {
    Mock mock;
    expectError<std::invalid_argument>([] { WintunDevice device(nullptr, L"test"); }, "Missing API accepted");
    expectError<std::invalid_argument>([&] { WintunDevice device(mock.api, L"", 0); },
                                       "Invalid input accepted");
    expectError<std::invalid_argument>([&] { WintunDevice device(mock.api, L"test", 12345); },
                                       "Invalid ring accepted");
    require(mock.calls.empty(), "Invalid input reached driver");
    mock.fail_create = true;
    expectError<std::system_error>([&] { WintunDevice device(mock.api, L"test"); }, "Create failure ignored");
    require(mock.calls == "C", "Failed create closed an unowned handle");
    mock.calls.clear();
    mock.fail_create = false;
    mock.fail_start = true;
    expectError<std::system_error>([&] { WintunDevice device(mock.api, L"test"); },
                                   "Session failure ignored");
    require(mock.calls == "CSc", "Session failure leaked adapter");
    mock.calls.clear();
    mock.fail_start = false;
    mock.fail_event = true;
    expectError<std::system_error>([&] { WintunDevice device(mock.api, L"test"); }, "Event failure ignored");
    require(mock.calls == "CSsc", "Event failure cleanup order incorrect");
}

void testPacketsAndWait() {
    Mock mock;
    Event cancel;
    {
        WintunDevice device(mock.api, L"test");
        std::array<BYTE, 4> buffer{};
        require(device.readPacket(buffer) == 4 && buffer == mock.incoming, "Receive copy failed");
        require(mock.released == 1, "Receive slot not released");
        expectError<std::length_error>([&] { device.readPacket(std::span(buffer).first(2)); },
                                       "Truncation allowed");
        require(mock.released == 2, "Oversized receive leaked slot");
        mock.empty = true;
        require(!device.readPacket(buffer), "Empty ring reported a packet");
        mock.receive_error = ERROR_HANDLE_EOF;
        expectError<std::system_error>([&] { device.readPacket(buffer); },
                                       "Closed adapter reported empty ring");
        require(device.writePacket(buffer) && mock.sent == 1 && mock.outgoing == buffer, "Send copy failed");
        mock.full = true;
        require(!device.writePacket(buffer) && mock.sent == 1, "Full ring reported successful send");
        mock.send_error = ERROR_HANDLE_EOF;
        expectError<std::system_error>([&] { device.writePacket(buffer); },
                                       "Closed adapter reported full ring");
        expectError<std::length_error>([&] { device.writePacket({}); }, "Empty packet accepted");
        std::array<BYTE, WINTUN_MAX_IP_PACKET_SIZE + 1> oversized{};
        expectError<std::length_error>([&] { device.writePacket(oversized); }, "Oversized packet accepted");
        require(device.luid().Value == 42, "Adapter identity lost");
        require(device.waitReadable(cancel.handle, 0) == WintunDevice::Wait::Timeout, "Wait should time out");
        SetEvent(mock.ready.handle);
        require(device.waitReadable(cancel.handle, 0) == WintunDevice::Wait::Ready, "Read event ignored");
        SetEvent(cancel.handle);
        require(device.waitReadable(cancel.handle, 0) == WintunDevice::Wait::Cancelled,
                "Cancellation lost priority");
        expectError<std::system_error>([&] { device.waitReadable(nullptr, 0); },
                                       "Invalid wait handle accepted");
    }
    require(mock.calls == "CSsc", "Destruction did not close session before adapter");
    DWORD flags{};
    require(GetHandleInformation(mock.ready.handle, &flags), "Borrowed read event was closed");
}

void liveTest(const std::wstring& path) {
    auto api = loadWintun(path);
    Event cancel;
    {
        WintunDevice device(api, L"SkewerTest-" + std::to_wstring(GetCurrentProcessId()));
        require(device.luid().Value != 0, "Live adapter has no LUID");
        std::array<BYTE, WINTUN_MAX_IP_PACKET_SIZE> packet{};
        // The OS may emit IPv6 discovery packets even without our own addresses.
        // Reading is allowed, but this test does not configure or route traffic.
        device.readPacket(packet);
        SetEvent(cancel.handle);
        require(device.waitReadable(cancel.handle, 1000) == WintunDevice::Wait::Cancelled,
                "Live wait did not cancel");
    }
    std::cout << "PASS: Wintun load, adapter/session lifetime, LUID, receive and cancellation\n";
}
} // namespace

int wmain(int argc, wchar_t** argv) {
    try {
        if (argc == 3 && std::wstring_view(argv[1]) == L"--live") {
            liveTest(argv[2]);
            return 0;
        }
        if (argc != 1) {
            std::cerr << "Usage: wintun_device_test [--live ABSOLUTE_DLL_PATH]\n";
            return 2;
        }
        expectError<std::invalid_argument>([] { loadWintun(L"wintun.dll"); }, "Relative DLL path accepted");
        expectError<std::invalid_argument>([] { loadWintun(L"\\\\server\\wintun.dll"); },
                                           "Network DLL path accepted");
        testRollback();
        testPacketsAndWait();
        std::cout << "PASS: Wintun rollback, packet ownership, backpressure, errors and cancellable wait\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
