#include "processes.hpp"
#include <bit>
#include <iostream>
#include <stdexcept>
#include <windivert.h>

// VM-only negative-capability experiment, not a production security helper.
// The parent deliberately kills this filter owner to test loss of protection.
int wmain(int argc, wchar_t** argv) {
    using namespace skewer::windows;
    try {
        if (argc != 4) {
            throw std::runtime_error("Usage: first_packet_test PID ABSOLUTE_DLL READY_EVENT");
        }
        const std::wstring text(argv[1]);
        if (text.empty() || text.find_first_not_of(L"0123456789") != std::wstring::npos) {
            throw std::runtime_error("Invalid fixture PID");
        }
        const auto number = std::stoull(text);
        if (!number || number > MAXDWORD) {
            throw std::runtime_error("Fixture PID out of range");
        }
        const auto pid = static_cast<DWORD>(number);
        Handle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, pid));
        if (!process) {
            throw std::runtime_error("Open fixture process");
        }
        ProcessTarget target(processKey(process.get(), pid));
        const std::wstring path(argv[2]);
        if (path.size() < 4 || path[1] != L':' || path[2] != L'\\') {
            throw std::runtime_error("Absolute trusted DLL path required");
        }
        const auto dll = LoadLibraryExW(path.c_str(), nullptr,
                                        LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (!dll) {
            throw std::runtime_error("Load WinDivert DLL");
        }
        struct Library {
            HMODULE value;
            ~Library() { FreeLibrary(value); }
        } library{dll};
        const auto openSymbol = GetProcAddress(dll, "WinDivertOpen");
        const auto closeSymbol = GetProcAddress(dll, "WinDivertClose");
        if (!openSymbol || !closeSymbol) {
            throw std::runtime_error("Resolve WinDivert API");
        }
        const auto open = std::bit_cast<decltype(&WinDivertOpen)>(openSymbol);
        const auto close = std::bit_cast<decltype(&WinDivertClose)>(closeSymbol);
        const auto filter = "processId == " + std::to_string(pid) +
                            " and event == CONNECT and (protocol == TCP or protocol == UDP)";
        const auto handle =
            open(filter.c_str(), WINDIVERT_LAYER_SOCKET, 0, WINDIVERT_FLAG_DROP | WINDIVERT_FLAG_RECV_ONLY);
        if (handle == INVALID_HANDLE_VALUE) {
            throw std::runtime_error("Open SOCKET block: " + std::to_string(GetLastError()));
        }
        struct Filter {
            HANDLE value;
            decltype(close) release;
            ~Filter() { release(value); }
        } guard{handle, close};
        Handle ready(OpenEventW(EVENT_MODIFY_STATE, FALSE, argv[3]));
        if (!ready || !SetEvent(ready.get())) {
            throw std::runtime_error("Signal filter readiness");
        }
        std::cout << "ARMED PID " << pid << std::endl;
        // Bound abandoned experiments and retire promptly when the fixture exits.
        WaitForSingleObject(target.waitHandle(), 60000);
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL: " << error.what() << std::endl;
        return 1;
    }
}
