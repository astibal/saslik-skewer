#include "service_host.hpp"
#include <iostream>

// VM-only service lifecycle fixture. No DLL loading, interception, routes,
// credentials or privileged IPC. Install as LocalService, never LocalSystem.
int wmain(int argc, wchar_t** argv) {
    try {
        if (argc != 2 && argc != 3) {
            throw std::invalid_argument("Usage: service_host_test SkewerLifecycle-NAME [--fail]");
        }
        const std::wstring name(argv[1]);
        if (!name.starts_with(L"SkewerLifecycle-") ||
            name.find_first_not_of(L"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-") !=
                std::wstring::npos ||
            (argc == 3 && std::wstring(argv[2]) != L"--fail")) {
            throw std::invalid_argument("Invalid fixture arguments");
        }
        const bool fail = argc == 3;
        return skewer::windows::runService(name, [fail](HANDLE stop) -> DWORD {
            // Bounded idle fixture so an interrupted test cannot leave it running.
            const auto outcome = WaitForSingleObject(stop, fail ? 2000 : 60000);
            if (outcome == WAIT_FAILED) {
                return GetLastError();
            }
            return fail && outcome == WAIT_TIMEOUT ? 42 : 0;
        });
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
