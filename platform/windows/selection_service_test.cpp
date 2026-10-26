#include "selection_transport.hpp"
#include "service_host.hpp"
#include <iostream>

using namespace skewer::windows;

// Elevated VM-only integration fixture. Administrator-provided PID/birth
// identifies the test launcher; it is not accepted from the pipe client.
int wmain(int argc, wchar_t** argv) {
    try {
        if (argc != 3 && argc != 5) {
            throw std::invalid_argument("Expected --client NAME or --service NAME PID BIRTH");
        }
        const std::wstring mode(argv[1]), name(argv[2]);
        if (!name.starts_with(L"SkewerSelectionTest-") || name.size() > 80 ||
            name.find_first_not_of(L"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-") !=
                std::wstring::npos) {
            throw std::invalid_argument("Invalid fixture service name");
        }
        if (mode == L"--client" && argc == 3) {
            const auto path = L"\\\\.\\pipe\\SkewerSelection-" + name;
            Handle pipe(CreateFileW(
                path.c_str(), FILE_GENERIC_READ | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA, 0,
                nullptr, OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, nullptr));
            if (!pipe) {
                throw std::runtime_error("Selection service pipe unavailable");
            }
            DWORD read_mode = PIPE_READMODE_MESSAGE;
            if (!SetNamedPipeHandleState(pipe.get(), &read_mode, nullptr, nullptr)) {
                throw std::runtime_error("Cannot enable message reads");
            }
            Handle stop(CreateEventW(nullptr, TRUE, FALSE, nullptr));
            const auto result = exchangeSelection(
                pipe.get(), name, processKey(GetCurrentProcess(), GetCurrentProcessId()), stop.get(), 3000);
            if (result != SelectionStatus::Verified) {
                throw std::runtime_error("Selection rejected");
            }
            std::cout
                << "PASS: SCM-authenticated service verified client process; routing remains disabled\n";
            return 0;
        }
        if (mode != L"--service" || argc != 5) {
            throw std::invalid_argument("Invalid fixture mode");
        }
        const auto number = [](const wchar_t* text) {
            const std::wstring input(text);
            if (input.empty() || input.find_first_not_of(L"0123456789") != std::wstring::npos) {
                throw std::invalid_argument("Invalid process identity");
            }
            return std::stoull(input);
        };
        const auto pid = number(argv[3]), birth = number(argv[4]);
        if (!pid || pid > MAXDWORD || !birth) {
            throw std::invalid_argument("Invalid process identity");
        }
        return runService(name, [=](HANDLE stop) -> DWORD {
            Handle owner(
                OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, static_cast<DWORD>(pid)));
            if (!owner || processKey(owner.get(), static_cast<DWORD>(pid)) !=
                              ProcessKey{static_cast<DWORD>(pid), birth}) {
                return 51;
            }
            HANDLE raw{};
            if (!OpenProcessToken(owner.get(), TOKEN_QUERY, &raw)) {
                return 52;
            }
            Handle token(raw);
            auto pipe = createSelectionPipe(name, token.get());
            const auto end = GetTickCount64() + 60000;
            while (WaitForSingleObject(stop, 0) == WAIT_TIMEOUT && GetTickCount64() < end) {
                try {
                    acceptSelection(pipe->get(), stop, 500);
                    auto result = serveSelection(pipe->get(), stop, 3000);
                    finishSelection(pipe->get(), stop, 1000);
                    // This fixture validates identity only, never installs policy.
                    // The verified target lives through completion of the reply.
                } catch (const std::runtime_error&) {
                    // Isolate a failed or idle connection from the next client.
                }
                DisconnectNamedPipe(pipe->get());
            }
            return 0;
        });
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
