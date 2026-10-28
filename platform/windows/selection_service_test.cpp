#include "selection_transport.hpp"
#include "service_host.hpp"
#include "selection_registry.hpp"
#include "pairing_handoff.hpp"
#include <filesystem>
#include <fstream>
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
        const bool handoff = name.find(L"-handoff") != std::wstring::npos;
        const bool wrong_owner = name.ends_with(L"-denied");
        if (!name.starts_with(L"SkewerSelectionTest-") || name.size() > 80 ||
            name.find_first_not_of(L"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-") !=
                std::wstring::npos) {
            throw std::invalid_argument("Invalid fixture service name");
        }
        const bool scope_client = mode == L"--scope-applications" || mode == L"--scope-host";
        const auto number = [](const wchar_t* text) {
            const std::wstring input(text);
            if (input.empty() || input.find_first_not_of(L"0123456789") != std::wstring::npos) {
                throw std::invalid_argument("Invalid process identity");
            }
            return std::stoull(input);
        };
        const bool target_client = mode == L"--client-target" && argc == 5;
        if (((mode == L"--client" || scope_client) && argc == 3) || target_client) {
            auto target = processKey(GetCurrentProcess(), GetCurrentProcessId());
            if (target_client) {
                const auto pid = number(argv[3]), birth = number(argv[4]);
                if (!pid || pid > MAXDWORD || !birth) {
                    throw std::invalid_argument("Invalid client target identity");
                }
                target = {static_cast<DWORD>(pid), birth};
            }
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
            if (handoff) {
                PairingHandoff value;
                value.endpoint = "skewer://127.0.0.1:18767/pair";
                value.identity = "public-fixture-client";
                value.key.fill(0x5a);
                bool rejected = false;
                try {
                    sendPairingHandoff(pipe.get(), name, value, stop.get(), 3000);
                } catch (const std::runtime_error&) {
                    rejected = true;
                }
                if (rejected != wrong_owner) {
                    throw std::runtime_error("Unexpected handoff authorization result");
                }
                std::cout << (wrong_owner ? "PASS: credential handoff rejected for foreign owner\n"
                                          : "PASS: authenticated credential handoff, no routing grant\n");
                return 0;
            }
            const auto result = scope_client
                                    ? exchangeScopeProbe(pipe.get(), name,
                                                         mode == L"--scope-host"
                                                             ? skewer::traffic::RoutingScope::WholeHost
                                                             : skewer::traffic::RoutingScope::Applications,
                                                         stop.get(), 3000)
                                    : exchangeSelection(pipe.get(), name, target, stop.get(), 3000);
            const auto expected =
                scope_client ? SelectionStatus::ScopeUnsupported : SelectionStatus::Verified;
            if (result != expected) {
                throw std::runtime_error("Selection rejected");
            }
            std::cout << (scope_client
                              ? "PASS: SCM-authenticated scope probe reports unsupported; no routing grant\n"
                              : "PASS: SCM-authenticated service verified client process; routing remains "
                                "disabled\n");
            return 0;
        }
        if (mode != L"--service" || argc != 5) {
            throw std::invalid_argument("Invalid fixture mode");
        }
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
            HANDLE raw_service{};
            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw_service)) {
                return 54;
            }
            Handle service_token(raw_service);
            wchar_t module[32768]{};
            const auto length = GetModuleFileNameW(nullptr, module, 32768);
            if (!length || length >= 32768) {
                return 53;
            }
            std::ofstream log(std::filesystem::path(module).parent_path() / (name + L".status"));
            log.exceptions(std::ios::badbit | std::ios::failbit);
            SelectionRegistry selected;
            const auto end = GetTickCount64() + 60000;
            while (WaitForSingleObject(stop, 0) == WAIT_TIMEOUT && GetTickCount64() < end) {
                try {
                    acceptSelection(pipe->get(), stop, 500);
                    if (handoff) {
                        const auto value = receivePairingHandoff(
                            pipe->get(), wrong_owner ? service_token.get() : token.get(), stop, 3000);
                        std::array<std::uint8_t, 32> expected{};
                        expected.fill(0x5a);
                        if (value->endpoint != "skewer://127.0.0.1:18767/pair" ||
                            value->identity != "public-fixture-client" || value->key != expected) {
                            throw std::runtime_error("Fixture handoff mismatch");
                        }
                        log << "handoff_received routing_ready=false" << std::endl;
                    } else {
                        auto result = serveSelection(pipe->get(), stop, 3000);
                        if (result.target) {
                            // Fixture-only retention: the validation protocol still
                            // grants no network policy or routed status to clients.
                            selected.retain(std::move(result.target));
                        }
                    }
                    finishSelection(pipe->get(), stop, 1000);
                } catch (const std::runtime_error&) {
                    // Isolate a failed or idle connection from the next client.
                }
                DisconnectNamedPipe(pipe->get());
                selected.reap();
                log << "after_disconnect live=" << selected.snapshot().size() << " routing_ready=false"
                    << std::endl;
            }
            return 0;
        });
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
