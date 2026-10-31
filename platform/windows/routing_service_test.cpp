#include "routing_control.hpp"
#include "pairing_handoff.hpp"
#include "guarded_worker.hpp"
#include "service_host.hpp"
#include "routing_service.hpp"
#include <filesystem>
#include <iostream>
#include <string_view>

using namespace skewer::windows;
namespace {
std::uint64_t number(const wchar_t* text) {
    const std::wstring value(text);
    if (value.empty() || value.find_first_not_of(L"0123456789") != std::wstring::npos) {
        throw std::invalid_argument("Invalid fixture number");
    }
    return std::stoull(value);
}
} // namespace
// Session-zero integration only. Public credentials, fixed false filter and
// deliberately failed session: never installs routes or claims active traffic.
int wmain(int argc, wchar_t** argv) {
    try {
        if (argc < 3 || argc > 6) {
            return 2;
        }
        const std::wstring mode(argv[1]), name(argv[2]);
        const bool fixture_name = name.starts_with(L"SkewerRoutingTest-") ||
                                  name.starts_with(L"SkewerRouting-Test-");
        if (!fixture_name || name.size() > 70 ||
            name.find_first_not_of(L"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-") !=
                std::wstring::npos) {
            throw std::invalid_argument("Invalid fixture service name");
        }
        if (mode == L"--client" || mode == L"--pair" || mode == L"--select" || mode == L"--direct") {
            if ((mode == L"--pair" && argc != 3) || (mode == L"--client" && argc != 5) ||
                (mode == L"--select" && argc != 6) || (mode == L"--direct" && argc != 5)) {
                return 2;
            }
            const auto path = L"\\\\.\\pipe\\SkewerSelection-" + name + (mode == L"--pair" ? L"-pair" : L"");
            HANDLE connected = INVALID_HANDLE_VALUE;
            const auto connect_deadline = GetTickCount64() + 3000;
            do {
                connected = CreateFileW(
                    path.c_str(), FILE_GENERIC_READ | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA,
                    0, nullptr, OPEN_EXISTING,
                    FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, nullptr);
                if (connected != INVALID_HANDLE_VALUE) {
                    break;
                }
                if (GetLastError() != ERROR_PIPE_BUSY && GetLastError() != ERROR_FILE_NOT_FOUND) {
                    break;
                }
                Sleep(20);
            } while (GetTickCount64() < connect_deadline);
            // Retry connection only; never resend a possibly committed command.
            Handle pipe(connected);
            if (!pipe) {
                throw std::runtime_error("Fixture pipe unavailable");
            }
            DWORD read_mode = PIPE_READMODE_MESSAGE;
            if (!SetNamedPipeHandleState(pipe.get(), &read_mode, nullptr, nullptr)) {
                throw std::runtime_error("Message mode failed");
            }
            Handle cancel(CreateEventW(nullptr, TRUE, FALSE, nullptr));
            if (mode == L"--pair") {
                PairingHandoff pairing;
                pairing.endpoint = "skewer://127.0.0.1:18767/pair";
                pairing.identity = "public-fixture";
                pairing.key.fill(0x5a);
                sendPairingHandoff(pipe.get(), name, pairing, cancel.get(), 3000);
                return 0;
            }
            const auto operation = (mode == L"--select" || mode == L"--direct") ? 0 : number(argv[3]);
            if (operation > 2 || (mode == L"--select" && number(argv[4]) > MAXDWORD)) {
                return 2;
            }
            RoutingReply response;
            if (mode == L"--select") {
                response = exchangeSelectedRouting(
                    pipe.get(), name,
                    {static_cast<DWORD>(number(argv[4])), number(argv[5])},
                    number(argv[3]), cancel.get(), 3000);
            } else if (mode == L"--direct") {
                if (std::wstring_view(argv[4]) != L"192.0.2.1") {
                    throw std::invalid_argument("Invalid fixture gateway");
                }
                response = exchangeDirectRouting(
                    pipe.get(), name, {192, 0, 2, 1}, number(argv[3]), cancel.get(), 3000);
            } else {
                response = exchangeRoutingCommand(pipe.get(), name, static_cast<RoutingCommand>(operation),
                                                  number(argv[4]), cancel.get(), 3000);
            }
            std::cout << "{\"result\":" << unsigned(response.result)
                      << ",\"phase\":" << unsigned(response.phase)
                      << ",\"scope\":" << unsigned(response.scope) << ",\"generation\":\""
                      << response.generation << "\",\"transport\":" << unsigned(response.transport)
                      << ",\"paired\":"
                      << (response.paired ? "true" : "false")
                      << ",\"tunnelAvailable\":" << (response.tunnel_available ? "true" : "false")
                      << ",\"directAvailable\":" << (response.direct_available ? "true" : "false");
            if (response.selected) {
                std::cout << ",\"selected\":{\"pid\":" << response.selected->pid
                          << ",\"birth\":\"" << response.selected->created << "\"}";
            }
            std::cout << "}\n";
            return 0;
        }
        if (mode != L"--service" || argc != 4) {
            return 2;
        }
        const ServiceOwner configured_owner(argv[3]);
        wchar_t module[32768]{};
        const auto length = GetModuleFileNameW(nullptr, module, 32768);
        if (!length || length >= 32768) {
            return 2;
        }
        const auto dll = std::filesystem::path(module).parent_path() / L"WinDivert.dll";
        return runService(name, [=](HANDLE stop) -> DWORD {
            serveRoutingService(name, configured_owner, stop,
                                [&](const PairingHandoff& pairing, HANDLE cancel, RoutingSignals& signals) {
                                    if (pairing.identity != "public-fixture" || pairing.key[0] != 0x5a) {
                                        throw std::runtime_error("Missing fixture pairing");
                                    }
                                    traffic::PacketCapture guard(dll.wstring(), "false");
                                    runGuardedWorker(
                                        guard, cancel,
                                        [](HANDLE) { throw std::runtime_error("Fixture tunnel failed"); },
                                        [] { return true; }, &signals.blocked);
                                },
                                [](const PairingHandoff&, std::unique_ptr<ProcessTarget> target,
                                   HANDLE cancel, RoutingSignals& signals) {
                                    if (!target || !target->running()) {
                                        throw std::runtime_error("Selected fixture target unavailable");
                                    }
                                    // Bookkeeping fixture only: no traffic is rerouted.
                                    signals.blocked = true;
                                    WaitForSingleObject(cancel, INFINITE);
                                },
                                [](std::array<std::uint8_t, 4> gateway, HANDLE cancel,
                                   RoutingSignals& signals) {
                                    if (gateway != std::array<std::uint8_t, 4>{192, 0, 2, 1}) {
                                        throw std::runtime_error("Unexpected direct fixture gateway");
                                    }
                                    signals.ready = true;
                                    WaitForSingleObject(cancel, INFINITE);
                                    signals.ready = false;
                                });
            return 0; // Controller cancels and joins before SCM sees STOPPED.
        });
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
