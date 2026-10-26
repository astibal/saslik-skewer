#include "service_host.hpp"
#include "packet_capture.hpp"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>

// Elevated VM fixture only. The filter is compiled in and matches nothing.
// No arbitrary filter, PID, destination or output path is accepted from IPC.
int wmain(int argc, wchar_t** argv) {
    try {
        if (argc != 2 && argc != 3) {
            throw std::invalid_argument("Usage: capture_service_test SkewerCapture-NAME [--missing-dll]");
        }
        const std::wstring name(argv[1]);
        if (!name.starts_with(L"SkewerCapture-") || name.size() > 100 ||
            name.find_first_not_of(L"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-") !=
                std::wstring::npos ||
            (argc == 3 && std::wstring(argv[2]) != L"--missing-dll")) {
            throw std::invalid_argument("Invalid capture fixture arguments");
        }
        std::wstring module(32768, L'\0');
        const auto length = GetModuleFileNameW(nullptr, module.data(), static_cast<DWORD>(module.size()));
        if (!length || length >= module.size()) {
            throw std::runtime_error("Cannot locate fixture binary");
        }
        module.resize(length);
        const auto root = std::filesystem::path(module).parent_path();
        const auto dll = root / (argc == 3 ? L"missing-windivert.dll" : L"WinDivert.dll");
        const auto log = root / (name + L".status");
        return skewer::windows::runService(name, [dll, log](HANDLE stop) -> DWORD {
            std::ofstream output(log);
            output.exceptions(std::ios::badbit | std::ios::failbit);
            // SCM RUNNING and successful handle acquisition are distinct from
            // routing readiness. This fixture can never declare routing ready.
            const auto report = [&](const char* phase, const auto& stats) {
                output << phase << " routing_ready=false captured=" << stats.captured_packets
                       << " injected=" << stats.injected_packets << std::endl;
            };
            using Capture = skewer::windows::traffic::PacketCapture;
            Capture::Stats stats{};
            report("starting", stats);
            try {
                {
                    Capture capture(dll.wstring(), "false");
                    report("capture_ready", capture.stats());
                    const auto deadline = GetTickCount64() + 60000;
                    for (;;) {
                        const auto result = capture.next(stop, 250);
                        if (result.status == Capture::Status::Cancelled) {
                            break;
                        }
                        if (result.status == Capture::Status::Packet) {
                            throw std::runtime_error("Impossible fixture filter captured traffic");
                        }
                        if (GetTickCount64() >= deadline) {
                            throw std::runtime_error("Capture service fixture lifetime exceeded");
                        }
                    }
                    stats = capture.stats();
                    report("stopping", stats);
                } // Drain I/O and close the WinDivert handle before STOPPED.
                report("stopped", stats);
                return 0;
            } catch (...) {
                report("failed", stats);
                return 51;
            }
        });
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
