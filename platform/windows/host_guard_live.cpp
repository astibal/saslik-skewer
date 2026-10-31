#include "packet_capture.hpp"
#include <iostream>
#include <sstream>

using namespace skewer::windows;
namespace {
unsigned number(const std::wstring& value, unsigned maximum) {
    if (value.empty() || value.find_first_not_of(L"0123456789") != std::wstring::npos) {
        throw std::invalid_argument("Invalid numeric argument");
    }
    const auto result = std::stoul(value);
    if (!result || result > maximum) {
        throw std::invalid_argument("Numeric argument out of range");
    }
    return static_cast<unsigned>(result);
}
std::string ipv4(const std::wstring& value) {
    std::wistringstream stream(value);
    std::wstring part;
    std::string result;
    unsigned count{};
    while (std::getline(stream, part, L'.')) {
        if (part.empty() || part.size() > 3 || part.find_first_not_of(L"0123456789") != std::wstring::npos ||
            std::stoul(part) > 255) {
            throw std::invalid_argument("Invalid IPv4 address");
        }
        if (count++) {
            result += '.';
        }
        result += std::to_string(std::stoul(part));
    }
    if (count != 4 || value.back() == L'.') {
        throw std::invalid_argument("Invalid IPv4 address");
    }
    return result;
}
} // namespace

// Disposable VM fixture only. Blocks physical egress except exact tunnel/control
// and SSH-management tuples. These tuple exemptions are NOT process isolation.
// No caller-supplied filter expression, persistent policy or route changes.
int wmain(int argc, wchar_t** argv) {
    try {
        if (argc != 9) {
            throw std::invalid_argument(
                "Expected DLL IFINDEX PEER UDPPORT CONTROLPORT MANAGEMENT READY STOP");
        }
        const auto index = number(argv[2], MAXDWORD);
        const auto peer = ipv4(argv[3]);
        const auto udp = number(argv[4], 65535), control = number(argv[5], 65535);
        const auto management = ipv4(argv[6]);
        Handle ready(OpenEventW(EVENT_MODIFY_STATE, FALSE, argv[7]));
        Handle stop(OpenEventW(SYNCHRONIZE, FALSE, argv[8]));
        if (!ready || !stop) {
            throw std::runtime_error("Cannot open fixture events");
        }
        const auto filter = "outbound and !loopback and ifIdx != " + std::to_string(index) +
                            " and (ip and ((ip.DstAddr == " + peer +
                            " and (udp.DstPort == " + std::to_string(udp) +
                            " or tcp.DstPort == " + std::to_string(control) +
                            ")) or (ip.DstAddr == " + management + " and tcp.SrcPort == 22)) ? false : true)";
        std::cout << "Host guard filter: " << filter << std::endl;
        traffic::PacketCapture capture(argv[1], filter);
        if (!SetEvent(ready.get())) {
            throw std::runtime_error("Cannot signal armed guard");
        }
        const auto deadline = GetTickCount64() + 90000;
        while (GetTickCount64() < deadline) {
            const auto result = capture.next(stop.get(), 100);
            if (result.status == traffic::PacketCapture::Status::Cancelled) {
                std::cout << "Guard stopped; dropped=" << capture.stats().captured_packets << '\n';
                return 0;
            }
            // Intentionally never reinject: this is the physical-egress deny path.
        }
        throw std::runtime_error("Fixture guard lifetime expired");
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
