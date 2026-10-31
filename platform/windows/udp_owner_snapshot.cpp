#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include "udp_owners.hpp"
#include <cstddef>
#include <cstring>
#include <stdexcept>
#include <system_error>
#include <type_traits>

namespace skewer::windows::traffic {
namespace {
template <typename Table, typename Convert>
void appendUdpTable(ULONG family, std::vector<UdpOwnerRow>& rows, Convert convert) {
    constexpr DWORD maximum = 4 * 1024 * 1024;
    DWORD size{};
    auto status = GetExtendedUdpTable(nullptr, &size, FALSE, family, UDP_TABLE_OWNER_PID, 0);
    if (status != ERROR_INSUFFICIENT_BUFFER) {
        throw std::system_error(status, std::system_category(), "Size UDP owner table");
    }
    // A busy host can grow the table between sizing and reading. Bound retries
    // as well as memory, and reject the entire snapshot on any failed family.
    for (unsigned attempt = 0; attempt < 4; ++attempt) {
        constexpr auto offset = offsetof(Table, table);
        if (size < offset || size > maximum) {
            throw std::runtime_error("UDP owner table exceeds bounds");
        }
        std::vector<unsigned char> bytes(size);
        DWORD written = size;
        status = GetExtendedUdpTable(bytes.data(), &written, FALSE, family, UDP_TABLE_OWNER_PID, 0);
        if (status == ERROR_INSUFFICIENT_BUFFER) {
            size = written;
            continue;
        }
        if (status != NO_ERROR) {
            throw std::system_error(status, std::system_category(), "Read UDP owner table");
        }
        using Row = std::remove_reference_t<decltype(Table{}.table[0])>;
        DWORD count{};
        std::memcpy(&count, bytes.data(), sizeof(count));
        if (written > bytes.size() || written < offset || count > (written - offset) / sizeof(Row)) {
            throw std::runtime_error("Malformed UDP owner table");
        }
        for (DWORD i = 0; i < count; ++i) {
            Row row{};
            std::memcpy(&row, bytes.data() + offset + i * sizeof(Row), sizeof(row));
            rows.push_back(convert(row));
        }
        return;
    }
    throw std::runtime_error("UDP owner table kept changing during collection");
}
} // namespace

UdpOwnerSnapshot captureUdpOwners() {
    UdpOwnerSnapshot snapshot;
    snapshot.started = UdpOwnerSnapshot::Clock::now();
    appendUdpTable<MIB_UDPTABLE_OWNER_PID>(AF_INET, snapshot.rows, [](const auto& row) {
        UdpOwnerRow result;
        result.pid = row.dwOwningPid;
        result.local_port = ntohs(static_cast<u_short>(row.dwLocalPort));
        std::memcpy(result.local_address.data(), &row.dwLocalAddr, 4);
        return result;
    });
    appendUdpTable<MIB_UDP6TABLE_OWNER_PID>(AF_INET6, snapshot.rows, [](const auto& row) {
        UdpOwnerRow result;
        result.ipv6 = true;
        result.pid = row.dwOwningPid;
        result.local_port = ntohs(static_cast<u_short>(row.dwLocalPort));
        std::memcpy(result.local_address.data(), row.ucLocalAddr, 16);
        // No scope in the packet tuple: retaining all scopes overestimates
        // competitors rather than incorrectly declaring a unique owner.
        return result;
    });
    snapshot.completed = UdpOwnerSnapshot::Clock::now();
    return snapshot;
}
} // namespace skewer::windows::traffic
