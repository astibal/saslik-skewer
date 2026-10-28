#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include "tcp_owners.hpp"
#include <algorithm>
#include <cstddef>
#include <cstring>
#include <stdexcept>
#include <system_error>
#include <type_traits>

namespace skewer::windows::traffic {
bool excludesSelectedTcpOwner(std::span<const std::uint32_t> candidates, std::uint32_t selected) {
    return selected && !candidates.empty() &&
           std::all_of(candidates.begin(), candidates.end(),
                       [&](auto pid) { return pid && pid != selected; });
}
namespace {
template <typename Table, typename Convert>
void appendTable(ULONG family, std::vector<TcpOwnerRow>& rows, Convert convert) {
    constexpr DWORD maximum = 4 * 1024 * 1024;
    DWORD size{};
    auto status = GetExtendedTcpTable(nullptr, &size, FALSE, family, TCP_TABLE_OWNER_PID_ALL, 0);
    if (status != ERROR_INSUFFICIENT_BUFFER) {
        throw std::system_error(status, std::system_category(), "Size TCP owner table");
    }
    for (unsigned attempt = 0; attempt < 4; ++attempt) {
        if (size < offsetof(Table, table) || size > maximum) {
            throw std::runtime_error("TCP owner table exceeds bounds");
        }
        std::vector<unsigned char> bytes(size);
        DWORD written = size;
        status = GetExtendedTcpTable(bytes.data(), &written, FALSE, family, TCP_TABLE_OWNER_PID_ALL, 0);
        if (status == ERROR_INSUFFICIENT_BUFFER) {
            size = written;
            continue;
        }
        if (status != NO_ERROR) {
            throw std::system_error(status, std::system_category(), "Read TCP owner table");
        }
        using Row = decltype(Table{}.table[0]);
        using Value = std::remove_reference_t<Row>;
        constexpr auto offset = offsetof(Table, table);
        DWORD count{};
        std::memcpy(&count, bytes.data(), sizeof(count));
        if (written > bytes.size() || written < offset || count > (written - offset) / sizeof(Value)) {
            throw std::runtime_error("Malformed TCP owner table");
        }
        for (DWORD i = 0; i < count; ++i) {
            Value row{};
            std::memcpy(&row, bytes.data() + offset + i * sizeof(Value), sizeof(row));
            rows.push_back(convert(row));
        }
        return;
    }
    throw std::runtime_error("TCP owner table kept changing during collection");
}
} // namespace

TcpOwnerSnapshot captureTcpOwners() {
    TcpOwnerSnapshot snapshot;
    snapshot.started = TcpOwnerSnapshot::Clock::now();
    appendTable<MIB_TCPTABLE_OWNER_PID>(AF_INET, snapshot.rows, [](const auto& row) {
        TcpOwnerRow result;
        result.pid = row.dwOwningPid;
        result.state = row.dwState;
        result.tuple.protocol = IPPROTO_TCP;
        std::memcpy(result.tuple.source.data(), &row.dwLocalAddr, 4);
        std::memcpy(result.tuple.destination.data(), &row.dwRemoteAddr, 4);
        result.tuple.source_port = ntohs(static_cast<u_short>(row.dwLocalPort));
        result.tuple.destination_port = ntohs(static_cast<u_short>(row.dwRemotePort));
        return result;
    });
    appendTable<MIB_TCP6TABLE_OWNER_PID>(AF_INET6, snapshot.rows, [](const auto& row) {
        TcpOwnerRow result;
        result.pid = row.dwOwningPid;
        result.state = row.dwState;
        result.tuple.ipv6 = true;
        result.tuple.protocol = IPPROTO_TCP;
        std::memcpy(result.tuple.source.data(), row.ucLocalAddr, 16);
        std::memcpy(result.tuple.destination.data(), row.ucRemoteAddr, 16);
        result.tuple.source_port = ntohs(static_cast<u_short>(row.dwLocalPort));
        result.tuple.destination_port = ntohs(static_cast<u_short>(row.dwRemotePort));
        // Scope IDs are not present in L3 tuples: include all matching scopes,
        // never silently select one and erase a competing owner.
        return result;
    });
    snapshot.completed = TcpOwnerSnapshot::Clock::now();
    return snapshot;
}

std::vector<std::uint32_t> tcpOwnerCandidates(std::span<const TcpOwnerRow> rows,
                                              const skewer::traffic::PacketTuple& tuple) {
    if (tuple.protocol != IPPROTO_TCP || !tuple.source_port || !tuple.destination_port) {
        throw std::invalid_argument("TCP owner lookup requires a complete TCP tuple");
    }
    std::vector<std::uint32_t> result;
    for (const auto& row : rows) {
        if (row.tuple == tuple) {
            result.push_back(row.pid);
        }
    }
    std::sort(result.begin(), result.end());
    result.erase(std::unique(result.begin(), result.end()), result.end());
    return result;
}
} // namespace skewer::windows::traffic
