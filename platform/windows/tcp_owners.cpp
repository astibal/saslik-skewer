#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include "tcp_owners.hpp"
#include "processes.hpp"
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

std::vector<TcpOwnerRow> ownedIpv4TcpRows(
    std::span<const TcpOwnerRow> rows,
    std::span<const skewer::windows::ProcessKey> processes) {
    std::vector<TcpOwnerRow> result;
    for (const auto& row : rows) {
        if (row.tuple.ipv6 || !row.tuple.source_port || !row.tuple.destination_port ||
            row.state == MIB_TCP_STATE_LISTEN || row.state == MIB_TCP_STATE_CLOSED) {
            continue;
        }
        const auto process = std::ranges::find_if(processes, [&](const auto& candidate) {
            return candidate.pid == row.pid;
        });
        if (process == processes.end()) continue;
        result.push_back(row);
    }
    return result;
}

std::size_t resetOwnedIpv4Tcp(std::span<const skewer::windows::ProcessKey> processes) {
    if (processes.empty()) return 0;
    const auto snapshot = captureTcpOwners();
    std::size_t reset{};
    for (const auto& row : ownedIpv4TcpRows(snapshot.rows, processes)) {
        // The ProcessTarget retained by SelectedGroupResolver keeps the PID
        // identity alive while this row is converted and deleted.
        MIB_TCPROW native{};
        native.dwState = MIB_TCP_STATE_DELETE_TCB;
        std::memcpy(&native.dwLocalAddr, row.tuple.source.data(), 4);
        std::memcpy(&native.dwRemoteAddr, row.tuple.destination.data(), 4);
        native.dwLocalPort = htons(row.tuple.source_port);
        native.dwRemotePort = htons(row.tuple.destination_port);
        const auto status = SetTcpEntry(&native);
        if (status == NO_ERROR) {
            ++reset;
        } else if (status != ERROR_INVALID_PARAMETER && status != ERROR_NOT_FOUND) {
            throw std::system_error(status, std::system_category(), "Reset selected TCP connection");
        }
        // INVALID_PARAMETER/NOT_FOUND means the endpoint disappeared after
        // the bounded owner snapshot; it no longer needs cleanup.
    }
    return reset;
}
} // namespace skewer::windows::traffic
