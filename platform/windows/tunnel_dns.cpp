#include "tunnel_dns.hpp"
#include <ws2tcpip.h>
#include <system_error>
#include <cstddef>
#include <cstring>

namespace skewer::windows {
namespace {
// SDK v1 ABI shim for MinGW headers that predate this API. Load the function
// dynamically so unsupported Windows versions fail explicitly at configuration.
// https://learn.microsoft.com/windows/win32/api/netioapi/ns-netioapi-dns_interface_settings
struct DnsSettingsV1 {
    ULONG version;
    ULONG64 flags;
    PWSTR domain;
    PWSTR name_server;
    PWSTR search_list;
    ULONG registration_enabled;
    ULONG register_adapter_name;
    ULONG enable_llmnr;
    ULONG query_adapter_name;
    PWSTR profile_name_server;
};
#ifdef _WIN64
static_assert(sizeof(DnsSettingsV1) == 64 && offsetof(DnsSettingsV1, name_server) == 24);
#endif
} // namespace
void configureTunnelDns(NET_LUID adapter, const std::wstring& server) {
    IN_ADDR parsed{};
    if (!adapter.Value || server.find(L'\0') != std::wstring::npos ||
        InetPtonW(AF_INET, server.c_str(), &parsed) != 1) {
        throw std::invalid_argument("Expected a numeric tunnel DNS server");
    }
    const auto ip = ntohl(parsed.S_un.S_addr);
    if (!ip || (ip >> 24) == 127 || (ip >> 24) >= 224) {
        throw std::invalid_argument("Expected a unicast tunnel DNS server");
    }
    GUID guid{};
    auto status = ConvertInterfaceLuidToGuid(&adapter, &guid);
    if (status != NO_ERROR) {
        throw std::system_error(status, std::system_category(), "Resolve tunnel DNS interface");
    }
    const auto module = GetModuleHandleW(L"iphlpapi.dll");
    using SetDns = DWORD(WINAPI*)(GUID, const DnsSettingsV1*);
    const auto raw = module ? GetProcAddress(module, "SetInterfaceDnsSettings") : nullptr;
    if (!raw) {
        throw std::runtime_error("Windows does not support native interface DNS settings");
    }
    SetDns set_dns{};
    static_assert(sizeof(set_dns) == sizeof(raw));
    memcpy(&set_dns, &raw, sizeof(set_dns));
    auto nameserver = server;
    DnsSettingsV1 settings{};
    settings.version = 1;
    // Nameserver + disable dynamic registration and LLMNR on our adapter only.
    settings.flags = 0x0002 | 0x0008 | 0x0080;
    settings.name_server = nameserver.data();
    status = set_dns(guid, &settings);
    if (status != NO_ERROR) {
        throw std::system_error(status, std::system_category(), "Configure tunnel DNS");
    }
    // Windows prefers DNS on the lowest-metric interface. Automatic Wintun
    // metrics can lose to a manually configured physical NIC, whose resolver
    // is intentionally unreachable through the physical-egress guard. Change
    // only our owned adapter; deleting it also retires this preference.
    MIB_IPINTERFACE_ROW preference{};
    InitializeIpInterfaceEntry(&preference);
    preference.Family = AF_INET;
    preference.InterfaceLuid = adapter;
    status = GetIpInterfaceEntry(&preference);
    if (status != NO_ERROR) {
        throw std::system_error(status, std::system_category(), "Read tunnel DNS preference");
    }
    preference.UseAutomaticMetric = FALSE;
    preference.Metric = 0;
    preference.SitePrefixLength = 0;
    status = SetIpInterfaceEntry(&preference);
    if (status != NO_ERROR) {
        throw std::system_error(status, std::system_category(), "Set tunnel DNS preference");
    }
    status = GetIpInterfaceEntry(&preference);
    if (status != NO_ERROR) {
        throw std::system_error(status, std::system_category(), "Verify tunnel DNS preference");
    }
    if (preference.UseAutomaticMetric || preference.Metric != 0) {
        throw std::runtime_error("Tunnel DNS preference was not retained");
    }
}
} // namespace skewer::windows
