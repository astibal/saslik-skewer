#include "tunnel_dns.hpp"
#include <iostream>

int main() {
    NET_LUID sentinel{};
    sentinel.Value = 1; // Never reaches an API call: all these inputs are invalid.
    try {
        for (const auto& server : {std::wstring{}, std::wstring(L"resolver.example"),
             std::wstring(L"0.0.0.0"), std::wstring(L"127.0.0.1"), std::wstring(L"224.0.0.1"),
             std::wstring(L"255.255.255.255"), std::wstring(L"1.1.1.1 8.8.8.8"),
             std::wstring(L"1.1.1.1\0ignored", 15)}) {
            bool rejected{};
            try { skewer::windows::configureTunnelDns(sentinel, server); }
            catch (const std::invalid_argument&) { rejected = true; }
            if (!rejected) { throw std::runtime_error("Invalid DNS input reached native API"); }
        }
        bool rejected{};
        try { skewer::windows::configureTunnelDns({}, L"1.1.1.1"); }
        catch (const std::invalid_argument&) { rejected = true; }
        if (!rejected) { return 2; }
        std::cout << "PASS: invalid DNS addresses and missing adapter rejected before native configuration\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
