#include "ipv4_prefix.hpp"

#include <iostream>
#include <stdexcept>

using namespace skewer::traffic;

namespace {
void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}
} // namespace

int main() {
    try {
        Ipv4Prefix prefix;
        require(parseIpv4Prefix(" 192.168.1.9/24 ", prefix) && prefix.text() == "192.168.1.0/24",
                "CIDR was not trimmed and canonicalized");
        require(prefix.contains(0xc0a801ffU) && !prefix.contains(0xc0a80200U),
                "CIDR membership is incorrect");
        require(parseIpv4Prefix("0.0.0.0/0", prefix) && prefix.contains(0xffffffffU),
                "Default prefix is invalid");
        for (const auto invalid : {"", "example.com", "::1", "1.2.3", "1.2.3.4.5",
                                   "1.2.3.4/", "1.2.3.4/33", "1.2.3.4/-1",
                                   "1.2.3.4; flush ruleset"}) {
            require(!parseIpv4Prefix(invalid, prefix), "Invalid prefix was accepted");
        }
        std::vector<std::string> normalized;
        std::string error;
        const std::vector<std::string> input{"203.0.113.7", "192.168.1.9/24", "203.0.113.7/32"};
        require(normalizeIpv4Prefixes(input, normalized, error) &&
                    normalized == std::vector<std::string>{"203.0.113.7/32", "192.168.1.0/24"},
                "Prefix normalization or stable deduplication failed");
        std::vector<std::string> excessive(max_ipv4_exemptions + 1, "192.0.2.1");
        require(!normalizeIpv4Prefixes(excessive, normalized, error) &&
                    error == "At most 256 destination exemptions are supported",
                "Exemption limit was not enforced");
        std::cout << "PASS: portable IPv4 prefix parsing, matching and normalization\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
