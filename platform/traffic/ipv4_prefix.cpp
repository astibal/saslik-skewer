#include "ipv4_prefix.hpp"

#include <algorithm>
#include <charconv>

namespace skewer::traffic {
namespace {

std::string_view trim(std::string_view value) {
    constexpr std::string_view whitespace = " \t\r\n\f\v";
    const auto first = value.find_first_not_of(whitespace);
    if (first == std::string_view::npos) return {};
    return value.substr(first, value.find_last_not_of(whitespace) - first + 1);
}

bool parseUnsigned(std::string_view value, unsigned maximum, unsigned& output) {
    if (value.empty()) return false;
    unsigned parsed{};
    const auto [end, error] = std::from_chars(value.data(), value.data() + value.size(), parsed);
    if (error != std::errc{} || end != value.data() + value.size() || parsed > maximum) return false;
    output = parsed;
    return true;
}

bool parseAddress(std::string_view value, std::uint32_t& output) {
    std::uint32_t address{};
    for (unsigned octet_index = 0; octet_index < 4; ++octet_index) {
        const auto separator = value.find('.');
        const bool last = octet_index == 3;
        if ((last && separator != std::string_view::npos) || (!last && separator == std::string_view::npos))
            return false;
        const auto octet_text = last ? value : value.substr(0, separator);
        unsigned octet{};
        if (!parseUnsigned(octet_text, 255, octet)) return false;
        address = (address << 8) | octet;
        if (!last) value.remove_prefix(separator + 1);
    }
    output = address;
    return true;
}

std::uint32_t mask(unsigned length) {
    return length == 0 ? 0 : 0xffffffffU << (32 - length);
}

} // namespace

bool Ipv4Prefix::contains(std::uint32_t address) const {
    return (address & mask(length)) == network;
}

std::string Ipv4Prefix::text() const {
    return std::to_string(network >> 24) + '.' + std::to_string((network >> 16) & 0xffU) + '.' +
           std::to_string((network >> 8) & 0xffU) + '.' + std::to_string(network & 0xffU) + '/' +
           std::to_string(length);
}

bool parseIpv4Prefix(std::string_view raw, Ipv4Prefix& prefix) {
    const auto value = trim(raw);
    const auto separator = value.find('/');
    if (separator != std::string_view::npos && value.find('/', separator + 1) != std::string_view::npos)
        return false;
    const auto address_text = separator == std::string_view::npos ? value : value.substr(0, separator);
    const auto length_text = separator == std::string_view::npos ? std::string_view{} : value.substr(separator + 1);
    unsigned length = 32;
    std::uint32_t address{};
    if (!parseAddress(address_text, address) ||
        (separator != std::string_view::npos && !parseUnsigned(length_text, 32, length))) {
        return false;
    }
    prefix = {address & mask(length), static_cast<std::uint8_t>(length)};
    return true;
}

bool normalizeIpv4Prefixes(std::span<const std::string> input, std::vector<std::string>& output,
                           std::string& error) {
    output.clear();
    error.clear();
    if (input.size() > max_ipv4_exemptions) {
        error = "At most 256 destination exemptions are supported";
        return false;
    }
    for (const auto& raw : input) {
        Ipv4Prefix prefix;
        if (!parseIpv4Prefix(raw, prefix)) {
            error = "Invalid IPv4 address or CIDR: " + std::string(trim(raw));
            output.clear();
            return false;
        }
        auto normalized = prefix.text();
        if (std::find(output.begin(), output.end(), normalized) == output.end())
            output.push_back(std::move(normalized));
    }
    return true;
}

} // namespace skewer::traffic
