#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace skewer::traffic {

inline constexpr std::size_t max_ipv4_exemptions = 256;

struct Ipv4Prefix final {
    std::uint32_t network{};
    std::uint8_t length{};

    [[nodiscard]] bool contains(std::uint32_t address) const;
    [[nodiscard]] std::string addressText() const;
    [[nodiscard]] std::string text() const;
    bool operator==(const Ipv4Prefix&) const = default;
};

[[nodiscard]] bool parseIpv4Prefix(std::string_view value, Ipv4Prefix& prefix);
[[nodiscard]] bool normalizeIpv4Prefixes(std::span<const std::string> input,
                                         std::vector<std::string>& output,
                                         std::string& error);

} // namespace skewer::traffic
