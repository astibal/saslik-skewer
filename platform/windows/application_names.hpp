#pragma once
#include <string>
#include <unordered_map>

namespace skewer::windows {
// Owned by one inventory worker. Metadata is presentation only: never use it
// for process identity, routing authorization or launch-path resolution.
class ApplicationNames final {
public:
    std::wstring lookup(const std::wstring& executable, const std::wstring& fallback);
private:
    std::unordered_map<std::wstring, std::wstring> names_;
};
} // namespace skewer::windows
