#include "application_names.hpp"
#include <windows.h>
#include <vector>
#include <cwchar>

namespace skewer::windows {
namespace {
std::wstring description(const std::wstring& path) {
    // Do not trigger network I/O for UNC or device paths during inventory.
    if (path.size() < 3 || path[1] != L':' || path[2] != L'\\' ||
        GetDriveTypeW(path.substr(0, 3).c_str()) == DRIVE_REMOTE) return {};
    DWORD unused{};
    const auto size = GetFileVersionInfoSizeW(path.c_str(), &unused);
    if (!size || size > 1024 * 1024) return {};
    std::vector<unsigned char> data(size);
    if (!GetFileVersionInfoW(path.c_str(), 0, size, data.data())) return {};
    struct Translation { WORD language, codepage; };
    Translation* translations{};
    UINT length{};
    if (!VerQueryValueW(data.data(), L"\\VarFileInfo\\Translation",
                        reinterpret_cast<void**>(&translations), &length)) return {};
    for (UINT i = 0; i < length / sizeof(Translation); ++i) {
        wchar_t query[96]{};
        std::swprintf(query, 96, L"\\StringFileInfo\\%04x%04x\\FileDescription",
                      translations[i].language, translations[i].codepage);
        wchar_t* value{};
        UINT characters{};
        if (!VerQueryValueW(data.data(), query, reinterpret_cast<void**>(&value), &characters) ||
            !characters || characters > 256) continue;
        std::wstring result;
        for (UINT n = 0; n < characters && value[n]; ++n) {
            if (value[n] < 32 || value[n] == 127) return {};
            result.push_back(value[n]);
        }
        if (!result.empty()) return result;
    }
    return {};
}
} // namespace
std::wstring ApplicationNames::lookup(const std::wstring& executable, const std::wstring& fallback) {
    if (executable.empty()) return fallback;
    if (const auto found = names_.find(executable); found != names_.end())
        return found->second.empty() ? fallback : found->second;
    // Bound session memory and avoid repeatedly loading metadata, including
    // failures. The executable path remains separately visible in the UI.
    if (names_.size() >= 512) return fallback;
    auto name = description(executable);
    names_.emplace(executable, name);
    return name.empty() ? fallback : name;
}
} // namespace skewer::windows
