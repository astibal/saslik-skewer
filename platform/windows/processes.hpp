#pragma once

#include <windows.h>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace skewer::windows {

// A PID alone is not an identity: Windows reuses process IDs.
struct ProcessKey {
    DWORD pid{};
    std::uint64_t created{};
    bool operator==(const ProcessKey&) const = default;
};

struct Process {
    ProcessKey key;
    DWORD parent{};
    DWORD session{};
    std::wstring executable;
    std::wstring name;
    std::vector<std::wstring> window_titles;
};

struct Snapshot {
    std::vector<Process> processes;
    bool window_enumeration_available{};
    unsigned inaccessible{};
    unsigned other_users{};
};

// Owns only handles created/opened by this backend, never a borrowed handle.
class Handle {
public:
    explicit Handle(HANDLE value = nullptr) : value_(value) {}
    ~Handle() {
        if (value_ && value_ != INVALID_HANDLE_VALUE) {
            CloseHandle(value_);
        }
    }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    HANDLE get() const { return value_; }
    explicit operator bool() const { return value_ && value_ != INVALID_HANDLE_VALUE; }

private:
    HANDLE value_;
};

Snapshot scanCurrentUser();
ProcessKey processKey(HANDLE process, DWORD pid);
std::wstring quoteArgument(std::wstring_view argument);
std::wstring commandLine(const std::wstring& executable, const std::vector<std::wstring>& arguments);

// No shell, no elevation, no network policy changes. The caller owns handles
// returned in PROCESS_INFORMATION and must close them after observing launch.
PROCESS_INFORMATION launch(const std::wstring& executable, const std::vector<std::wstring>& arguments);
std::string utf8(std::wstring_view value);

} // namespace skewer::windows
