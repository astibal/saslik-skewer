#pragma once

#include <windows.h>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
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

// A checked reference to exactly one current-user process instance. Acquiring
// it neither changes network policy nor grants terminate/inject privileges.
// The handle remains bound to that process object after exit; it never follows
// a recycled PID. Separate consumers can use this identity without a tunnel.
// Stable, administrator-configured owner for a service. Never accept this SID
// from a pipe request. Unlike an installer PID/token it survives logon changes.
class ServiceOwner final {
public:
    explicit ServiceOwner(const std::wstring& sid);
    static ServiceOwner fromToken(HANDLE token);
    const std::wstring& sid() const { return text_; }

private:
    friend class ProcessTarget;
    std::wstring text_;
    std::vector<unsigned char> bytes_;
};

class ProcessTarget final {
public:
    explicit ProcessTarget(ProcessKey expected);
    // Service boundary: token must come from authenticated OS IPC, never from
    // request fields or a caller-supplied SID/PID. Borrowed only during validation.
    // The service's own account is deliberately not used as the caller identity.
    ProcessTarget(ProcessKey expected, HANDLE authenticated_user_token);
    ProcessTarget(ProcessKey expected, const ServiceOwner& configured_owner);
    ProcessTarget(const ProcessTarget&) = delete;
    ProcessTarget& operator=(const ProcessTarget&) = delete;

    const ProcessKey& key() const { return key_; }
    const std::wstring& executable() const { return executable_; }
    bool running() const;
    // Borrowed wait handle: do not close it or retain it beyond this object.
    HANDLE waitHandle() const { return process_.get(); }

private:
    void validateOwner(const std::vector<unsigned char>& caller);
    Handle process_;
    ProcessKey key_;
    std::wstring executable_;
};

Snapshot scanCurrentUser();
ProcessKey processKey(HANDLE process, DWORD pid);
std::wstring quoteArgument(std::wstring_view argument);
std::wstring commandLine(const std::wstring& executable, const std::vector<std::wstring>& arguments);

// No shell, no elevation, no network policy changes. The caller owns handles
// returned in PROCESS_INFORMATION and must close them after observing launch.
// Suspended mode additionally requires the caller to resume or terminate its
// child; closing handles alone deliberately does neither.
enum class LaunchMode { Running, Suspended };
enum class LaunchConsole { Inherit, New };
using EnvironmentOverrides = std::vector<std::pair<std::wstring, std::wstring>>;
PROCESS_INFORMATION launch(const std::wstring& executable, const std::vector<std::wstring>& arguments,
                           LaunchMode mode = LaunchMode::Running,
                           const EnvironmentOverrides& environment = {},
                           LaunchConsole console = LaunchConsole::Inherit);
std::string utf8(std::wstring_view value);

} // namespace skewer::windows
