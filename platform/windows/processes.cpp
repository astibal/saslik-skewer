#include "processes.hpp"
#include <tlhelp32.h>
#include <algorithm>
#include <stdexcept>
#include <unordered_map>
#include <sddl.h>
#include <memory>

namespace skewer::windows {
namespace {
[[noreturn]] void fail(const char* operation) {
    throw std::runtime_error(std::string(operation) + ": Win32 error " + std::to_string(GetLastError()));
}

std::vector<unsigned char> tokenUserSid(HANDLE token) {
    DWORD length = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &length);
    if (!length) {
        return {};
    }
    std::vector<unsigned char> information(length);
    if (!GetTokenInformation(token, TokenUser, information.data(), length, &length)) {
        return {};
    }
    auto sid = reinterpret_cast<TOKEN_USER*>(information.data())->User.Sid;
    if (!IsValidSid(sid)) {
        return {};
    }
    std::vector<unsigned char> result(GetLengthSid(sid));
    if (!CopySid(static_cast<DWORD>(result.size()), result.data(), sid)) {
        return {};
    }
    return result;
}

std::vector<unsigned char> userSid(HANDLE process) {
    HANDLE raw = nullptr;
    if (!OpenProcessToken(process, TOKEN_QUERY, &raw)) {
        return {};
    }
    Handle token(raw);
    return tokenUserSid(token.get());
}

std::vector<unsigned char> authenticatedSid(HANDLE token) {
    TOKEN_TYPE type{};
    DWORD size{};
    if (!token || token == INVALID_HANDLE_VALUE ||
        !GetTokenInformation(token, TokenType, &type, sizeof(type), &size)) {
        throw std::invalid_argument("A queryable authenticated token is required");
    }
    if (type == TokenImpersonation) {
        SECURITY_IMPERSONATION_LEVEL level{};
        if (!GetTokenInformation(token, TokenImpersonationLevel, &level, sizeof(level), &size) ||
            level < SecurityIdentification) {
            throw std::invalid_argument("Anonymous client tokens cannot select applications");
        }
    } else if (type != TokenPrimary) {
        throw std::invalid_argument("Unsupported client token type");
    }
    const auto sid = tokenUserSid(token);
    if (sid.empty()) {
        throw std::runtime_error("Cannot determine authenticated client identity");
    }
    return sid;
}

HANDLE openTarget(ProcessKey expected) {
    if (expected.pid == 0 || expected.created == 0) {
        throw std::invalid_argument("Process selection requires PID and creation time");
    }
    // Inheritance is disabled: unrelated launched applications must not retain
    // our reference or gain access to another selected process.
    const auto process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, expected.pid);
    if (!process) {
        fail("Open selected process");
    }
    return process;
}

std::wstring processExecutable(HANDLE process) {
    std::wstring path(32768, L'\0');
    DWORD size = static_cast<DWORD>(path.size());
    if (!QueryFullProcessImageNameW(process, 0, path.data(), &size)) {
        fail("Read selected process executable");
    }
    if (size == 0) {
        throw std::runtime_error("Selected process has no executable identity");
    }
    path.resize(size);
    return path;
}

struct WindowsContext {
    std::unordered_map<DWORD, Process*> processes;
    bool failed{};
};

BOOL CALLBACK collectWindow(HWND window, LPARAM parameter) {
    auto& context = *reinterpret_cast<WindowsContext*>(parameter);
    // Never let a C++ exception unwind through a Win32 callback.
    try {
        if (!IsWindowVisible(window) || GetWindow(window, GW_OWNER) ||
            (GetWindowLongPtrW(window, GWL_EXSTYLE) & WS_EX_TOOLWINDOW)) {
            return TRUE;
        }
        DWORD pid = 0;
        GetWindowThreadProcessId(window, &pid);
        const auto found = context.processes.find(pid);
        if (found == context.processes.end()) {
            return TRUE;
        }
        // Windows can disappear while enumerating. Bound allocation and accept
        // a missing title instead of attempting cross-process message calls.
        const int length = std::min(GetWindowTextLengthW(window), 4096);
        if (length <= 0) {
            return TRUE;
        }
        std::wstring title(static_cast<size_t>(length) + 1, L'\0');
        const int copied = GetWindowTextW(window, title.data(), static_cast<int>(title.size()));
        if (copied <= 0) {
            return TRUE;
        }
        title.resize(static_cast<size_t>(copied));
        auto& titles = found->second->window_titles;
        if (std::find(titles.begin(), titles.end(), title) == titles.end()) {
            titles.push_back(std::move(title));
        }
        return TRUE;
    } catch (...) {
        context.failed = true;
        return FALSE;
    }
}
} // namespace

ProcessKey processKey(HANDLE process, DWORD pid) {
    const auto actual_pid = GetProcessId(process);
    if (!actual_pid) {
        fail("GetProcessId");
    }
    if (actual_pid != pid) {
        throw std::invalid_argument("Process handle does not match the requested PID");
    }
    FILETIME creation{}, exit{}, kernel{}, user{};
    if (!GetProcessTimes(process, &creation, &exit, &kernel, &user)) {
        fail("GetProcessTimes");
    }
    return {pid, (std::uint64_t(creation.dwHighDateTime) << 32) | creation.dwLowDateTime};
}

ProcessTarget::ProcessTarget(ProcessKey expected) : process_(openTarget(expected)), key_(expected) {
    validateOwner(userSid(GetCurrentProcess()));
}

ServiceOwner::ServiceOwner(const std::wstring& sid) {
    PSID raw{};
    if (sid.empty() || sid.size() > 184 || !ConvertStringSidToSidW(sid.c_str(), &raw)) {
        throw std::invalid_argument("Invalid service owner SID");
    }
    std::unique_ptr<void, decltype(&LocalFree)> parsed(raw, LocalFree);
    LPWSTR encoded{};
    if (!IsValidSid(raw) || !ConvertSidToStringSidW(raw, &encoded)) {
        throw std::invalid_argument("Invalid service owner SID");
    }
    std::unique_ptr<wchar_t, decltype(&LocalFree)> canonical(encoded, LocalFree);
    if (sid != encoded) {
        throw std::invalid_argument("Service owner SID must be canonical");
    }
    text_ = sid;
    bytes_.resize(GetLengthSid(raw));
    if (!CopySid(static_cast<DWORD>(bytes_.size()), bytes_.data(), raw)) {
        fail("Copy service owner SID");
    }
}

ServiceOwner ServiceOwner::fromToken(HANDLE token) {
    auto bytes = authenticatedSid(token);
    LPWSTR encoded{};
    if (bytes.empty() || !ConvertSidToStringSidW(bytes.data(), &encoded)) {
        throw std::invalid_argument("Cannot read service owner token");
    }
    std::unique_ptr<wchar_t, decltype(&LocalFree)> text(encoded, LocalFree);
    return ServiceOwner(text.get());
}

ProcessTarget::ProcessTarget(ProcessKey expected, const ServiceOwner& owner)
    : process_(openTarget(expected)), key_(expected) {
    validateOwner(owner.bytes_);
}

ProcessTarget::ProcessTarget(ProcessKey expected, HANDLE authenticated_user_token)
    : process_(openTarget(expected)), key_(expected) {
    validateOwner(authenticatedSid(authenticated_user_token));
}

void ProcessTarget::validateOwner(const std::vector<unsigned char>& caller) {
    if (processKey(process_.get(), key_.pid) != key_) {
        throw std::runtime_error("Selected process identity is stale; refresh the process list");
    }
    const auto owner = userSid(process_.get());
    if (caller.empty() || owner.empty() || caller != owner) {
        throw std::runtime_error("Selected process does not belong to the authenticated user");
    }
    executable_ = processExecutable(process_.get());
    if (!running()) {
        throw std::runtime_error("Selected process has already exited");
    }
}

bool ProcessTarget::running() const {
    // STILL_ACTIVE is also a legal exit code. The process object's signalled
    // state is authoritative and does not confuse that code with liveness.
    const auto state = WaitForSingleObject(process_.get(), 0);
    if (state == WAIT_FAILED) {
        fail("Wait for selected process");
    }
    if (state != WAIT_TIMEOUT && state != WAIT_OBJECT_0) {
        throw std::runtime_error("Unexpected selected-process wait result");
    }
    return state == WAIT_TIMEOUT;
}

Snapshot scanCurrentUser() {
    const auto own_sid = userSid(GetCurrentProcess());
    if (own_sid.empty()) {
        throw std::runtime_error("Cannot determine current user SID");
    }
    FILETIME captured{};
    GetSystemTimeAsFileTime(&captured);
    const auto captured_at = (std::uint64_t(captured.dwHighDateTime) << 32) | captured.dwLowDateTime;
    Handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (!snapshot) {
        fail("CreateToolhelp32Snapshot");
    }
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    Snapshot result;
    if (!Process32FirstW(snapshot.get(), &entry)) {
        fail("Process32FirstW");
    }
    do {
        Handle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, entry.th32ProcessID));
        if (!process) {
            ++result.inaccessible;
            continue;
        }
        const auto sid = userSid(process.get());
        if (sid.empty()) {
            ++result.inaccessible;
            continue;
        }
        if (!EqualSid(const_cast<unsigned char*>(own_sid.data()), const_cast<unsigned char*>(sid.data()))) {
            ++result.other_users;
            continue;
        }
        Process item;
        try {
            item.key = processKey(process.get(), entry.th32ProcessID);
        } catch (const std::runtime_error&) {
            ++result.inaccessible;
            continue;
        }
        // Do not combine an old snapshot entry with a newly reused PID.
        if (item.key.created > captured_at) {
            ++result.inaccessible;
            continue;
        }
        item.parent = entry.th32ParentProcessID;
        if (!ProcessIdToSessionId(item.key.pid, &item.session)) {
            ++result.inaccessible;
            continue;
        }
        std::wstring path(32768, L'\0');
        DWORD size = static_cast<DWORD>(path.size());
        if (QueryFullProcessImageNameW(process.get(), 0, path.data(), &size)) {
            path.resize(size);
            item.executable = std::move(path);
        }
        item.name = entry.szExeFile;
        result.processes.push_back(std::move(item));
    } while (Process32NextW(snapshot.get(), &entry));
    if (GetLastError() != ERROR_NO_MORE_FILES) {
        fail("Process32NextW");
    }

    WindowsContext context;
    for (auto& process : result.processes) {
        context.processes.emplace(process.key.pid, &process);
    }
    for (auto& process : result.processes) {
        const auto parent = context.processes.find(process.parent);
        // An exited parent's PID may now identify an unrelated newer process.
        if (parent == context.processes.end() || process.parent == process.key.pid ||
            parent->second->key.created > process.key.created) {
            process.parent = 0;
        }
    }
    // Service/SSH sessions do not observe the user's interactive desktop.
    USEROBJECTFLAGS station_flags{};
    if (GetUserObjectInformationW(GetProcessWindowStation(), UOI_FLAGS, &station_flags, sizeof(station_flags),
                                  nullptr)) {
        result.window_enumeration_available = (station_flags.dwFlags & WSF_VISIBLE) != 0;
    }
    if (result.window_enumeration_available &&
        !EnumWindows(collectWindow, reinterpret_cast<LPARAM>(&context))) {
        if (context.failed) {
            throw std::runtime_error("Window enumeration callback failed");
        }
        fail("EnumWindows");
    }
    std::sort(result.processes.begin(), result.processes.end(), [](const Process& a, const Process& b) {
        if (a.window_titles.empty() != b.window_titles.empty()) {
            return !a.window_titles.empty();
        }
        return a.key.pid < b.key.pid;
    });
    return result;
}

std::wstring quoteArgument(std::wstring_view argument) {
    // Microsoft CRT quoting: double backslashes before a quote and before the
    // closing delimiter, preserving empty arguments and trailing backslashes.
    std::wstring result = L"\"";
    size_t slashes = 0;
    for (wchar_t ch : argument) {
        if (ch == L'\\') {
            ++slashes;
            continue;
        }
        result.append(ch == L'"' ? 2 * slashes + 1 : slashes, L'\\');
        slashes = 0;
        result += ch;
    }
    result.append(2 * slashes, L'\\');
    result += L'"';
    return result;
}

std::wstring commandLine(const std::wstring& executable, const std::vector<std::wstring>& arguments) {
    auto result = quoteArgument(executable);
    for (const auto& argument : arguments) {
        result += L" " + quoteArgument(argument);
    }
    return result;
}

PROCESS_INFORMATION launch(const std::wstring& executable, const std::vector<std::wstring>& arguments,
                           LaunchMode mode) {
    if (mode != LaunchMode::Running && mode != LaunchMode::Suspended) {
        throw std::invalid_argument("Invalid process launch mode");
    }
    if (executable.empty() || executable.find(L'\0') != std::wstring::npos) {
        throw std::invalid_argument("Executable must be nonempty and contain no NUL");
    }
    for (const auto& argument : arguments) {
        if (argument.find(L'\0') != std::wstring::npos) {
            throw std::invalid_argument("Argument contains NUL");
        }
    }
    auto line = commandLine(executable, arguments);
    if (line.size() >= 32767) {
        throw std::invalid_argument("Command line exceeds Windows limit");
    }
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION information{};
    // No inherited handles, shell expansion, admin token or hidden routing.
    const DWORD flags = mode == LaunchMode::Suspended ? CREATE_SUSPENDED : 0;
    if (!CreateProcessW(executable.c_str(), line.data(), nullptr, nullptr, FALSE, flags, nullptr, nullptr,
                        &startup, &information)) {
        fail("CreateProcessW");
    }
    return information;
}

std::string utf8(std::wstring_view value) {
    if (value.empty()) {
        return {};
    }
    const int size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
                                         static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    if (!size) {
        fail("WideCharToMultiByte");
    }
    std::string result(static_cast<size_t>(size), '\0');
    if (!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()),
                             result.data(), size, nullptr, nullptr)) {
        fail("WideCharToMultiByte");
    }
    return result;
}
} // namespace skewer::windows
