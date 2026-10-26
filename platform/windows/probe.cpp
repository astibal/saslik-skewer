#include "processes.hpp"
#include <shellapi.h>
#include <algorithm>
#include <iostream>
#include <stdexcept>

using namespace skewer::windows;

namespace {
void require(bool condition, const char* description) {
    if (!condition) {
        throw std::runtime_error(description);
    }
}

std::string jsonString(std::wstring_view value) {
    const auto bytes = utf8(value);
    std::string result = "\"";
    constexpr char hex[] = "0123456789abcdef";
    for (unsigned char byte : bytes) {
        if (byte == '"' || byte == '\\') {
            result += '\\';
            result += char(byte);
        } else if (byte < 32) {
            result += "\\u00";
            result += hex[byte >> 4];
            result += hex[byte & 15];
        } else {
            result += char(byte);
        }
    }
    return result + '"';
}

// A test owns this child, not an arbitrary PID. Always reap it on failure.
struct Child {
    PROCESS_INFORMATION information;
    ~Child() {
        TerminateProcess(information.hProcess, 0);
        WaitForSingleObject(information.hProcess, 5000);
        CloseHandle(information.hThread);
        CloseHandle(information.hProcess);
    }
};

struct Window {
    HWND handle{};
    ~Window() {
        if (handle) {
            DestroyWindow(handle);
        }
    }
};

void testCommandLine() {
    const std::vector<std::wstring> arguments = {L"",
                                                 L"two words",
                                                 L"quote\"inside",
                                                 L"C:\\space dir\\",
                                                 L"\\\"",
                                                 L"\u017elu\u0165ou\u010dk\u00fd",
                                                 L"& echo not-a-shell"};
    auto line = commandLine(L"C:\\Program Files\\Skewer\\probe.exe", arguments);
    int count = 0;
    auto decoded = CommandLineToArgvW(line.c_str(), &count);
    require(decoded != nullptr, "CommandLineToArgvW failed");
    bool equal = count == static_cast<int>(arguments.size() + 1);
    for (size_t i = 0; equal && i < arguments.size(); ++i) {
        equal = arguments[i] == decoded[i + 1];
    }
    LocalFree(decoded);
    require(equal, "Windows command-line roundtrip failed");
    require(utf8(L"\u017e") == "\xc5\xbe", "Unicode conversion failed");
    require(jsonString(L"a\n\"\\") == "\"a\\u000a\\\"\\\\\"", "JSON escaping failed");
    bool rejected = false;
    try {
        launch(L"", {});
    } catch (const std::invalid_argument&) {
        rejected = true;
    }
    require(rejected, "Empty executable accepted");
    rejected = false;
    try {
        launch(L"C:\\missing.exe", {std::wstring(L"a\0b", 3)});
    } catch (const std::invalid_argument&) {
        rejected = true;
    }
    require(rejected, "Embedded NUL accepted");
}

void testProcessSnapshot() {
    std::wstring executable(32768, L'\0');
    DWORD size = GetModuleFileNameW(nullptr, executable.data(), static_cast<DWORD>(executable.size()));
    require(size && size < executable.size(), "Cannot resolve test executable");
    executable.resize(size);
    Child child{launch(executable, {L"--child"})};
    const auto expected_child = processKey(child.information.hProcess, child.information.dwProcessId);
    const auto expected_self = processKey(GetCurrentProcess(), GetCurrentProcessId());
    const std::wstring title = L"Skewer native window test";
    Window window{CreateWindowExW(WS_EX_APPWINDOW, L"STATIC", title.c_str(), WS_OVERLAPPEDWINDOW | WS_VISIBLE,
                                  0, 0, 200, 100, nullptr, nullptr, GetModuleHandleW(nullptr), nullptr)};
    require(window.handle != nullptr, "Cannot create test window in current desktop");
    auto snapshot = scanCurrentUser();
    const auto self = std::find_if(snapshot.processes.begin(), snapshot.processes.end(),
                                   [&](const Process& p) { return p.key == expected_self; });
    const auto found = std::find_if(snapshot.processes.begin(), snapshot.processes.end(),
                                    [&](const Process& p) { return p.key == expected_child; });
    require(self != snapshot.processes.end(), "Current user scan omitted itself");
    require(found != snapshot.processes.end(), "Current user scan omitted launched child");
    require(found->parent == expected_self.pid, "Child parent identity mismatch");
    require(!found->executable.empty(), "Child executable path missing");
    if (snapshot.window_enumeration_available) {
        require(std::find(self->window_titles.begin(), self->window_titles.end(), title) !=
                    self->window_titles.end(),
                "Visible top-level window not associated with its process");
        ShowWindow(window.handle, SW_HIDE);
        const auto hidden_snapshot = scanCurrentUser();
        const auto hidden_self =
            std::find_if(hidden_snapshot.processes.begin(), hidden_snapshot.processes.end(),
                         [&](const Process& p) { return p.key == expected_self; });
        require(hidden_self != hidden_snapshot.processes.end(), "Hidden window scan omitted process");
        require(std::find(hidden_self->window_titles.begin(), hidden_self->window_titles.end(), title) ==
                    hidden_self->window_titles.end(),
                "Hidden window was presented as a visible application");
    } else {
        std::cout << "SKIP: visible/hidden windows (noninteractive window station)\n";
    }
    for (const auto& p : snapshot.processes) {
        require(p.key.created != 0, "Missing creation time");
        require(p.parent != p.key.pid, "Self-parent cycle");
    }

    if (snapshot.window_enumeration_available) {
        std::cout << "PASS: visible/hidden windows\n";
    }
}

void testHandleLifetime() {
    // Repeated polling must not leak process, token or snapshot handles.
    DWORD before = 0, after = 0;
    require(GetProcessHandleCount(GetCurrentProcess(), &before), "Handle count unavailable");
    for (unsigned i = 0; i < 8; ++i) {
        scanCurrentUser();
    }
    require(GetProcessHandleCount(GetCurrentProcess(), &after), "Handle count unavailable");
    require(after <= before + 2, "Process scanner leaks handles");
}

void selfTest() {
    testCommandLine();
    testProcessSnapshot();
    testHandleLifetime();
    std::cout << "PASS: quoting, Unicode/JSON, invalid arguments, launch, identity, parent linkage, repeated "
                 "scan and handle lifetime\n";
}

void printSnapshot(const Snapshot& snapshot) {
    std::cout << "{\"routingSupported\":false,\"windowEnumerationAvailable\":"
              << (snapshot.window_enumeration_available ? "true" : "false")
              << ",\"inaccessible\":" << snapshot.inaccessible << ",\"otherUsers\":" << snapshot.other_users
              << ",\"processes\":[";
    bool first = true;
    for (const auto& process : snapshot.processes) {
        if (!first) {
            std::cout << ',';
        }
        first = false;
        std::cout << "{\"pid\":" << process.key.pid << ",\"created\":\"" << process.key.created
                  << "\",\"parent\":" << process.parent << ",\"session\":" << process.session
                  << ",\"name\":" << jsonString(process.name)
                  << ",\"executable\":" << jsonString(process.executable) << ",\"windows\":[";
        bool first_title = true;
        for (const auto& title : process.window_titles) {
            if (!first_title) {
                std::cout << ',';
            }
            first_title = false;
            std::cout << jsonString(title);
        }
        std::cout << "]}";
    }
    std::cout << "]}\n";
}
} // namespace

int wmain(int argc, wchar_t** argv) {
    try {
        if (argc == 2 && std::wstring_view(argv[1]) == L"--child") {
            Sleep(30000);
            return 0;
        }
        if (argc == 2 && std::wstring_view(argv[1]) == L"--self-test") {
            selfTest();
            return 0;
        }
        if (argc == 1 || (argc == 2 && std::wstring_view(argv[1]) == L"--json")) {
            printSnapshot(scanCurrentUser());
            return 0;
        }
        std::cerr << "Usage: skewer-process-probe [--json|--self-test]\n";
        return 2;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
