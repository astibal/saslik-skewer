#include "application_names.hpp"
#include <windows.h>
#include <iostream>
#include <stdexcept>
using namespace skewer::windows;
int main() {
    try {
        ApplicationNames names;
        if (names.lookup(L"", L"fallback") != L"fallback" ||
            names.lookup(L"\\\\unreachable.invalid\\app.exe", L"network") != L"network" ||
            names.lookup(L"relative.exe", L"relative") != L"relative")
            throw std::runtime_error("Unsafe or missing path did not fall back");
        wchar_t system[MAX_PATH]{};
        if (!GetSystemDirectoryW(system, MAX_PATH)) throw std::runtime_error("System directory unavailable");
        const auto path = std::wstring(system) + L"\\kernel32.dll";
        const auto name = names.lookup(path, L"fallback");
        if (name.empty() || name == L"fallback" || names.lookup(path, L"other") != name)
            throw std::runtime_error("Native localized version metadata/cache failed");
        std::cout << "PASS: native application names, cached metadata and safe fallback\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
