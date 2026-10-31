#include "application_icons.hpp"
#include <QGuiApplication>
#include <windows.h>
#include <future>
#include <iostream>
#include <stdexcept>

int main(int argc, char** argv) {
    QGuiApplication app(argc, argv);
    try {
        auto worker = std::async(std::launch::async, [] {
            skewer::windows::ApplicationIcons icons;
            if (!icons.lookup(L"\\\\invalid.example\\unread.exe").isNull() ||
                !icons.lookup(L"relative.exe").isNull() || !icons.lookup(L"").isNull()) {
                throw std::runtime_error("Unsafe or absent path produced an icon");
            }
            wchar_t directory[MAX_PATH]{};
            const auto length = GetSystemDirectoryW(directory, MAX_PATH);
            if (!length || length >= MAX_PATH) throw std::runtime_error("Cannot locate system resources");
            const auto path = std::wstring(directory) + L"\\shell32.dll";
            const auto first = icons.lookup(path);
            if (first.isNull() || first.width() > 32 || first.height() > 32) {
                throw std::runtime_error("Missing or unbounded native icon");
            }
            const auto handles = GetGuiResources(GetCurrentProcess(), GR_GDIOBJECTS);
            const auto user_handles = GetGuiResources(GetCurrentProcess(), GR_USEROBJECTS);
            for (unsigned i = 0; i < 1000; ++i) {
                if (icons.lookup(path).cacheKey() != first.cacheKey()) {
                    throw std::runtime_error("Icon was decoded again instead of cached");
                }
            }
            // Recreate caches as well: cached lookups alone cannot expose a
            // leaked HICON from the native extraction path.
            for (unsigned i = 0; i < 32; ++i) {
                skewer::windows::ApplicationIcons fresh;
                if (fresh.lookup(path).isNull()) throw std::runtime_error("Fresh icon extraction failed");
            }
            if (GetGuiResources(GetCurrentProcess(), GR_GDIOBJECTS) > handles + 2 ||
                GetGuiResources(GetCurrentProcess(), GR_USEROBJECTS) > user_handles + 2) {
                throw std::runtime_error("Repeated icon extraction leaked GDI/USER objects");
            }
            return first;
        });
        if (worker.get().isNull()) throw std::runtime_error("Worker image was lost");
        std::cout << "PASS: worker-owned native icons, bounded images, cache and safe fallback\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL: " << error.what() << '\n';
        return 1;
    }
}
