#include "application_icons.hpp"
#include <windows.h>
#include <shellapi.h>

namespace skewer::windows {
QImage ApplicationIcons::lookup(const std::wstring& executable) {
    if (executable.empty()) return {};
    if (const auto found = icons_.find(executable); found != icons_.end()) return found->second;
    if (icons_.size() >= 512) return {};
    QImage image;
    // Do not deliberately inspect UNC, device, mapped-network or removable paths.
    // Resource extraction reads the executable; it does not execute its code.
    if (executable.size() >= 3 && executable[1] == L':' && executable[2] == L'\\' &&
        GetDriveTypeW(executable.substr(0, 3).c_str()) == DRIVE_FIXED) {
        HICON icon{};
        const auto count = ExtractIconExW(executable.c_str(), 0, nullptr, &icon, 1);
        struct IconCleanup {
            HICON value;
            ~IconCleanup() { if (value) DestroyIcon(value); }
        } cleanup{icon};
        if (count == 1 && icon) {
            image = QImage::fromHICON(icon).scaled(32, 32, Qt::KeepAspectRatio, Qt::SmoothTransformation);
        }
    }
    icons_.emplace(executable, image);
    return image;
}
} // namespace skewer::windows
