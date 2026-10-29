#pragma once
#include <QImage>
#include <string>
#include <unordered_map>

namespace skewer::windows {
// Inventory-worker owned. QImage can cross threads; QPixmap/QIcon cannot be
// constructed here. Missing resources are cached just like successful reads.
class ApplicationIcons final {
public:
    QImage lookup(const std::wstring& executable);
private:
    std::unordered_map<std::wstring, QImage> icons_;
};
} // namespace skewer::windows
