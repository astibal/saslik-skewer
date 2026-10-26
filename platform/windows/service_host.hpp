#pragma once
#include <windows.h>
#include <functional>
#include <string>

namespace skewer::windows {
// One host per process. The worker owns its resources and must observe the
// borrowed manual-reset stop event. Return zero on success, otherwise a stable
// service-specific failure code. No routing or privilege policy is implied.
using ServiceWorker = std::function<DWORD(HANDLE)>;
int runService(const std::wstring& name, ServiceWorker worker);
} // namespace skewer::windows
