#include <windows.h>
#include <shellapi.h>
#include <sddl.h>
#include "service_installer.hpp"
#include "processes.hpp"
#include <QHostAddress>
#include <QHostInfo>
#include <QFileInfo>
#include <QUrl>
#include <algorithm>
#include <memory>
#include <stdexcept>
#include <vector>

namespace skewer::windows {
namespace {
QString windowsError(DWORD code) {
    wchar_t* raw{};
    const auto size = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                                         FORMAT_MESSAGE_IGNORE_INSERTS,
                                     nullptr, code, 0, reinterpret_cast<wchar_t*>(&raw), 0, nullptr);
    std::unique_ptr<wchar_t, decltype(&LocalFree)> text(raw, LocalFree);
    return size ? QString::fromWCharArray(raw, static_cast<int>(size)).trimmed()
                : QStringLiteral("Windows error %1").arg(code);
}

std::wstring currentSid() {
    HANDLE raw{};
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw))
        throw std::runtime_error("Cannot open current user token");
    Handle token(raw);
    DWORD size{};
    GetTokenInformation(token.get(), TokenUser, nullptr, 0, &size);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || !size)
        throw std::runtime_error("Cannot size current user SID");
    std::vector<unsigned char> bytes(size);
    if (!GetTokenInformation(token.get(), TokenUser, bytes.data(), size, &size))
        throw std::runtime_error("Cannot read current user SID");
    const auto* user = reinterpret_cast<const TOKEN_USER*>(bytes.data());
    wchar_t* raw_text{};
    if (!ConvertSidToStringSidW(user->User.Sid, &raw_text))
        throw std::runtime_error("Cannot encode current user SID");
    std::unique_ptr<wchar_t, decltype(&LocalFree)> text(raw_text, LocalFree);
    return text.get();
}

InstallerResult runElevated(const std::vector<std::wstring>& arguments, const QString& operation) {
    const auto parameters = commandLine(L"", arguments).substr(3); // Drop the quoted empty executable.
    SHELLEXECUTEINFOW info{sizeof(info)};
    info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
    info.lpVerb = L"runas";
    info.lpFile = L"powershell.exe";
    info.lpParameters = parameters.c_str();
    info.nShow = SW_SHOWNORMAL;
    if (!ShellExecuteExW(&info)) return {0, windowsError(GetLastError())};
    Handle process(info.hProcess);
    if (WaitForSingleObject(process.get(), INFINITE) != WAIT_OBJECT_0)
        return {0, QStringLiteral("Cannot wait for elevated %1").arg(operation)};
    DWORD exit_code{};
    if (!GetExitCodeProcess(process.get(), &exit_code))
        return {0, windowsError(GetLastError())};
    return {exit_code, exit_code ? QStringLiteral("Elevated %1 exited with code %2")
                                      .arg(operation).arg(exit_code)
                                 : QString{}};
}
} // namespace

bool routingServiceInstalled(const QString& name) {
    const auto manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!manager) return false;
    const auto service = OpenServiceW(manager, name.toStdWString().c_str(), SERVICE_QUERY_STATUS);
    if (service) CloseServiceHandle(service);
    CloseServiceHandle(manager);
    return service != nullptr;
}

QString selectBootstrapIpv4(const QString& host, const QList<QHostAddress>& addresses) {
    QHostAddress literal;
    if (literal.setAddress(host)) {
        if (literal.protocol() != QAbstractSocket::IPv4Protocol || literal.isNull() ||
            literal.isLoopback() || literal.isMulticast()) {
            throw std::invalid_argument("Tunnel endpoint must resolve to a unicast non-loopback IPv4 address");
        }
        return literal.toString();
    }
    QStringList candidates;
    for (const auto& address : addresses) {
        if (address.protocol() == QAbstractSocket::IPv4Protocol && !address.isNull() &&
            !address.isLoopback() && !address.isMulticast()) {
            candidates.push_back(address.toString());
        }
    }
    candidates.removeDuplicates();
    std::sort(candidates.begin(), candidates.end());
    if (candidates.isEmpty()) {
        throw std::runtime_error("Tunnel endpoint DNS bootstrap returned no usable IPv4 address");
    }
    return candidates.front();
}

InstallerResult runRoutingServiceInstaller(const QString& script, const QString& package,
                                           const QString& service, const QString& endpoint,
                                           bool upgrade) {
    try {
        if (service != QStringLiteral("SkewerRouting"))
            throw std::invalid_argument("The desktop installer manages only the production SkewerRouting service");
        if (!QFileInfo(script).isFile() || !QFileInfo(package).isDir())
            throw std::invalid_argument("The packaged routing service installer is incomplete");
        std::vector<std::wstring> arguments{L"-NoProfile", L"-ExecutionPolicy", L"Bypass", L"-File",
                                             script.toStdWString(), L"-PackageDirectory", package.toStdWString(),
                                             L"-OwnerSid", currentSid()};
        if (!endpoint.trimmed().isEmpty()) {
            const QUrl url(endpoint);
            if (!url.isValid() || url.scheme() != QStringLiteral("skewer") ||
                url.host().isEmpty() || url.path() != QStringLiteral("/pair") ||
                url.port() <= 0 || url.port() > 65535 ||
                !url.userInfo().isEmpty() || url.hasQuery() || url.hasFragment()) {
                throw std::invalid_argument(
                    "Tunnel-ready installation requires a valid paired endpoint");
            }
            QHostAddress literal;
            const auto addresses = literal.setAddress(url.host())
                                       ? QList<QHostAddress>{literal}
                                       : QHostInfo::fromName(url.host()).addresses();
            const auto peer = selectBootstrapIpv4(url.host(), addresses);
            arguments.insert(arguments.end(), {L"-Endpoint", endpoint.toStdWString(),
                                               L"-Peer", peer.toStdWString()});
        }
        if (upgrade) arguments.push_back(L"-Upgrade");
        return runElevated(arguments, QStringLiteral("installer"));
    } catch (const std::exception& error) {
        return {0, QString::fromUtf8(error.what())};
    }
}

InstallerResult runRoutingServiceRemover(const QString& script, const QString& service) {
    try {
        if (service != QStringLiteral("SkewerRouting"))
            throw std::invalid_argument("The desktop remover manages only the production SkewerRouting service");
        if (!QFileInfo(script).isFile())
            throw std::invalid_argument("The packaged routing service remover is missing");
        const std::vector<std::wstring> arguments{L"-NoProfile", L"-ExecutionPolicy", L"Bypass", L"-File",
                                                  script.toStdWString(), L"-Name", service.toStdWString(),
                                                  L"-Confirm:$false"};
        return runElevated(arguments, QStringLiteral("remover"));
    } catch (const std::exception& error) {
        return {0, QString::fromUtf8(error.what())};
    }
}
} // namespace skewer::windows
