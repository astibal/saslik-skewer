#include "processes.hpp"
#include "selection_auth.hpp"
#include <sddl.h>
#include <iostream>
#include <stdexcept>

namespace {
using namespace skewer::windows;
void require(bool ok, const char* message) {
    if (!ok) {
        throw std::runtime_error(message);
    }
}
template <typename Action> void rejects(Action action, const char* message) {
    bool rejected{};
    try {
        action();
    } catch (const std::exception&) {
        rejected = true;
    }
    require(rejected, message);
}
void test() {
    const auto key = processKey(GetCurrentProcess(), GetCurrentProcessId());
    HANDLE raw{};
    require(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &raw), "Open test token");
    Handle primary(raw);
    ProcessTarget own(key, primary.get());
    require(own.running() && own.key() == key, "Primary token selection failed");
    HANDLE identified{};
    require(DuplicateTokenEx(primary.get(), TOKEN_QUERY, nullptr, SecurityIdentification, TokenImpersonation,
                             &identified),
            "Create identification token");
    {
        Handle token(identified);
        ProcessTarget selected(key, token.get());
        require(selected.running(), "Identification-level selection failed");
    }
    rejects([&] { ProcessTarget target(key, nullptr); }, "Null token accepted");
    rejects([&] { ProcessTarget target(key, INVALID_HANDLE_VALUE); }, "Invalid token accepted");
    rejects([&] { ProcessTarget target(key, GetCurrentProcess()); }, "Process handle accepted as token");
    auto stale = key;
    ++stale.created;
    rejects([&] { ProcessTarget target(stale, primary.get()); }, "Stale identity accepted");
    HANDLE anonymous{};
    require(DuplicateTokenEx(primary.get(), TOKEN_QUERY, nullptr, SecurityAnonymous, TokenImpersonation,
                             &anonymous),
            "Create anonymous token");
    Handle anonymous_token(anonymous);
    rejects([&] { ProcessTarget target(key, anonymous_token.get()); }, "Anonymous token accepted");
    // Handle lifetime is independent of the borrowed authorization token.
    require(own.running(), "Pinned process was lost");
}
void pipeTest(const ProcessKey* foreign = nullptr) {
    const auto key = processKey(GetCurrentProcess(), GetCurrentProcessId());
    const auto name = L"\\\\.\\pipe\\SkewerAuthFixture-" + std::to_wstring(key.pid) + L"-" +
                      std::to_wstring(GetTickCount64());
    PSECURITY_DESCRIPTOR raw{};
    require(ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;;GA;;;SY)(A;;GRGW;;;OW)",
                                                                 SDDL_REVISION_1, &raw, nullptr),
            "Create fixture pipe ACL");
    std::shared_ptr<void> descriptor(raw, [](void* value) { LocalFree(value); });
    SECURITY_ATTRIBUTES security{sizeof(security), raw, FALSE};
    Handle server(
        CreateNamedPipeW(name.c_str(), PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                         PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                         1, 64, 64, 3000, &security));
    require(static_cast<bool>(server), "Create local fixture pipe");
    Handle client(CreateFileW(name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
                              SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, nullptr));
    require(static_cast<bool>(client), "Connect identification-level client");
    require(ConnectNamedPipe(server.get(), nullptr) || GetLastError() == ERROR_PIPE_CONNECTED,
            "Accept local client");
    const std::uint8_t request = 1;
    DWORD transferred{};
    require(WriteFile(client.get(), &request, sizeof(request), &transferred, nullptr) && transferred == 1,
            "Write fixture request");
    std::uint8_t received{};
    require(ReadFile(server.get(), &received, sizeof(received), &transferred, nullptr) && transferred == 1,
            "Read fixture request");
    auto selected = authorizePipeSelection(server.get(), key);
    require(selected->running() && selected->key() == key, "Pipe identity did not authorize its process");
    auto stale = key;
    ++stale.created;
    rejects([&] { authorizePipeSelection(server.get(), stale); }, "Pipe accepted stale process");
    rejects([&] { authorizePipeSelection(client.get(), key); }, "Client handle accepted as server");
    if (foreign) {
        rejects([&] { authorizePipeSelection(server.get(), *foreign); }, "Foreign-user process accepted");
    }
    HANDLE token{};
    const bool impersonating = OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &token) != FALSE;
    const auto error = GetLastError();
    Handle unexpected(token);
    require(!impersonating && error == ERROR_NO_TOKEN, "Authorization leaked impersonation");
}
} // namespace
int main(int argc, char** argv) {
    try {
        test();
        if (argc == 1) {
            pipeTest();
        } else {
            require(argc == 3 && std::string(argv[1]) == "--foreign", "Invalid test arguments");
            const std::string number(argv[2]);
            require(!number.empty() && number.find_first_not_of("0123456789") == std::string::npos,
                    "Invalid foreign PID");
            const auto value = std::stoull(number);
            require(value > 0 && value <= MAXDWORD && value != GetCurrentProcessId(),
                    "Foreign PID out of range");
            const auto pid = static_cast<DWORD>(value);
            Handle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, pid));
            require(static_cast<bool>(process), "Cannot inspect foreign fixture");
            const auto foreign = processKey(process.get(), pid);
            pipeTest(&foreign);
            std::cout << "PASS: pipe client cannot select the foreign-user service fixture\n";
        }
        std::cout << "PASS: authenticated token selection and invalid/stale/anonymous rejection\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
