#include "selected_service_tunnel.hpp"
#include <QCoreApplication>
#include <QDir>
#include <iostream>

using namespace skewer::windows;
namespace {
class FailingControl final : public TunnelControl {
public:
    FailingControl(HANDLE cancel, RoutingSignals& state, bool pause_recovery)
        : cancel_(cancel), state_(state), pause_recovery_(pause_recovery) {}
    PairedTunnel open() override {
        ++opens;
        if (pause_recovery_) {
            if (opens == 1) {
                request_ = std::make_shared<PauseChange>(true);
                state_.pause_change = request_;
            } else {
                const bool expected_paused = opens < 4;
                if (!request_ || request_->phase != PauseChange::Phase::Complete ||
                    !request_->error.empty() || state_.paused != expected_paused ||
                    state_.ready || !state_.blocked) {
                    failure = "Recovery lost acknowledged pause intent or claimed readiness";
                    SetEvent(cancel_);
                    throw std::runtime_error(failure);
                }
                ++verified;
                if (opens == 3) {
                    // Resume during transport failure must not publish Active.
                    request_ = std::make_shared<PauseChange>(false);
                    state_.pause_change = request_;
                }
            }
        }
        if (opens >= (pause_recovery_ ? 4U : 3U)) {
            SetEvent(cancel_);
            throw std::runtime_error("fixture complete");
        }
        Tuntom::Endpoint endpoint;
        endpoint.id = 1;
        endpoint.leaseSeconds = 1;
        endpoint.context = "fixture";
        endpoint.serverAddress = "10.253.0.1/30";
        endpoint.clientAddress = "10.253.0.2/30";
        return {endpoint, QByteArray(16, '\x42')};
    }
    void renew(const Tuntom::Endpoint&) override { throw std::runtime_error("injected renewal loss"); }
    void close(const Tuntom::Endpoint&) override { ++closes; }
    unsigned opens{}, closes{}, verified{};
    std::string failure;

private:
    HANDLE cancel_;
    RoutingSignals& state_;
    bool pause_recovery_;
    std::shared_ptr<PauseChange> request_;
};
} // namespace

int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    try {
        if (app.arguments().size() == 2 && app.arguments()[1] == "--child") {
            Sleep(20000);
            return 0;
        }
        Handle cancel(CreateEventW(nullptr, TRUE, FALSE, nullptr));
        if (!cancel) throw std::runtime_error("Cannot create fixture cancellation event");
        const auto child = launch(app.applicationFilePath().toStdWString(), {L"--child"});
        Handle child_process(child.hProcess), child_thread(child.hThread);
        struct StopChild {
            HANDLE process;
            ~StopChild() {
                if (WaitForSingleObject(process, 0) == WAIT_TIMEOUT) {
                    TerminateProcess(process, 0);
                    WaitForSingleObject(process, 2000);
                }
            }
        } stop_child{child_process.get()};
        const auto identity = processKey(child_process.get(), child.dwProcessId);
        HANDLE token_raw{};
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token_raw)) {
            throw std::runtime_error("Cannot open fixture token");
        }
        Handle token(token_raw);
        const auto owner = ServiceOwner::fromToken(token.get());
        RoutingSignals state;
        const bool pause_recovery = app.arguments().size() == 2 && app.arguments()[1] == "--pause-recovery";
        if (app.arguments().size() != 1 && !pause_recovery)
            throw std::invalid_argument("Expected no arguments or --pause-recovery");
        FailingControl control(cancel.get(), state, pause_recovery);
        const auto dll = QDir::toNativeSeparators(app.applicationDirPath() + "/WinDivert.dll").toStdWString();
        runSelectedServiceTunnel(dll, std::make_unique<ProcessTarget>(identity), owner, control,
                                 QStringLiteral("127.0.0.1"), 8766, {}, cancel.get(), state);
        if (!control.failure.empty()) throw std::runtime_error(control.failure);
        if (control.opens < 3 || control.closes < 2 || state.ready.load() || !state.blocked.load()) {
            throw std::runtime_error("Reconnect did not preserve blocked state and retry ownership");
        }
        if (pause_recovery && (control.verified != 3 || state.paused)) {
            throw std::runtime_error("Pause/recovery checkpoints did not complete");
        }
        if (pause_recovery)
            std::cout << "PASS: acknowledged pause survives replacement sessions; Resume during failure remains blocked\n";
        std::cout << "PASS: selected capture survives transport loss and retries until cancellation\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL: " << error.what() << '\n';
        return 1;
    }
}
