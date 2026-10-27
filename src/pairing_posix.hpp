#pragma once
#include <QTcpSocket>
#include <QByteArray>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <csignal>
#include <pthread.h>
#include <stdexcept>

namespace PairingPlatform {
// Block socket BIO SIGPIPE on this worker only; never change process-wide
// signal policy or consume a signal that was already pending before the call.
struct SignalGuard {
    sigset_t previous{}, blocked{};
    bool pending{};
    SignalGuard() {
        sigset_t pending_set;
        if (sigpending(&pending_set)) {
            throw std::runtime_error("Cannot inspect pending control socket signals");
        }
        pending = sigismember(&pending_set, SIGPIPE);
        sigemptyset(&blocked);
        sigaddset(&blocked, SIGPIPE);
        if (pthread_sigmask(SIG_BLOCK, &blocked, &previous)) {
            throw std::runtime_error("Cannot block control socket SIGPIPE");
        }
    }
    ~SignalGuard() {
        if (!pending && !sigismember(&previous, SIGPIPE)) {
            timespec zero{};
            sigtimedwait(&blocked, nullptr, &zero);
        }
        pthread_sigmask(SIG_SETMASK, &previous, nullptr);
    }
    SignalGuard(const SignalGuard&) = delete;
    SignalGuard& operator=(const SignalGuard&) = delete;
};
class Transport final {
public:
    explicit Transport(QTcpSocket& socket) : fd_(dup(socket.socketDescriptor())) {
        if (fd_ < 0) {
            throw std::runtime_error("Cannot duplicate control socket");
        }
        timeval timeout{5, 0};
        const auto flags = fcntl(fd_, F_GETFL);
        if (flags < 0 || fcntl(fd_, F_SETFL, flags & ~O_NONBLOCK) < 0 ||
            setsockopt(fd_, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) ||
            setsockopt(fd_, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout))) {
            close(fd_);
            throw std::runtime_error("Cannot configure control socket");
        }
    }
    ~Transport() { close(fd_); }
    Transport(const Transport&) = delete;
    Transport& operator=(const Transport&) = delete;
    int descriptor() const { return fd_; }

private:
    int fd_;
};
inline QByteArray encode(const QByteArray& input) {
    return input;
}
inline QByteArray decode(const QByteArray& input) {
    return input;
}
} // namespace PairingPlatform
