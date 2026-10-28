#include "routing_panel.hpp"
#include "routing_client.hpp"
#include "stored_pairing_handoff.hpp"
#include <QLineEdit>
#include <QLabel>
#include <QPushButton>
#include <QVBoxLayout>
#include <QFormLayout>
#include <QSettings>
#include <QCoreApplication>
#include <QDir>
#include <QFileInfo>
#include <QtConcurrent>

namespace skewer::windows {
RoutingPanel::RoutingPanel(QWidget* parent)
    : QWidget(parent), cancel_(std::make_shared<Handle>(CreateEventW(nullptr, TRUE, FALSE, nullptr))) {
    auto* layout = new QVBoxLayout(this);
    auto* note = new QLabel(tr("Whole-host IPv4 routing through an installed Skewer service. Closing this "
                               "window does not stop routing. "
                               "The Applications tab can route one process's fresh IPv4 TCP connections. "
                               "WinDivert protection does "
                               "not survive a service crash."),
                            this);
    note->setWordWrap(true);
    layout->addWidget(note);
    auto* form = new QFormLayout;
    service_ = new QLineEdit(QSettings().value("windows/routingService", "SkewerRouting").toString(), this);
    endpoint_ = new QLineEdit(QSettings().value("windows/routingEndpoint", QSettings().value("windows/saslikEndpoint")).toString(), this);
    service_->setObjectName("routingService");
    endpoint_->setObjectName("routingEndpoint");
    endpoint_->setPlaceholderText("skewer://HOST:8766/pair (already paired)");
    form->addRow(tr("Installed service"), service_);
    form->addRow(tr("Paired endpoint"), endpoint_);
    layout->addLayout(form);
    auto* buttons = new QHBoxLayout;
    pair_ = new QPushButton(tr("Send pairing"), this);
    start_ = new QPushButton(tr("Start whole-host routing"), this);
    stop_ = new QPushButton(tr("Stop routing"), this);
    pair_->setObjectName("routingPair");
    start_->setObjectName("routingStart");
    stop_->setObjectName("routingStop");
    buttons->addWidget(pair_);
    buttons->addWidget(start_);
    buttons->addWidget(stop_);
    install_ = new QPushButton(tr("Install routing service…"), this);
    install_->setObjectName("routingInstall");
    buttons->addWidget(install_);
    buttons->addStretch();
    layout->addLayout(buttons);
    status_ = new QLabel(tr("Checking service…"), this);
    status_->setObjectName("routingStatus");
    status_->setWordWrap(true);
    layout->addWidget(status_);
    layout->addStretch();
    connect(pair_, &QPushButton::clicked, this, [this] {
        automatic_pairing_attempted_ = true;
        submit(3);
    });
    connect(start_, &QPushButton::clicked, this, [this] { submit(1); });
    connect(stop_, &QPushButton::clicked, this, [this] { submit(2); });
    connect(install_, &QPushButton::clicked, this, [this] {
        const auto package = QCoreApplication::applicationDirPath();
        const auto script = QDir(package).filePath(QStringLiteral("install-routing-service.ps1"));
        const auto service = service_->text().trimmed();
        const auto endpoint = endpoint_->text().trimmed();
        const bool upgrade = routingServiceInstalled(service);
        status_->setText(upgrade ? tr("Waiting for approval to upgrade the routing service…")
                                 : tr("Waiting for approval to install the routing service…"));
        updateControls();
        install_watcher_.setFuture(QtConcurrent::run(runRoutingServiceInstaller, script, package,
                                                     service, endpoint, upgrade));
        updateControls();
    });
    connect(&install_watcher_, &QFutureWatcher<InstallerResult>::finished, this, [this] {
        const auto result = install_watcher_.result();
        if (!result.error.isEmpty()) status_->setText(tr("Service installation failed: %1").arg(result.error));
        else status_->setText(tr("Routing service installed and started in Idle."));
        ++epoch_;
        known_ = false;
        updateControls();
        submit(0);
    });
    connect(service_, &QLineEdit::textChanged, this, [this] {
        ++epoch_;
        known_ = false;
        automatic_pairing_attempted_ = false;
        updateControls();
        status_->setText(tr("Checking service…"));
    });
    connect(endpoint_, &QLineEdit::textChanged, this, [this] {
        automatic_pairing_attempted_ = false;
    });
    connect(&timer_, &QTimer::timeout, this, [this] {
        if (!watcher_.isRunning() && !action_busy_) {
            submit(0);
        }
    });
    connect(&watcher_, &QFutureWatcher<Result>::finished, this, [this] {
        const auto result = watcher_.result();
        if (result.request.epoch == epoch_) {
            if (result.request.action) {
                action_busy_ = false;
            }
            if (!result.error.isEmpty()) {
                known_ = false;
                automatic_pairing_attempted_ = false;
                status_->setText(
                    tr("Service unavailable or request failed: %1. No automatic retry of Start/Stop.")
                        .arg(result.error));
            } else {
                known_ = true;
                state_ = result.reply;
                const QStringList phases{tr("Idle"),
                                         tr("Starting"),
                                         tr("Active"),
                                         tr("Blocked — tunnel failed, protection retained"),
                                         tr("Stopping — cleaning up"),
                                         tr("Failed — previous session ended with an error")};
                status_->setText(phases.value(static_cast<int>(state_.phase), tr("Unknown")));
                if (state_.phase == RoutingPhase::Idle) {
                    status_->setText(state_.paired ? tr("Idle — paired control ready")
                                                   : tr("Idle — restoring paired control…"));
                }
                if (!state_.detail.empty()) {
                    status_->setText(status_->text() + tr(": %1").arg(QString::fromUtf8(state_.detail)));
                }
                if (state_.phase == RoutingPhase::Active &&
                    state_.scope == RoutingScope::SelectedProcess && state_.selected) {
                    status_->setText(tr("Active — selected PID %1 (generation %2)")
                                         .arg(state_.selected->pid)
                                         .arg(state_.generation));
                } else if (state_.phase == RoutingPhase::Active &&
                           state_.scope == RoutingScope::WholeHost) {
                    status_->setText(tr("Active — whole-host routing (generation %1)")
                                         .arg(state_.generation));
                }
                if (state_.result != RoutingResult::Ok) {
                    status_->setText(tr("Request rejected (stale generation or busy). ") + status_->text());
                }
                if (result.request.action == 3) {
                    status_->setText(tr("Pairing delivered; routing not started. ") + status_->text());
                }
                QSettings().setValue("windows/routingService", result.request.service);
                if (result.request.action == 3) {
                    QSettings().setValue("windows/routingEndpoint", result.request.endpoint);
                }
            }
            if (state_callback_) {
                state_callback_(known_, state_);
            }
        }
        if (pending_) {
            auto request = *pending_;
            pending_.reset();
            action_busy_ = true;
            dispatch(std::move(request));
        }
        updateControls();
        if (known_ && !state_.paired && !automatic_pairing_attempted_ && !action_busy_ && !pending_ &&
            !endpoint_->text().trimmed().isEmpty() &&
            (state_.phase == RoutingPhase::Idle || state_.phase == RoutingPhase::Failed)) {
            // Pairing handoff changes only service memory. It never starts a
            // routing generation and is safe to restore after service reboot.
            automatic_pairing_attempted_ = true;
            QTimer::singleShot(0, this, [this] {
                if (!action_busy_ && !watcher_.isRunning()) {
                    status_->setText(tr("Restoring paired control to the idle service…"));
                    submit(3);
                }
            });
        }
    });
    updateControls();
    timer_.start(2000);
    submit(0);
}
void RoutingPanel::setStateCallback(StateCallback callback) {
    state_callback_ = std::move(callback);
    if (state_callback_) {
        state_callback_(known_, state_);
    }
}
void RoutingPanel::setServiceName(const QString& service) {
    const auto normalized = service.trimmed();
    if (!normalized.isEmpty() && service_->text() != normalized) {
        service_->setText(normalized);
    }
}
void RoutingPanel::startSelected(ProcessKey process) {
    if (!process.pid || !process.created || !known_ || !state_.paired) {
        return;
    }
    Request request{4, service_->text().trimmed(), endpoint_->text().trimmed(), state_.generation,
                    process, epoch_};
    action_busy_ = true;
    updateControls();
    status_->setText(tr("Starting selected-process routing…"));
    if (watcher_.isRunning()) {
        pending_ = request;
    } else {
        dispatch(std::move(request));
    }
}
void RoutingPanel::stopCurrent() { submit(2); }
RoutingPanel::~RoutingPanel() {
    timer_.stop();
    pending_.reset();
    // Cancel only local IPC. Never send a service Stop on window destruction.
    if (*cancel_) {
        SetEvent(cancel_->get());
    }
    watcher_.waitForFinished();
    install_watcher_.waitForFinished();
}
void RoutingPanel::updateControls() {
    const bool idle = known_ && (state_.phase == RoutingPhase::Idle || state_.phase == RoutingPhase::Failed);
    pair_->setEnabled(idle && !action_busy_);
    start_->setEnabled(idle && state_.paired && !action_busy_);
    stop_->setEnabled(known_ && !idle && state_.phase != RoutingPhase::Stopping && !action_busy_);
    service_->setEnabled(!action_busy_);
    endpoint_->setEnabled(!action_busy_);
    const auto package = QCoreApplication::applicationDirPath();
    const bool packaged = QFileInfo::exists(QDir(package).filePath("install-routing-service.ps1")) &&
                          QFileInfo::exists(QDir(package).filePath("wintun.dll")) &&
                          QFileInfo::exists(QDir(package).filePath("WinDivert.dll")) &&
                          QFileInfo::exists(QDir(package).filePath("WinDivert64.sys"));
    install_->setText(routingServiceInstalled(service_->text().trimmed())
                          ? tr("Upgrade routing service…") : tr("Install routing service…"));
    install_->setEnabled(packaged && !action_busy_ && !install_watcher_.isRunning());
}
void RoutingPanel::submit(int action) {
    Request request{action, service_->text().trimmed(), endpoint_->text().trimmed(), state_.generation,
                    std::nullopt, epoch_};
    if (action) {
        action_busy_ = true;
        updateControls();
        status_->setText(tr("Sending request…"));
    }
    if (watcher_.isRunning()) {
        if (action) {
            pending_ = request;
        }
        return;
    }
    dispatch(std::move(request));
}
void RoutingPanel::dispatch(Request request) {
    watcher_.setFuture(QtConcurrent::run([request = std::move(request), cancel = cancel_] {
        Result result;
        result.request = request;
        try {
            const auto name = request.service.toStdWString();
            if (request.action == 3) {
                auto pipe = connectRoutingService(name, true, cancel->get(), 1000);
                sendStoredPairing(pipe->get(), name, QUrl(request.endpoint), cancel->get(), 2000);
            }
            auto pipe = connectRoutingService(name, false, cancel->get(), 1000);
            if (request.selected) {
                result.reply = exchangeSelectedRouting(pipe->get(), name, *request.selected,
                                                       request.generation, cancel->get(), 2000);
            } else {
                const auto command = request.action == 3
                                         ? RoutingCommand::Status
                                         : static_cast<RoutingCommand>(request.action);
                result.reply = exchangeRoutingCommand(pipe->get(), name, command, request.generation,
                                                      cancel->get(), 2000);
            }
        } catch (const std::exception& error) {
            result.error = QString::fromUtf8(error.what());
        }
        return result;
    }));
}
} // namespace skewer::windows
