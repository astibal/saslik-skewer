#include "routing_panel.hpp"
#include "routing_client.hpp"
#include "stored_pairing_handoff.hpp"
#include <QLineEdit>
#include <QComboBox>
#include <QHostAddress>
#include <QLabel>
#include <QPushButton>
#include <QVBoxLayout>
#include <QFormLayout>
#include <QSettings>
#include <QCoreApplication>
#include <QDir>
#include <QFileInfo>
#include <QMessageBox>
#include <QtConcurrent>
#include <utility>

namespace skewer::windows {
namespace {
constexpr int AutoTransport = -1;

bool canonicalIpv4(const QString& text) {
    QHostAddress address;
    return address.setAddress(text) && address.protocol() == QAbstractSocket::IPv4Protocol &&
           address.toString() == text;
}
} // namespace

RoutingPanel::RoutingPanel(QWidget* parent, QString service_override)
    : QWidget(parent), cancel_(std::make_shared<Handle>(CreateEventW(nullptr, TRUE, FALSE, nullptr))) {
    auto* layout = new QVBoxLayout(this);
    auto* note = new QLabel(tr("Whole-host IPv4 routing through an installed Skewer service. Closing this "
                               "window does not stop routing. "
                               "The Applications tab can route one process's fresh corroborated IPv4 TCP "
                               "and UDP traffic. "
                               "WinDivert protection does "
                               "not survive a service crash."),
                            this);
    note->setWordWrap(true);
    layout->addWidget(note);
    auto* form = new QFormLayout;
    // Integration tests bind one GUI process to a disposable SCM service.
    // That process-local override must never become the user's next default.
    service_overridden_ = !service_override.trimmed().isEmpty();
    service_ = new QLineEdit(service_overridden_
                                 ? service_override.trimmed()
                                 : QSettings().value("windows/routingService", "SkewerRouting").toString(),
                             this);
    endpoint_ = new QLineEdit(QSettings().value("windows/routingEndpoint", QSettings().value("windows/saslikEndpoint")).toString(), this);
    transport_ = new QComboBox(this);
    transport_->setObjectName("routingTransport");
    transport_->setAccessibleName(tr("Whole-host transport"));
    transport_->addItem(tr("Encrypted tunnel (Tuntom)"), static_cast<int>(RoutingTransport::Tunnel));
    transport_->addItem(tr("Directly reachable Saslik gateway"), static_cast<int>(RoutingTransport::Direct));
    transport_->addItem(tr("Auto — direct when configured, otherwise tunnel"), AutoTransport);
    transport_->setToolTip(tr("Auto chooses once when Start is pressed. It never falls back from a failed "
                              "tunnel to direct routing."));
    transport_->setCurrentIndex(qBound(0, QSettings().value("windows/routingTransport", 2).toInt(), 2));
    gateway_ = new QLineEdit(QSettings().value("windows/directGateway").toString(), this);
    gateway_->setObjectName("routingGateway");
    gateway_->setAccessibleName(tr("Direct gateway"));
    gateway_->setPlaceholderText(tr("On-link Saslik IPv4 gateway"));
    service_->setObjectName("routingService");
    endpoint_->setObjectName("routingEndpoint");
    endpoint_->setPlaceholderText("skewer://HOST:8766/pair (already paired)");
    form->addRow(tr("Installed service"), service_);
    form->addRow(tr("Paired endpoint"), endpoint_);
    form->addRow(tr("Whole-host transport"), transport_);
    form->addRow(tr("Direct gateway"), gateway_);
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
    remove_ = new QPushButton(tr("Remove service…"), this);
    remove_->setObjectName("routingRemove");
    buttons->addWidget(remove_);
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
    connect(start_, &QPushButton::clicked, this, [this] {
        submit(nextStartUsesDirect() ? 5 : 1);
    });
    connect(stop_, &QPushButton::clicked, this, [this] { submit(2); });
    connect(install_, &QPushButton::clicked, this, [this] {
        const auto package = QCoreApplication::applicationDirPath();
        const auto script = QDir(package).filePath(QStringLiteral("install-routing-service.ps1"));
        const auto service = service_->text().trimmed();
        const auto endpoint = endpoint_->text().trimmed();
        const bool upgrade = routingServiceInstalled(service);
        const auto action = upgrade ? tr("upgrade") : tr("installation");
        status_->setText(endpoint.isEmpty()
                             ? tr("Waiting for approval to continue service %1…").arg(action)
                             : tr("Resolving the paired endpoint, then waiting for approval to continue "
                                  "service %1…").arg(action));
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
    connect(remove_, &QPushButton::clicked, this, [this] {
        if (QMessageBox::warning(this, tr("Remove routing service"),
                tr("Stop and remove the privileged routing service?\n\n"
                   "Routing protection will end. Pairing and Skewer settings are preserved."),
                QMessageBox::Yes | QMessageBox::Cancel, QMessageBox::Cancel) != QMessageBox::Yes) return;
        const auto script = QDir(QCoreApplication::applicationDirPath())
                                .filePath(QStringLiteral("remove-routing-service.ps1"));
        status_->setText(tr("Waiting for approval to remove the routing service…"));
        updateControls();
        remove_watcher_.setFuture(QtConcurrent::run(runRoutingServiceRemover, script,
                                                     service_->text().trimmed()));
        updateControls();
    });
    connect(&remove_watcher_, &QFutureWatcher<InstallerResult>::finished, this, [this] {
        const auto result = remove_watcher_.result();
        status_->setText(result.error.isEmpty() ? tr("Routing service removed; settings preserved.")
                                                : tr("Service removal failed: %1").arg(result.error));
        ++epoch_;
        known_ = false;
        automatic_pairing_attempted_ = false;
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
    connect(transport_, &QComboBox::currentIndexChanged, this, [this] {
        QSettings().setValue("windows/routingTransport", transport_->currentIndex());
        updateControls();
    });
    connect(gateway_, &QLineEdit::textChanged, this, [this] { updateControls(); });
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
                if (state_.scope == RoutingScope::WholeHost &&
                    (state_.transport == RoutingTransport::Tunnel ||
                     state_.transport == RoutingTransport::Direct) &&
                    transport_->currentData().toInt() != AutoTransport) {
                    const auto index = state_.transport == RoutingTransport::Direct ? 1 : 0;
                    transport_->blockSignals(true);
                    transport_->setCurrentIndex(index);
                    transport_->blockSignals(false);
                }
                const QStringList phases{tr("Idle"),
                                         tr("Starting"),
                                         tr("Active"),
                                         tr("Blocked — tunnel failed, protection retained"),
                                         tr("Stopping — cleaning up"),
                                         tr("Failed — previous session ended with an error")};
                status_->setText(phases.value(static_cast<int>(state_.phase), tr("Unknown")));
                if (state_.phase == RoutingPhase::Idle) {
                    if (!state_.tunnel_available) {
                        status_->setText(
                            tr("Idle — Direct-only service ready; upgrade to enable tunnel routing"));
                    } else {
                        status_->setText(state_.paired ? tr("Idle — paired control ready")
                                                       : tr("Idle — restoring paired control…"));
                    }
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
                    const auto mode = state_.transport == RoutingTransport::Direct
                                          ? tr("direct gateway") : tr("encrypted tunnel");
                    status_->setText(tr("Active — whole-host routing via %1 (generation %2)")
                                         .arg(mode).arg(state_.generation));
                }
                if (state_.result != RoutingResult::Ok) {
                    status_->setText(tr("Request rejected (stale generation or busy). ") + status_->text());
                }
                if (result.request.action == 3) {
                    status_->setText(tr("Pairing delivered; routing not started. ") + status_->text());
                }
                if (!service_overridden_) {
                    QSettings().setValue("windows/routingService", result.request.service);
                }
                if (result.request.action == 3) {
                    QSettings().setValue("windows/routingEndpoint", result.request.endpoint);
                }
                if ((result.request.action == 1 || result.request.action == 5) &&
                    state_.result == RoutingResult::Ok) {
                    if (result.request.action == 5) {
                        QSettings().setValue("windows/directGateway", result.request.gateway);
                    }
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
        if (known_ && state_.tunnel_available && !state_.paired && !automatic_pairing_attempted_ &&
            !action_busy_ && !pending_ &&
            nextStartRequiresPairing() &&
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
    if (service_overridden_) {
        return;
    }
    const auto normalized = service.trimmed();
    if (!normalized.isEmpty() && service_->text() != normalized) {
        service_->setText(normalized);
    }
}
QString RoutingPanel::serviceName() const { return service_->text().trimmed(); }
void RoutingPanel::setPairedEndpoint(const QString& endpoint) {
    const auto normalized = endpoint.trimmed();
    if (normalized.isEmpty()) {
        return;
    }
    const bool idle = known_ && (state_.phase == RoutingPhase::Idle || state_.phase == RoutingPhase::Failed);
    if (!routingServiceInstalled(service_->text().trimmed()) || (idle && !action_busy_)) {
        pending_endpoint_.clear();
        endpoint_->setText(normalized);
    } else {
        // An active or not-yet-inspected installed service may belong to the
        // previous endpoint. Keep its visible configuration stable until the
        // user explicitly stops that authoritative generation.
        pending_endpoint_ = normalized;
    }
}
void RoutingPanel::startSelected(ProcessKey process) {
    if (!process.pid || !process.created || !known_ || !state_.tunnel_available || !state_.paired) {
        return;
    }
    Request request{4, service_->text().trimmed(), endpoint_->text().trimmed(), {},
                    state_.generation, process, epoch_};
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
    remove_watcher_.waitForFinished();
}
bool RoutingPanel::validDirectGateway() const {
    return canonicalIpv4(gateway_->text().trimmed());
}
bool RoutingPanel::nextStartUsesDirect() const {
    const auto requested = transport_->currentData().toInt();
    return requested == static_cast<int>(RoutingTransport::Direct) ||
           (requested == AutoTransport && validDirectGateway());
}
bool RoutingPanel::nextStartRequiresPairing() const {
    const auto requested = transport_->currentData().toInt();
    return requested == static_cast<int>(RoutingTransport::Tunnel) ||
           (requested == AutoTransport && gateway_->text().trimmed().isEmpty());
}
void RoutingPanel::updateControls() {
    const bool idle = known_ && (state_.phase == RoutingPhase::Idle || state_.phase == RoutingPhase::Failed);
    // Keep the UI bound to the authoritative service generation it started.
    // Changing the service/endpoint or upgrading SCM while that generation is
    // live could orphan routing from this panel or terminate it outside Stop.
    const bool configuration_editable = !known_ || idle;
    if (!action_busy_ && !pending_endpoint_.isEmpty() &&
        ((known_ && idle) || !routingServiceInstalled(service_->text().trimmed()))) {
        endpoint_->setText(std::exchange(pending_endpoint_, QString{}));
    }
    const auto requested = transport_->currentData().toInt();
    const bool direct = requested == static_cast<int>(RoutingTransport::Direct);
    const bool automatic = requested == AutoTransport;
    const auto gateway_text = gateway_->text().trimmed();
    const bool valid_gateway = validDirectGateway();
    const bool transport_ready = direct ? (state_.direct_available && valid_gateway)
                                        : automatic ? (gateway_text.isEmpty()
                                                           ? (state_.tunnel_available && state_.paired)
                                                           : (state_.direct_available && valid_gateway))
                                                    : (state_.tunnel_available && state_.paired);
    pair_->setEnabled(idle && state_.tunnel_available && !action_busy_);
    start_->setEnabled(idle && !action_busy_ && transport_ready);
    stop_->setEnabled(known_ && !idle && state_.phase != RoutingPhase::Stopping && !action_busy_);
    service_->setEnabled(configuration_editable && !action_busy_ && !service_overridden_);
    endpoint_->setEnabled(configuration_editable && !action_busy_);
    transport_->setEnabled(idle && !action_busy_);
    gateway_->setEnabled(idle && !action_busy_ && (direct || automatic));
    const auto package = QCoreApplication::applicationDirPath();
    const bool install_packaged = QFileInfo::exists(QDir(package).filePath("install-routing-service.ps1")) &&
                                  QFileInfo::exists(QDir(package).filePath("wintun.dll")) &&
                                  QFileInfo::exists(QDir(package).filePath("WinDivert.dll")) &&
                                  QFileInfo::exists(QDir(package).filePath("WinDivert64.sys"));
    const bool remove_packaged = QFileInfo::exists(QDir(package).filePath("remove-routing-service.ps1"));
    install_->setText(routingServiceInstalled(service_->text().trimmed())
                          ? tr("Upgrade routing service…") : tr("Install routing service…"));
    const bool managing = install_watcher_.isRunning() || remove_watcher_.isRunning();
    install_->setEnabled(install_packaged && configuration_editable && !action_busy_ && !managing &&
                         !service_overridden_);
    const bool removable = !known_ || state_.phase == RoutingPhase::Idle || state_.phase == RoutingPhase::Failed;
    remove_->setEnabled(remove_packaged && routingServiceInstalled(service_->text().trimmed()) && removable &&
                        !action_busy_ && !managing && !service_overridden_);
}
void RoutingPanel::submit(int action) {
    Request request{action, service_->text().trimmed(), endpoint_->text().trimmed(),
                    gateway_->text().trimmed(), state_.generation,
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
            } else if (request.action == 5) {
                if (!canonicalIpv4(request.gateway)) {
                    throw std::invalid_argument("Direct routing requires a canonical IPv4 gateway");
                }
                QHostAddress address(request.gateway);
                const auto value = address.toIPv4Address();
                result.reply = exchangeDirectRouting(
                    pipe->get(), name,
                    {static_cast<std::uint8_t>(value >> 24), static_cast<std::uint8_t>(value >> 16),
                     static_cast<std::uint8_t>(value >> 8), static_cast<std::uint8_t>(value)},
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
