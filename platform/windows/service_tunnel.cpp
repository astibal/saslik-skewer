#include "service_tunnel.hpp"

namespace skewer::windows {
namespace {
class DeferredRoutes final : public TunnelRoutePolicy {
public:
    DeferredRoutes(ServiceRoutePlan plan, const std::unique_ptr<WintunDevice>& device)
        : plan_(std::move(plan)), device_(device) {}

    void activate(const Tuntom::Endpoint& endpoint) override {
        if (!device_ || routes_) {
            throw std::logic_error("Invalid service route activation");
        }
        routes_ = std::make_unique<TunnelRoutes>(plan_(device_->luid(), endpoint));
        routes_->activate(endpoint);
    }
    void withdraw() noexcept override {
        if (routes_) {
            routes_->withdraw();
        }
    }
    bool clean() const noexcept { return !routes_ || routes_->clean(); }

private:
    ServiceRoutePlan plan_;
    const std::unique_ptr<WintunDevice>& device_;
    std::unique_ptr<TunnelRoutes> routes_;
};
GuardedTunnelResult runOwnedDeviceTunnel(traffic::PacketCapture& guard, std::unique_ptr<WintunDevice>& device,
                                         std::shared_ptr<const WintunApi> api,
                                         const std::wstring& adapter_name, TunnelControl& control,
                                         const QString& peer, ServiceRoutePlan plan, HANDLE stop,
                                         std::atomic_bool& ready, std::atomic_bool& blocked) {
    if (!api || !plan || adapter_name.empty()) {
        throw std::invalid_argument("Incomplete service tunnel configuration");
    }
    ready.store(false);
    blocked.store(false);
    std::unique_ptr<AddressedTunnelControl> addressed;
    DeferredRoutes routes(std::move(plan), device);
    GuardedTunnelResult result{};
    result.worker = runGuardedWorker(
        guard, stop,
        [&](HANDLE cancel) {
            // Setup is inside the protected worker: a failed adapter/control
            // setup must not unwind the guard and silently restore direct egress.
            if (!device) {
                device = std::make_unique<WintunDevice>(api, adapter_name);
            }
            addressed = std::make_unique<AddressedTunnelControl>(control, *device, cancel);
            result.counters = runPairedTunnel(*device, *addressed, peer, cancel, ready, &routes);
        },
        [&] {
            // The worker has joined. Keep the adapter until every owned route
            // is gone; only then retire its address and the adapter itself.
            ready.store(false);
            routes.withdraw();
            if (!routes.clean()) {
                return false;
            }
            addressed.reset();
            device.reset();
            return true;
        },
        &blocked);
    return result;
}
} // namespace

GuardedTunnelResult runServiceTunnel(traffic::PacketCapture& guard, std::shared_ptr<const WintunApi> api,
                                     const std::wstring& name, TunnelControl& control, const QString& peer,
                                     ServiceRoutePlan plan, HANDLE stop, std::atomic_bool& ready,
                                     std::atomic_bool& blocked) {
    std::unique_ptr<WintunDevice> device;
    return runOwnedDeviceTunnel(guard, device, api, name, control, peer, std::move(plan), stop, ready,
                                blocked);
}

GuardedTunnelResult runConfiguredServiceTunnel(std::shared_ptr<const WintunApi> api, const std::wstring& name,
                                               TunnelControl& control, const QString& peer,
                                               ServiceGuardFactory guard_factory, ServiceRoutePlan plan,
                                               HANDLE stop, std::atomic_bool& ready,
                                               std::atomic_bool& blocked) {
    ready.store(false);
    blocked.store(false);
    if (!api || !guard_factory || !plan || name.empty()) {
        throw std::invalid_argument("Incomplete configured service tunnel");
    }
    // Reverse destruction keeps protection alive until adapter teardown, even
    // on exceptional paths. Before guard creation no address/routes are changed.
    std::unique_ptr<traffic::PacketCapture> guard;
    auto device = std::make_unique<WintunDevice>(api, name);
    guard = guard_factory(device->luid());
    if (!guard) {
        throw std::runtime_error("Service egress guard was not created");
    }
    return runOwnedDeviceTunnel(*guard, device, api, name, control, peer, std::move(plan), stop, ready,
                                blocked);
}
} // namespace skewer::windows
