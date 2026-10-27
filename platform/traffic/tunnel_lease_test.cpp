#include "tunnel_lease.hpp"
#include <iostream>

using skewer::traffic::TunnelLease;
using namespace std::chrono_literals;
int main() {
    const auto t = TunnelLease::Clock::now();
    auto require = [](bool value) {
        if (!value) {
            throw std::runtime_error("Lease assertion failed");
        }
    };
    try {
        TunnelLease lease(t, t + 2s, 10s);
        require(lease.valid(t + 3s));
        require(lease.renew(t + 4s, t + 5s));
        require(lease.valid(t + 13s));
        require(!lease.valid(t + 14s));
        require(!lease.renew(t + 13s, t + 14s));
        TunnelLease late(t, t, 10s);
        require(!late.renew(t + 9s, t + 10s));
        TunnelLease stopped(t, t, 10s);
        stopped.stop();
        require(!stopped.renew(t + 1s, t + 2s));
        TunnelLease backwards(t, t + 2s, 10s);
        require(!backwards.valid(t + 1s));
        require(!backwards.valid(t + 3s));
        bool rejected = false;
        try {
            TunnelLease expired(t, t + 10s, 10s);
        } catch (const std::invalid_argument&) {
            rejected = true;
        }
        require(rejected);
        std::cout << "PASS: conservative lease deadlines and terminal expiration\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
