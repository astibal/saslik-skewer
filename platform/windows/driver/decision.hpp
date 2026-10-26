#pragma once

namespace skewer::ale {
enum class Decision { Preserve, Continue, Block };
struct Authorization {
    bool can_write;
    bool expected_layer;
    bool has_pid;
    bool target_active;
    unsigned long long pid;
    unsigned long long target_pid;
};
// No Permit decision exists in this block-only prototype. Unknown metadata is
// blocked inside the management filter's explicitly limited scope.
constexpr Decision decide(const Authorization& input) {
    if (!input.can_write) {
        return Decision::Preserve;
    }
    if (!input.expected_layer || !input.has_pid) {
        return Decision::Block;
    }
    if (input.target_active && input.pid == input.target_pid) {
        return Decision::Block;
    }
    return Decision::Continue;
}
} // namespace skewer::ale
