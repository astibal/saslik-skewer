#include "decision.hpp"
#include <iostream>

int main() {
    using namespace skewer::ale;
    for (unsigned flags = 0; flags < 32; ++flags) {
        const bool writable = flags & 1, layer = flags & 2, metadata = flags & 4;
        const bool active = flags & 8, matches = flags & 16;
        const Authorization input{writable, layer, metadata, active, matches ? 42ULL : 43ULL, 42};
        const auto actual = decide(input);
        const auto expected = !writable                                      ? Decision::Preserve
                              : (!layer || !metadata || (active && matches)) ? Decision::Block
                                                                             : Decision::Continue;
        if (actual != expected) {
            std::cerr << "FAIL: ALE decision combination " << flags << '\n';
            return 1;
        }
    }
    std::cout << "PASS: ALE block-only decisions, missing metadata, inactive target and action rights\n";
    return 0;
}
