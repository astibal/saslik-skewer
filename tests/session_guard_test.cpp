#include "session_guard.hpp"
#include <iostream>

int main()
{
    const GuardIdentity original{123, 1000, 77};
    if (!sameProcess(original, original)) return 1;
    if (sameProcess(original, {123, 1000, 78}) || sameProcess(original, {123, 1001, 77})
        || sameProcess(original, {124, 1000, 77})) return 2;
    if (!guardWindowOpen(10000, 10000) || !guardWindowOpen(10000, 14999)
        || guardWindowOpen(10000, 15000) || guardWindowOpen(10000, 9999)) return 3;
    if (!routedGroup("/user.slice/skewer-routed.slice/app.scope")
        || routedGroup("/user.slice/not-skewer-routed.slice/app.scope")) return 4;
    std::cout << "session identity and independent deadline tests passed\n";
}
