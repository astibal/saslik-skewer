#include "socket_cleanup.hpp"
#include <QCoreApplication>

int main(int argc, char** argv)
{
    QCoreApplication app(argc,argv);
    const quint32 destination = 0xc6336407U; // 198.51.100.7
    if (!exemptionDestinationChanged(destination, {}, {"198.51.100.0/24"})) return 11;
    if (!exemptionDestinationChanged(destination, {"198.51.100.0/24"}, {})) return 12;
    if (exemptionDestinationChanged(destination, {"198.51.100.0/24"}, {"198.51.100.7"})) return 13;
    if (exemptionDestinationChanged(destination, {"10.0.0.0/8"}, {"192.168.0.0/16"})) return 14;
    if (!exemptionDestinationChanged(destination, {}, {"0.0.0.0/0"})) return 15;
    if (exemptionDestinationChanged(destination, {"198.51.100.0/24", "198.51.0.0/16"}, {"198.51.0.0/16"})) return 16;
    if (exemptionDestinationChanged(destination, {"198.51.100.7"}, {"198.51.100.7/32"})) return 17;
    if (exemptionDestinationChanged(destination, {}, {"invalid", "198.51.100.7/33"})) return 18;
    if (!cleanupCandidate(1000,1000,1,123,false,true)) return 1;
    if (cleanupCandidate(1000,1001,1,123,false,true)) return 2;
    if (cleanupCandidate(1000,1000,10,123,false,true)) return 3;
    if (cleanupCandidate(1000,1000,7,123,false,true)) return 4;
    if (cleanupCandidate(1000,1000,1,0,false,true)) return 5;
    if (cleanupCandidate(1000,1000,1,123,true,true)) return 6;
    if (cleanupCandidate(1000,1000,1,123,false,false)) return 7;
    // Invalid inputs must fail before any netlink operation, even in preview mode.
    if (cleanupSockets(1000,{},true) != 2) return 8;
    if (cleanupSockets(1000,{"1:123"},true) != 2) return 9;
    if (cleanupSockets(1000,{"invalid"},true) != 2) return 10;
    return 0;
}
