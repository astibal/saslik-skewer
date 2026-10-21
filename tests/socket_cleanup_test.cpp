#include "socket_cleanup.hpp"
#include <QCoreApplication>

int main(int argc, char** argv)
{
    QCoreApplication app(argc,argv);
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
