#include "helper_protocol.hpp"
#include <iostream>

int main()
{
    QStringList args;
    if (!HelperProtocol::decode(R"({"args":["up","192.0.2.2"]})", args)
        || args != QStringList{"up", "192.0.2.2"}) return 1;
    for (const auto* value : {
        R"({"args":["serve"]})", R"({"args":["tunnel-worker"]})",
        R"({"args":["ca-install","x","y"]})", R"({"args":["/bin/sh","-c","id"]})",
        R"({"args":["status"],"uid":0})", R"({"args":["status",0]})",
        R"({"args":["status","\u0000"]})", R"({"args":[]})", "broken"}) {
        if (HelperProtocol::decode(value, args)) return 2;
    }
    if (HelperProtocol::decode(QByteArray(HelperProtocol::maxRequest + 1, ' '), args)) return 3;
    std::cout << "Helper protocol validates bounded commands without identity overrides\n";
}
