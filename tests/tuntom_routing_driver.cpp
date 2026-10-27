// Test-only executable: exercise the real privileged hooks without a transport
// installation. It refuses to operate in the caller's original network namespace.
#define main helperMain
#include "../src/net_helper.cpp"
#undef main

int main(int argc, char** argv)
{
    QCoreApplication app(argc, argv);
    const auto args = app.arguments();
    if (args.size() != 5 || QFile::symLinkTarget("/proc/self/ns/net").isEmpty()) return 2;
    char net[256]{};
    const auto size = ::readlink("/proc/self/ns/net", net, sizeof(net));
    if (size <= 0 || QByteArray(net, size) == args[3].toUtf8()) return 2;
    char mount[256]{};
    const auto mount_size = ::readlink("/proc/self/ns/mnt", mount, sizeof(mount));
    if (mount_size <= 0 || QByteArray(mount, mount_size) == args[4].toUtf8()) return 2;
    const uid_t uid = args[2].toUInt();
    Tuntom::Endpoint endpoint{1, 60, QString(64, 'a'), "skt1c", "10.253.0.5/30", "10.253.0.6/30"};
    try {
        if (args[1] == "begin") Tuntom::beginRouting(uid, endpoint, {});
        else if (args[1] == "begin-host") Tuntom::beginRouting(uid, endpoint, {}, {{"interface", "skt1c"}});
        else if (args[1] == "verified") Tuntom::updateRouting(uid, endpoint, true);
        else if (args[1] == "waiting") Tuntom::updateRouting(uid, endpoint, false);
        else return 2;
        return 0;
    } catch (const std::exception& error) {
        QTextStream(stderr) << error.what() << '\n';
        return 1;
    }
}
