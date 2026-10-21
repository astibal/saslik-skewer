#include "socket_cleanup.hpp"
#include <QDir>
#include <QDirIterator>
#include <QFile>
#include <QSet>
#include <QTextStream>
#include <linux/inet_diag.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/sock_diag.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cstring>
#include <optional>

namespace {
QByteArray read(const QString& path) { QFile f(path); return f.open(QIODevice::ReadOnly) ? f.readAll() : QByteArray{}; }
struct Target { int pid; QByteArray start; QString group; };
bool valid(const Target& target, uid_t uid)
{
    const QString path = QString("/proc/%1").arg(target.pid);
    struct stat st{};
    if (::stat(path.toLocal8Bit(), &st) || st.st_uid != uid) return false;
    const auto stat = read(path + "/stat");
    const auto fields = stat.mid(stat.lastIndexOf(')') + 2).simplified().split(' ');
    return fields.size() > 19 && fields[19] == target.start
        && QString::fromUtf8(read(path + "/cgroup")).trimmed() == "0::" + target.group;
}
QSet<quint64> sockets(const Target& target)
{
    QSet<quint64> result;
    QDir dir(QString("/proc/%1/fd").arg(target.pid));
    for (const auto& fd : dir.entryList(QDir::AllEntries | QDir::System | QDir::NoDotAndDotDot)) {
        char buf[256]; const auto n = readlink(dir.filePath(fd).toLocal8Bit(), buf, sizeof(buf));
        if (n <= 0) continue;
        const QByteArray value(buf,n);
        if (value.startsWith("socket:[") && value.endsWith(']')) result.insert(value.mid(8,value.size()-9).toULongLong());
    }
    return result;
}
struct Socket { inet_diag_msg message{}; quint64 group = 0; };
// Each exchange has its own fd: no stale dump replies can acknowledge a destroy.
bool query(int family, const Socket* target, bool destroy, QVector<Socket>& output)
{
    const int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_SOCK_DIAG);
    if (fd < 0) return false;
    struct Close { int fd; ~Close() { close(fd); } } close_fd{fd};
    timeval timeout{3,0}; setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));
    struct { nlmsghdr header; inet_diag_req_v2 request; } packet{};
    packet.header.nlmsg_len = sizeof(packet);
    packet.header.nlmsg_type = destroy ? SOCK_DESTROY : SOCK_DIAG_BY_FAMILY;
    packet.header.nlmsg_flags = NLM_F_REQUEST | (target ? NLM_F_ACK : NLM_F_DUMP);
    packet.header.nlmsg_seq = 1;
    packet.request.sdiag_family = family;
    packet.request.sdiag_protocol = IPPROTO_TCP;
    packet.request.idiag_states = ~0U;
    if (target) packet.request.id = target->message.id;
    sockaddr_nl kernel{}; kernel.nl_family = AF_NETLINK;
    if (sendto(fd,&packet,sizeof(packet),0,reinterpret_cast<sockaddr*>(&kernel),sizeof(kernel)) < 0) return false;
    char buffer[65536];
    for (;;) {
        int size = recv(fd,buffer,sizeof(buffer),0);
        if (size <= 0) return false;
        for (auto* h = reinterpret_cast<nlmsghdr*>(buffer); NLMSG_OK(h,size); h=NLMSG_NEXT(h,size)) {
            if (h->nlmsg_seq != 1 || (h->nlmsg_flags & NLM_F_DUMP_INTR)) return false;
            if (h->nlmsg_type == NLMSG_DONE) return true;
            if (h->nlmsg_type == NLMSG_ERROR) {
                if (h->nlmsg_len < NLMSG_LENGTH(sizeof(nlmsgerr))) return false;
                return reinterpret_cast<nlmsgerr*>(NLMSG_DATA(h))->error == 0;
            }
            if (h->nlmsg_len < NLMSG_LENGTH(sizeof(inet_diag_msg))) return false;
            Socket item; memcpy(&item.message,NLMSG_DATA(h),sizeof(item.message));
            int length = h->nlmsg_len - NLMSG_LENGTH(sizeof(inet_diag_msg));
            auto* attr = reinterpret_cast<rtattr*>(reinterpret_cast<char*>(NLMSG_DATA(h))+NLMSG_ALIGN(sizeof(inet_diag_msg)));
            for (; RTA_OK(attr,length); attr=RTA_NEXT(attr,length))
                if (attr->rta_type == INET_DIAG_CGROUP_ID && RTA_PAYLOAD(attr) == sizeof(quint64))
                    memcpy(&item.group,RTA_DATA(attr),sizeof(item.group));
            output.push_back(item);
        }
    }
}
}

int cleanupSockets(uid_t uid, const QStringList& arguments, bool dry_run, int* count_out)
{
    if (arguments.isEmpty() || arguments.size() > 1024) return 2;
    QVector<Target> targets;
    QSet<quint64> routed_groups, inodes;
    for (const auto& value : arguments) {
        const auto parts = value.split(':'); bool ok = false;
        const int pid = parts.value(0).toInt(&ok);
        if (!ok || pid <= 1 || parts.size()!=2 || parts[1].isEmpty()) return 2;
        const QString cg = QString::fromUtf8(read(QString("/proc/%1/cgroup").arg(pid))).trimmed();
        const QString group = cg.startsWith("0::/") ? cg.mid(3) : QString{};
        const auto segments = group.split('/');
        if (!segments.contains("skewer-routed.slice") || group.contains("..")) return 2;
        Target target{pid,parts[1].toLatin1(),group};
        if (!valid(target,uid)) return 2;
        targets.push_back(target); inodes.unite(sockets(target));
        const QString root = "/sys/fs/cgroup" + group.left(group.indexOf("/skewer-routed.slice") + QString("/skewer-routed.slice").size());
        auto add = [&routed_groups](const QString& path) { struct stat st{}; if (!::stat(path.toLocal8Bit(),&st)) routed_groups.insert(st.st_ino); };
        add(root);
        QDirIterator dirs(root,QDir::Dirs|QDir::NoDotAndDotDot,QDirIterator::Subdirectories);
        while (dirs.hasNext()) add(dirs.next());
    }
    QVector<Socket> candidates;
    if (!query(AF_INET,nullptr,false,candidates) || !query(AF_INET6,nullptr,false,candidates)) return 1;
    int count = 0, failed = 0;
    for (const auto& socket : candidates) {
        if (socket.message.idiag_uid != uid || !inodes.contains(socket.message.idiag_inode)
            || socket.message.idiag_state == 10 || socket.message.idiag_state == 7) continue; // LISTEN / CLOSE
        if (!socket.group) { ++failed; continue; } // Missing cgroup evidence must fail closed.
        if (routed_groups.contains(socket.group)) continue;
        if (!cleanupCandidate(uid,socket.message.idiag_uid,socket.message.idiag_state,
                              socket.group,routed_groups.contains(socket.group),inodes.contains(socket.message.idiag_inode))) continue;
        bool owned = false;
        for (const auto& target : targets)
            if (valid(target,uid) && sockets(target).contains(socket.message.idiag_inode)) owned = true;
        if (!owned) continue;
        QVector<Socket> fresh;
        if (!query(socket.message.idiag_family,&socket,false,fresh) || fresh.size()!=1
            || fresh[0].group != socket.group || fresh[0].message.idiag_uid != uid) { ++failed; continue; }
        QVector<Socket> ignored;
        // The kernel cookie in sockid prevents a reused endpoint from being destroyed.
        if (dry_run || query(socket.message.idiag_family,&socket,true,ignored)) ++count;
        else ++failed;
    }
    QTextStream(stdout) << (dry_run ? "Eligible TCP sockets: " : "Closed TCP sockets: ") << count
        << "; unverified/failed: " << failed << '\n';
    if (count_out) *count_out = count;
    return failed ? 1 : 0;
}
