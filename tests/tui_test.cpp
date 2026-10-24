#include "tui.hpp"
#include <QApplication>
#include <QTemporaryDir>
#include <QSettings>
#include "runtime_trust_service.hpp"
#include <QFile>

class TuiTest {
public:
    static int run()
    {
        Tui tui;
        // Both startup and Enable use a liveness probe, never routing status.
        if (TuiTunnel::authorizationProbe() != QStringList{"tunnel-poll"}) return 20;
        QSettings settings;
        int authorizations = 0, resumes = 0;
        const auto authorize = [&] { ++authorizations; return PrivilegedSession::Reply{true, {}}; };
        const auto resume = [&] { ++resumes; };
        // Even a fresh frontend without routing intent opens its helper once.
        tui.startSession(authorize, resume);
        if (authorizations != 1 || resumes != 0) return 13;
        settings.setValue("routing/requested", true);
        settings.setValue("routing/mode", "saslik");
        settings.setValue("routing/transport", "tunnel");
        settings.setValue("routing/lastTransport", "tunnel");
        tui.restoreRoutingIntent();
        tui.startSession(authorize, resume);
        if (authorizations != 2 || resumes != 1) return 14;
        tui.startSession([&] { ++authorizations; return PrivilegedSession::Reply{false, "canceled"}; }, resume);
        if (authorizations != 3 || resumes != 1 || tui.retry_.isValid()
            || !tui.status_.contains("E retries")) return 15;
        settings.setValue("routing/resumeOnStartup", false);
        tui.startSession(authorize, resume);
        if (authorizations != 4 || resumes != 1) return 16;
        settings.setValue("routing/resumeOnStartup", true);
        settings.setValue("saslik/disconnected", true);
        tui.startSession(authorize, resume);
        if (authorizations != 5 || resumes != 1) return 17;
        if (!tui.requested_ || !tui.tunnel_pinned_ || !tui.tunnel_.view.requested
            || Tuntom::compactStatus(tui.tunnel_.view) == "Tunnel off"
            || tui.tunnel_.view.routingActive || tui.tunnel_.view.fresh) return 10;
        tui.tunnel_.view.state = "authorization-required";
        if (!Tuntom::compactStatus(tui.tunnel_.view).contains("authorization required")) return 11;
        settings.clear();
        tui.restoreRoutingIntent();
        if (tui.requested_ || tui.tunnel_pinned_
            || Tuntom::compactStatus(tui.tunnel_.view) != "Tunnel off") return 12;
        tui.requested_ = true;
        tui.routing_issue_ = "Lab not ready (Saslik connected)";
        tui.retry_.start();
        const auto unavailable = tui.routingSummary();
        if (!unavailable.contains("Lab not ready") || !unavailable.contains("retry in")
            || unavailable.contains("Tunnel off") || unavailable.contains("connecting")) return 18;
        tui.retry_.invalidate();
        tui.routing_issue_ = "Helper session ended · E authorizes again";
        if (tui.routingSummary().contains("retry in") || !tui.routingSummary().contains("E authorizes")) return 19;
        tui.routing_issue_.clear();
        tui.requested_ = false;
        if (!runtimeTrustDirectory({}).isEmpty() || !runtimeTrustEnvironment({}).isEmpty()) return 6;
        if (!prepareRuntimeTrust({}).contains("Select exactly one CA")
            || !removeRuntimeTrust({}).contains("Select exactly one CA")) return 7;
        // Invalid endpoints are rejected without starting systemd or a helper.
        if (tui.tunnel_.start("http://localhost/pair") || tui.tunnel_.running()) return 3;
        if (tui.tunnel_.start("skewer://localhost:8766/pair#secret") || tui.tunnel_.running()) return 4;
        if (tui.tunnel_.start("skewer:///pair") || tui.tunnel_.running()) return 8;
        tui.tunnel_.view.selected = true;
        tui.tunnel_.view.fresh = true;
        tui.tunnel_.poll();
        if (tui.tunnel_.view.fresh || tui.tunnel_.view.state != "failed") return 9;
        tui.tunnel_.stop();
        tui.tunnel_.view.mode = "tunnel"; tui.tunnel_.view.requested = true;
        if (!Tuntom::compactStatus(tui.tunnel_.view, true).contains("missing")) return 5;
        ProcessInfo process;
        process.pid = 101;
        process.parent_pid = 1;
        process.name = "skewer-tui-test";
        process.executable = "/opt/skewer-tui-test";
        process.cgroup = "/app-tui-test.scope";
        tui.model_.setProcesses({process});
        tui.expanded_.insert("section:applications");
        tui.expanded_.insert("section:other");
        tui.rebuildRows();
        for (int row = 0; row < tui.rows_.size(); ++row)
            if (tui.rows_[row].index.data(ApplicationModel::NodeTypeRole).toInt()
                == static_cast<int>(ApplicationModel::NodeType::Application)) tui.selected_ = row;
        const QString selected = tui.rows_.at(tui.selected_).stable_id;
        for (int iteration = 0; iteration < 100; ++iteration) {
            process.command_line = QString("test %1").arg(iteration);
            tui.model_.setProcesses({process});
            // Incremental updates preserve the selection's persistent index.
            if (!tui.rows_.at(tui.selected_).index.isValid()
                || tui.rows_.at(tui.selected_).index.data(ApplicationModel::StableIdRole).toString() != selected)
                return 1;
            tui.rebuildRows();
            if (tui.rows_.at(tui.selected_).stable_id != selected) return 2;
        }
        tui.model_.setProcesses({});
        tui.rebuildRows();
        tui.moveSelection(1);
        tui.toggleExpanded();
        return 0;
    }
};

int main(int argc, char** argv)
{
    QApplication app(argc, argv);
    QTemporaryDir config;
    QSettings::setDefaultFormat(QSettings::IniFormat);
    QSettings::setPath(QSettings::IniFormat, QSettings::UserScope, config.path());
    qputenv("XDG_DATA_HOME", config.path().toUtf8());
    return TuiTest::run();
}
