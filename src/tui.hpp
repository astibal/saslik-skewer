#pragma once

#include "application_model.hpp"
#include "cgroup_manager.hpp"
#include "routing_controller.hpp"
#include "tui_tunnel.hpp"

#include <QPersistentModelIndex>
#include <QSet>
#include <QFuture>
#include <functional>

class Tui {
public:
    int run();

private:
    friend class TuiTest;
    struct Row {
        QPersistentModelIndex index;
        int depth{};
        QString stable_id;
    };

    void rebuildRows();
    void draw();
    QString routingSummary() const;
    void moveSelection(int delta);
    void toggleExpanded();
    void changeRouting(bool routed);
    void launch();
    void shell();
    void configureRouting();
    void disableRouting();
    void enableRouting();
    void restoreRoutingIntent();
    void startSession(const std::function<PrivilegedSession::Reply()>& authorize,
                      const std::function<void()>& resume);
    void configureSaslik();
    void configureTransport();
    void showTunnelDetails();
    void pollTunnel();
    void caTrust();
    void runtimeTrust();
    void connections();
    void preferences();
    void pairSaslik();
    int choose(const QString& title, const QStringList& items);
    void rememberCertificate(const QJsonObject& state);
    [[nodiscard]] QString prompt(const QString& label, bool secret = false);
    [[nodiscard]] QVector<pid_t> selectedPids() const;

    ApplicationModel model_;
    CgroupManager cgroups_;
    RoutingController routing_;
    QVector<Row> rows_;
    QSet<QString> expanded_;
    int selected_{};
    bool routing_active_{};
    QString routing_next_hop_;
    QString status_{QStringLiteral("Ready")};
    QString routing_issue_;
    TuiTunnel tunnel_;
    bool requested_{};
    bool tunnel_pinned_{};
    QElapsedTimer retry_;
    QByteArray certificate_;
    QFuture<ConnectionSnapshot> connections_pending_;
    QElapsedTimer connections_age_;
    bool connections_started_{};
};
