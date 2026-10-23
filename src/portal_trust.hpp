#pragma once

class QNetworkAccessManager;
class QWidget;

// Trust-on-first-use for the installation-scoped Saslik Portal certificate.
// The certificate is never added to the system trust store.
void installPortalTrust(QNetworkAccessManager* manager, QWidget* parent);
