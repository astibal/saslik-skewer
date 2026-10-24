#pragma once
#include <QDialog>

// Programmatic layout only; settings are saved only after explicit acceptance.
class PreferencesDialog final : public QDialog {
public:
    explicit PreferencesDialog(QWidget* parent = nullptr);
};
