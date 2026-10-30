Unicode True
ManifestDPIAware true
RequestExecutionLevel admin
SetCompressor /SOLID lzma

!include "MUI2.nsh"
!include "LogicLib.nsh"

!ifndef VERSION
  !error "VERSION is required"
!endif
!ifndef PAYLOAD
  !error "PAYLOAD is required"
!endif
!ifndef OUTPUT
  !error "OUTPUT is required"
!endif

Name "Skewer ${VERSION}"
OutFile "${OUTPUT}"
InstallDir "$PROGRAMFILES64\Skewer"
InstallDirRegKey HKLM "Software\Smithproxy\Skewer" "InstallLocation"
BrandingText "Smithproxy · Saslik"
ShowInstDetails show
ShowUninstDetails show

VIProductVersion "${VERSION}"
VIAddVersionKey /LANG=1033 "ProductName" "Skewer"
VIAddVersionKey /LANG=1033 "CompanyName" "Smithproxy"
VIAddVersionKey /LANG=1033 "FileDescription" "Skewer setup"
VIAddVersionKey /LANG=1033 "FileVersion" "${VERSION}"
VIAddVersionKey /LANG=1033 "ProductVersion" "${VERSION}"

!define MUI_ABORTWARNING
!define MUI_FINISHPAGE_NOAUTOCLOSE
!define MUI_FINISHPAGE_LINK "Open the Skewer documentation"
!define MUI_FINISHPAGE_LINK_LOCATION "https://github.com/astibal/saslik-skewer"

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_WELCOME
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_COMPONENTS
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_UNPAGE_FINISH

!insertmacro MUI_LANGUAGE "English"

Var InstallResult

Section "Skewer application and routing service" SEC_CORE
  SectionIn RO
  SetShellVarContext all
  RMDir /r "$TEMP\SkewerSetupPayload-${VERSION}"
  SetOutPath "$TEMP\SkewerSetupPayload-${VERSION}"
  File /r "${PAYLOAD}\*"

  nsExec::ExecToStack 'powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$TEMP\SkewerSetupPayload-${VERSION}\install-wizard.ps1" -PackageDirectory "$TEMP\SkewerSetupPayload-${VERSION}" -Destination "$INSTDIR"'
  Pop $InstallResult
  Pop $0
  ${If} $InstallResult != 0
    DetailPrint "$0"
    IfSilent install_silent_error install_interactive_error
install_interactive_error:
    MessageBox MB_ICONSTOP|MB_OK "Skewer installation failed.$\r$\n$\r$\n$0"
    Abort
install_silent_error:
    SetErrorLevel $InstallResult
    Quit
  ${EndIf}
  RMDir /r "$TEMP\SkewerSetupPayload-${VERSION}"

  WriteUninstaller "$INSTDIR\Uninstall.exe"
  WriteRegStr HKLM "Software\Smithproxy\Skewer" "InstallLocation" "$INSTDIR"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Skewer" "DisplayName" "Skewer"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Skewer" "DisplayVersion" "${VERSION}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Skewer" "Publisher" "Smithproxy"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Skewer" "InstallLocation" "$INSTDIR"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Skewer" "DisplayIcon" "$INSTDIR\skewer.exe"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Skewer" "UninstallString" '"$INSTDIR\Uninstall.exe"'
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Skewer" "NoModify" 1
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Skewer" "NoRepair" 1
  CreateDirectory "$SMPROGRAMS\Skewer"
  CreateShortcut "$SMPROGRAMS\Skewer\Skewer.lnk" "$INSTDIR\skewer.exe" "" "$INSTDIR\skewer.exe"
  CreateShortcut "$SMPROGRAMS\Skewer\Uninstall Skewer.lnk" "$INSTDIR\Uninstall.exe"
SectionEnd

Section /o "Desktop shortcut" SEC_DESKTOP
  SetShellVarContext all
  CreateShortcut "$DESKTOP\Skewer.lnk" "$INSTDIR\skewer.exe" "" "$INSTDIR\skewer.exe"
SectionEnd

LangString DESC_SEC_CORE ${LANG_ENGLISH} "Install the Skewer desktop application, signed network dependencies and the protected routing service."
LangString DESC_SEC_DESKTOP ${LANG_ENGLISH} "Create a shortcut on the public desktop."
!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
  !insertmacro MUI_DESCRIPTION_TEXT ${SEC_CORE} $(DESC_SEC_CORE)
  !insertmacro MUI_DESCRIPTION_TEXT ${SEC_DESKTOP} $(DESC_SEC_DESKTOP)
!insertmacro MUI_FUNCTION_DESCRIPTION_END

Section "un.Skewer application" UNSEC_CORE
  SectionIn RO
  SetShellVarContext all
  nsExec::ExecToStack 'powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$INSTDIR\uninstall-wizard.ps1" -InstallDirectory "$INSTDIR"'
  Pop $InstallResult
  Pop $0
  ${If} $InstallResult != 0
    DetailPrint "$0"
    IfSilent uninstall_silent_error uninstall_interactive_error
uninstall_interactive_error:
    MessageBox MB_ICONSTOP|MB_OK "Skewer uninstall failed.$\r$\n$\r$\n$0"
    Abort
uninstall_silent_error:
    SetErrorLevel $InstallResult
    Quit
  ${EndIf}
  Delete "$DESKTOP\Skewer.lnk"
  RMDir /r "$SMPROGRAMS\Skewer"
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Skewer"
  DeleteRegKey HKLM "Software\Smithproxy\Skewer"
SectionEnd

Section /o "un.Pairing and user settings" UNSEC_SETTINGS
  nsExec::ExecToStack 'powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$INSTDIR\uninstall-wizard.ps1" -InstallDirectory "$INSTDIR" -RemoveSettings'
  Pop $InstallResult
  Pop $0
  ${If} $InstallResult != 0
    DetailPrint "$0"
    IfSilent settings_silent_error settings_interactive_error
settings_interactive_error:
    MessageBox MB_ICONSTOP|MB_OK "Removing Skewer user data failed.$\r$\n$\r$\n$0"
    Abort
settings_silent_error:
    SetErrorLevel $InstallResult
    Quit
  ${EndIf}
SectionEnd

Function un.onUninstSuccess
  RMDir /r "$INSTDIR"
FunctionEnd

LangString DESC_UNSEC_CORE ${LANG_ENGLISH} "Remove the application and its idle routing service. Pairing and settings are preserved."
LangString DESC_UNSEC_SETTINGS ${LANG_ENGLISH} "Also permanently remove pairing credentials and this user's preferences."
!insertmacro MUI_UNFUNCTION_DESCRIPTION_BEGIN
  !insertmacro MUI_DESCRIPTION_TEXT ${UNSEC_CORE} $(DESC_UNSEC_CORE)
  !insertmacro MUI_DESCRIPTION_TEXT ${UNSEC_SETTINGS} $(DESC_UNSEC_SETTINGS)
!insertmacro MUI_UNFUNCTION_DESCRIPTION_END
