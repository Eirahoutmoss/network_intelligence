; Nexus — Network Intelligence Platform: Windows x64 installer (NSIS 3).
;
; Built by deployments/windows/build.sh. Heavy lifting (preflight checks,
; secrets, configuration, service, permissions, firewall, health checks,
; upgrade backup and rollback) is done by "nexus.exe install"; this script
; copies files, asks the few questions, shows progress and registers the
; application with Windows.
;
; Silent installation (standard NSIS /S and /D, plus):
;   /PORT=8080        web port (default: keep current, else 8080; a free one is chosen if taken)
;   /LAN=1            reachable from other computers (firewall rule for domain/private networks)
;   /DEMO=1           start the simulated demo network
;   /NOSTART          install without starting the service
;   /NODESKTOP        no desktop shortcut
;   /NOBROWSER        do not open the browser at the end
;   /LOG=path         write the installation log to this file as well
;   /DATADIR=path     data directory (default %ProgramData%\Nexus)
; Exit codes: 0 ok, 1 cancelled, 2 installation failed, 3 upgrade failed (previous version restored)

Unicode true
ManifestDPIAware true
ManifestSupportedOS Win10
RequestExecutionLevel admin
SetCompressor /SOLID lzma
SetCompressorDictSize 64

!ifndef VERSION
  !error "VERSION is not defined (use build.sh)"
!endif
!define PRODUCT "Nexus"
!define PRODUCT_LONG "Nexus Network Intelligence"
!define AUTHOR "Hasan Güler"
!define REGKEY "Software\Nexus"
!define UNINSTKEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\Nexus"
!define APPDIR "$INSTDIR\app\${VERSION}"

Name "${PRODUCT} ${VERSION}"
Caption "${PRODUCT} ${VERSION} Setup"
OutFile "${OUTFILE}"
InstallDir "$PROGRAMFILES64\Nexus"
BrandingText "Nexus v1 · ${AUTHOR}"
ShowInstDetails show
ShowUninstDetails show

VIProductVersion "${VERSION}.0"
VIFileVersion "${VERSION}.0"
VIAddVersionKey "ProductName" "${PRODUCT_LONG}"
VIAddVersionKey "ProductVersion" "${VERSION}"
VIAddVersionKey "FileVersion" "${VERSION}"
VIAddVersionKey "FileDescription" "${PRODUCT_LONG} Setup"
VIAddVersionKey "CompanyName" "${AUTHOR}"
VIAddVersionKey "LegalCopyright" "Copyright ${AUTHOR}. Apache License 2.0."

!include "MUI2.nsh"
!include "LogicLib.nsh"
!include "x64.nsh"
!include "WinVer.nsh"
!include "FileFunc.nsh"
!include "WordFunc.nsh"
!include "nsDialogs.nsh"

Var Upgrade          ; 1 when an earlier version is installed
Var OldVersion
Var DataDir
Var Port
Var Lan
Var Demo
Var NoStart
Var WantDesktop
Var NoBrowser
Var LogFile
Var Status           ; ok | installed | failed | rolled-back | rollback-failed
Var Url
Var ErrorText
Var FinishTitle
Var FinishText
; options page controls
Var hPort
Var hLan
Var hDesktop
Var hDemo

!define MUI_ICON "${ASSETS}\nexus.ico"
!define MUI_UNICON "${ASSETS}\nexus.ico"
!define MUI_WELCOMEFINISHPAGE_BITMAP "${ASSETS}\welcome.bmp"
!define MUI_UNWELCOMEFINISHPAGE_BITMAP "${ASSETS}\welcome.bmp"
!define MUI_HEADERIMAGE
!define MUI_HEADERIMAGE_RIGHT
!define MUI_HEADERIMAGE_BITMAP "${ASSETS}\header.bmp"
!define MUI_HEADERIMAGE_UNBITMAP "${ASSETS}\header.bmp"
!define MUI_ABORTWARNING

; ------------------------------------------------------------------ pages
!define MUI_WELCOMEPAGE_TITLE "Nexus ${VERSION}"
!define MUI_WELCOMEPAGE_TEXT "Nexus v1 — Network Intelligence Platform$\r$\n$\r$\nSetup installs Nexus as a Windows service with its own database. Nothing else needs to be installed: no Docker, WSL, PostgreSQL or other components, and no internet access is required.$\r$\n$\r$\nYou will create the administrator account in the browser at the end.$\r$\n$\r$\n$\r$\nDesigned and developed by ${AUTHOR}$\r$\n$\"Sen ağa erişimi ver. Gerisini sistem anlamaya çalışsın.$\""
!insertmacro MUI_PAGE_WELCOME
!define MUI_PAGE_CUSTOMFUNCTION_PRE SkipOnUpgrade
!insertmacro MUI_PAGE_DIRECTORY
Page custom OptionsPage OptionsLeave
!define MUI_PAGE_HEADER_TEXT "Installing Nexus"
!define MUI_PAGE_HEADER_SUBTEXT "Checking this computer and setting up Nexus. This takes about a minute."
!insertmacro MUI_PAGE_INSTFILES
!define MUI_FINISHPAGE_TITLE "$FinishTitle"
!define MUI_FINISHPAGE_TEXT "$FinishText"
!define MUI_FINISHPAGE_RUN
!define MUI_FINISHPAGE_RUN_TEXT "Open Nexus"
!define MUI_FINISHPAGE_RUN_FUNCTION OpenNexus
!define MUI_PAGE_CUSTOMFUNCTION_SHOW FinishShow
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
UninstPage custom un.DataPage un.DataLeave
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "English"

; ------------------------------------------------------------------ helpers
!macro ParseOption NAME VAR DEFAULT
  ClearErrors
  ${GetOptions} $R9 "/${NAME}=" ${VAR}
  ${If} ${Errors}
    StrCpy ${VAR} "${DEFAULT}"
  ${EndIf}
!macroend

!macro ParseFlag NAME VAR
  ClearErrors
  ${GetOptions} $R9 "/${NAME}" $R8
  ${IfNot} ${Errors}
    StrCpy ${VAR} "1"
  ${EndIf}
!macroend

; ------------------------------------------------------------------ init
Function .onInit
  SetShellVarContext all
  SetRegView 64
  InitPluginsDir

  ; one installer at a time
  System::Call 'kernel32::CreateMutex(p 0, i 0, t "NexusSetupMutex") p .r1 ?e'
  Pop $R0
  ${If} $R0 == 183
    MessageBox MB_OK|MB_ICONINFORMATION "Nexus Setup is already running." /SD IDOK
    Abort
  ${EndIf}

  ${IfNot} ${RunningX64}
    MessageBox MB_OK|MB_ICONSTOP "Nexus requires a 64-bit (x64) version of Windows." /SD IDOK
    SetErrorLevel 2
    Abort
  ${EndIf}
  ${IfNot} ${AtLeastWin10}
    MessageBox MB_OK|MB_ICONSTOP "Nexus requires Windows 10 (1809) / Windows Server 2019 or newer." /SD IDOK
    SetErrorLevel 2
    Abort
  ${EndIf}

  ; defaults and command line
  ${GetParameters} $R9
  !insertmacro ParseOption "PORT" $Port ""
  !insertmacro ParseOption "LAN" $Lan ""
  !insertmacro ParseOption "DEMO" $Demo ""
  !insertmacro ParseOption "LOG" $LogFile ""
  !insertmacro ParseOption "DATADIR" $DataDir "$APPDATA\Nexus"
  StrCpy $NoStart "0"
  StrCpy $NoBrowser "0"
  StrCpy $WantDesktop "1"
  !insertmacro ParseFlag "NOSTART" $NoStart
  !insertmacro ParseFlag "NOBROWSER" $NoBrowser
  ClearErrors
  ${GetOptions} $R9 "/NODESKTOP" $R8
  ${IfNot} ${Errors}
    StrCpy $WantDesktop "0"
  ${EndIf}

  ; existing installation
  StrCpy $Upgrade "0"
  ReadRegStr $OldVersion HKLM "${REGKEY}" "Version"
  ${If} $OldVersion != ""
    StrCpy $Upgrade "1"
    ReadRegStr $R0 HKLM "${REGKEY}" "InstallDir"
    ${If} $R0 != ""
      StrCpy $INSTDIR $R0
    ${EndIf}
    ReadRegStr $R0 HKLM "${REGKEY}" "DataDir"
    ${If} $R0 != ""
    ${AndIf} $DataDir == "$APPDATA\Nexus"
      StrCpy $DataDir $R0
    ${EndIf}
    ${VersionCompare} "${VERSION}" $OldVersion $R1
    ${If} $R1 == 2
      MessageBox MB_OK|MB_ICONSTOP "Nexus $OldVersion is installed, which is newer than ${VERSION}. Downgrading is not supported because the database may already use a newer format." /SD IDOK
      SetErrorLevel 2
      Abort
    ${EndIf}
  ${EndIf}

  ; current settings as defaults for the options page
  ${If} $Port == ""
    ReadRegStr $Port HKLM "${REGKEY}" "Port"
  ${EndIf}
  ${If} $Port == ""
    StrCpy $Port "8080"
  ${EndIf}
  ${If} $Lan == ""
    ReadRegStr $Lan HKLM "${REGKEY}" "Lan"
  ${EndIf}
  ${If} $Lan == ""
    StrCpy $Lan "0"
  ${EndIf}
  ${If} $Demo == ""
    ReadRegStr $Demo HKLM "${REGKEY}" "Demo"
  ${EndIf}
  ${If} $Demo == ""
    StrCpy $Demo "0"
  ${EndIf}
FunctionEnd

Function SkipOnUpgrade
  ${If} $Upgrade == "1"
    Abort
  ${EndIf}
FunctionEnd

Function OptionsPage
  ${If} $Upgrade == "1"
    !insertmacro MUI_HEADER_TEXT "Upgrade Nexus $OldVersion to ${VERSION}" "Your devices, topology, locations, users, credentials and settings are kept. A backup is made before upgrading."
  ${Else}
    !insertmacro MUI_HEADER_TEXT "Options" "Most installations can keep these defaults."
  ${EndIf}
  nsDialogs::Create 1018
  Pop $0
  ${If} $0 == error
    Abort
  ${EndIf}
  ${NSD_CreateLabel} 0 0 100% 12u "Web interface port (another free port is chosen automatically if this one is in use):"
  Pop $0
  ${NSD_CreateNumber} 0 14u 60u 12u "$Port"
  Pop $hPort
  ${NSD_CreateCheckbox} 0 38u 100% 12u "Allow access from other computers on the network"
  Pop $hLan
  ${NSD_CreateLabel} 12u 51u 95% 20u "Adds a Windows Firewall rule for this port on domain and private networks only. Leave off to use Nexus on this computer only (also works over remote desktop tools)."
  Pop $0
  ${NSD_CreateCheckbox} 0 78u 100% 12u "Create a desktop shortcut"
  Pop $hDesktop
  ${NSD_CreateCheckbox} 0 96u 100% 12u "Include the demo network (simulated switches and devices for evaluation)"
  Pop $hDemo
  ${If} $Lan == "1"
    ${NSD_Check} $hLan
  ${EndIf}
  ${If} $WantDesktop == "1"
    ${NSD_Check} $hDesktop
  ${EndIf}
  ${If} $Demo == "1"
    ${NSD_Check} $hDemo
  ${EndIf}
  nsDialogs::Show
FunctionEnd

Function OptionsLeave
  ${NSD_GetText} $hPort $Port
  ${If} $Port < 1
  ${OrIf} $Port > 65535
    MessageBox MB_OK|MB_ICONEXCLAMATION "Enter a port between 1 and 65535."
    Abort
  ${EndIf}
  ${NSD_GetState} $hLan $0
  ${If} $0 == ${BST_CHECKED}
    StrCpy $Lan "1"
  ${Else}
    StrCpy $Lan "0"
  ${EndIf}
  ${NSD_GetState} $hDesktop $0
  ${If} $0 == ${BST_CHECKED}
    StrCpy $WantDesktop "1"
  ${Else}
    StrCpy $WantDesktop "0"
  ${EndIf}
  ${NSD_GetState} $hDemo $0
  ${If} $0 == ${BST_CHECKED}
    StrCpy $Demo "1"
  ${Else}
    StrCpy $Demo "0"
  ${EndIf}
FunctionEnd

; ------------------------------------------------------------------ install
Section "Nexus" SecMain
  SectionIn RO
  SetShellVarContext all
  SetRegView 64
  ${DisableX64FSRedirection}
  SetDetailsPrint both
  StrCpy $Status "failed"

  ; Repairing the same version: its files are in use by the running service.
  ${If} ${FileExists} "${APPDIR}\nexus.exe"
    DetailPrint "Stopping Nexus to repair version ${VERSION}..."
    nsExec::Exec '"${APPDIR}\nexus.exe" service stop'
    Pop $0
  ${EndIf}

  DetailPrint "Copying files..."
  SetDetailsPrint textonly
  SetOutPath "${APPDIR}"
  File /r "${STAGE}\app\${VERSION}\*.*"
  SetOutPath "$INSTDIR"
  File "/oname=$INSTDIR\nexus.ico" "${ASSETS}\nexus.ico"
  File "/oname=$INSTDIR\LICENSE.txt" "${STAGE}\app\${VERSION}\LICENSE"
  WriteUninstaller "$INSTDIR\Uninstall Nexus.exe"
  SetDetailsPrint both
  DetailPrint "Files copied."
  DetailPrint ""

  StrCpy $R0 ""
  ${If} $NoStart == "1"
    StrCpy $R0 "--no-start"
  ${EndIf}

  retry:
  Delete "$PLUGINSDIR\result.ini"
  nsExec::ExecToLog '"${APPDIR}\nexus.exe" install --utf16 --data "$DataDir" --port $Port --lan $Lan --demo $Demo --result "$PLUGINSDIR\result.ini" $R0'
  Pop $0
  ReadINIStr $Status "$PLUGINSDIR\result.ini" "result" "status"
  ReadINIStr $Url "$PLUGINSDIR\result.ini" "result" "url"
  ReadINIStr $ErrorText "$PLUGINSDIR\result.ini" "result" "error"
  ReadINIStr $R1 "$PLUGINSDIR\result.ini" "result" "port"
  ${If} $R1 != ""
    StrCpy $Port $R1
  ${EndIf}
  ${If} $Status == ""
    StrCpy $Status "failed"
    StrCpy $ErrorText "the setup helper did not finish (exit code $0)"
  ${EndIf}

  ${If} $Status == "failed"
    MessageBox MB_RETRYCANCEL|MB_ICONEXCLAMATION "Nexus could not finish setup:$\r$\n$\r$\n$ErrorText$\r$\n$\r$\nThe steps above show which part failed. Logs: $DataDir\logs$\r$\n$\r$\nRetry now?" /SD IDCANCEL IDRETRY retry
  ${EndIf}

  ; Register with Windows even after a failed start, so Retry, repair and
  ; uninstall work from Settings > Apps.
  WriteRegStr HKLM "${REGKEY}" "InstallDir" "$INSTDIR"
  WriteRegStr HKLM "${REGKEY}" "DataDir" "$DataDir"
  WriteRegStr HKLM "${REGKEY}" "Port" "$Port"
  WriteRegStr HKLM "${REGKEY}" "Lan" "$Lan"
  WriteRegStr HKLM "${REGKEY}" "Demo" "$Demo"
  ${If} $Status != "rolled-back"
    WriteRegStr HKLM "${REGKEY}" "Version" "${VERSION}"
    WriteRegStr HKLM "${REGKEY}" "AppDir" "${APPDIR}"
  ${EndIf}
  ${If} $Url != ""
    WriteRegStr HKLM "${REGKEY}" "Url" "$Url"
  ${Else}
    StrCpy $Url "http://localhost:$Port/"
  ${EndIf}

  WriteRegStr HKLM "${UNINSTKEY}" "DisplayName" "${PRODUCT_LONG}"
  WriteRegStr HKLM "${UNINSTKEY}" "DisplayVersion" "${VERSION}"
  WriteRegStr HKLM "${UNINSTKEY}" "Publisher" "${AUTHOR}"
  WriteRegStr HKLM "${UNINSTKEY}" "DisplayIcon" "$INSTDIR\nexus.ico"
  WriteRegStr HKLM "${UNINSTKEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKLM "${UNINSTKEY}" "UninstallString" '"$INSTDIR\Uninstall Nexus.exe"'
  WriteRegStr HKLM "${UNINSTKEY}" "QuietUninstallString" '"$INSTDIR\Uninstall Nexus.exe" /S'
  WriteRegStr HKLM "${UNINSTKEY}" "URLInfoAbout" "https://github.com/Eirahoutmoss/network_intelligence"
  WriteRegDWORD HKLM "${UNINSTKEY}" "NoModify" 1
  WriteRegDWORD HKLM "${UNINSTKEY}" "NoRepair" 1
  ${GetSize} "$INSTDIR" "/S=0K" $R2 $R3 $R4
  IntFmt $R2 "0x%08X" $R2
  WriteRegDWORD HKLM "${UNINSTKEY}" "EstimatedSize" "$R2"

  ; Shortcuts open the web interface in the default browser.
  CreateDirectory "$SMPROGRAMS\Nexus"
  Delete "$SMPROGRAMS\Nexus\*.url"
  WriteINIStr "$SMPROGRAMS\Nexus\Nexus.url" "InternetShortcut" "URL" "$Url"
  WriteINIStr "$SMPROGRAMS\Nexus\Nexus.url" "InternetShortcut" "IconFile" "$INSTDIR\nexus.ico"
  WriteINIStr "$SMPROGRAMS\Nexus\Nexus.url" "InternetShortcut" "IconIndex" "0"
  CreateShortCut "$SMPROGRAMS\Nexus\Nexus Diagnostics.lnk" "${APPDIR}\nexus.exe" "diagnostics --gui" "$INSTDIR\nexus.ico" 0 SW_SHOWMINIMIZED "" "Create a diagnostic bundle (secrets removed) on your desktop"
  ${If} $WantDesktop == "1"
    WriteINIStr "$DESKTOP\Nexus.url" "InternetShortcut" "URL" "$Url"
    WriteINIStr "$DESKTOP\Nexus.url" "InternetShortcut" "IconFile" "$INSTDIR\nexus.ico"
    WriteINIStr "$DESKTOP\Nexus.url" "InternetShortcut" "IconIndex" "0"
  ${Else}
    Delete "$DESKTOP\Nexus.url"
  ${EndIf}

  ; Remove older application versions after a successful upgrade.
  ${If} $Status == "ok"
  ${OrIf} $Status == "installed"
    FindFirst $R5 $R6 "$INSTDIR\app\*"
    loop:
      StrCmp $R6 "" loopdone
      StrCmp $R6 "." next
      StrCmp $R6 ".." next
      StrCmp $R6 "${VERSION}" next
      DetailPrint "Removing old version $R6"
      RMDir /r "$INSTDIR\app\$R6"
    next:
      FindNext $R5 $R6
      Goto loop
    loopdone:
    FindClose $R5
  ${EndIf}

  ${Select} $Status
    ${Case} "ok"
      StrCpy $FinishTitle "Nexus is ready"
      StrCpy $FinishText "Nexus ${VERSION} is installed and running.$\r$\n$\r$\n$Url$\r$\n$\r$\nOpen it to create the administrator account (first installation) or sign in. Nexus starts automatically with Windows. Start menu → Nexus opens it again."
    ${Case} "installed"
      StrCpy $FinishTitle "Nexus is installed"
      StrCpy $FinishText "Nexus ${VERSION} is installed but was not started (/NOSTART). Start the Nexus service in Services or restart Windows."
    ${Case} "rolled-back"
      StrCpy $FinishTitle "Upgrade not completed"
      StrCpy $FinishText "Nexus ${VERSION} could not start, so Nexus $OldVersion was restored and is running with your data unchanged.$\r$\n$\r$\nReason: $ErrorText$\r$\n$\r$\nLogs are in $DataDir\logs. Start menu → Nexus Diagnostics creates a bundle for support."
      SetErrorLevel 3
    ${Default}
      StrCpy $FinishTitle "Nexus setup did not finish"
      StrCpy $FinishText "$ErrorText$\r$\n$\r$\nNo data was deleted. Fix the cause shown above and run Setup again; it continues where it stopped.$\r$\n$\r$\nLogs are in $DataDir\logs. Start menu → Nexus Diagnostics creates a bundle for support."
      SetErrorLevel 2
  ${EndSelect}

  ${If} $LogFile != ""
    Call DumpLog
  ${EndIf}
  ${EnableX64FSRedirection}
SectionEnd

Function .onInstSuccess
  ${If} ${Silent}
  ${AndIf} $Status == "ok"
  ${AndIf} $NoBrowser != "1"
    Call OpenNexus
  ${EndIf}
FunctionEnd

Function FinishShow
  ${If} $Status != "ok"
  ${OrIf} $NoBrowser == "1"
    ShowWindow $mui.FinishPage.Run 0
    SendMessage $mui.FinishPage.Run ${BM_SETCHECK} ${BST_UNCHECKED} 0
  ${EndIf}
FunctionEnd

Function OpenNexus
  ; Explorer hands the URL to the signed-in user's default browser, so the
  ; browser does not inherit the installer's administrator rights.
  Exec '"$WINDIR\explorer.exe" "$Url"'
FunctionEnd

; Writes the details list to $LogFile (silent installs, /LOG=).
Function DumpLog
  Push $0
  Push $1
  Push $2
  Push $3
  Push $4
  Push $5
  Push $6
  FindWindow $0 "#32770" "" $HWNDPARENT
  GetDlgItem $0 $0 1016
  StrCmp $0 0 nowindow
  FileOpen $5 $LogFile "w"
  StrCmp $5 "" dumpdone
  FileWriteUTF16LE /BOM $5 ""
  SendMessage $0 ${LVM_GETITEMCOUNT} 0 0 $6
  System::Call '*(&t${NSIS_MAX_STRLEN})p.r3'
  StrCpy $2 0
  System::Call "*(i, i, i, i, i, p, i, i, i) p (0, 0, 0, 0, 0, r3, ${NSIS_MAX_STRLEN}) .r1"
  dumploop:
    StrCmp $2 $6 dumpfree
    System::Call "User32::SendMessage(p, i, p, p) p ($0, ${LVM_GETITEMTEXT}, $2, r1)"
    System::Call "*$3(&t${NSIS_MAX_STRLEN} .r4)"
    FileWriteUTF16LE $5 "$4$\r$\n"
    IntOp $2 $2 + 1
    Goto dumploop
  dumpfree:
  FileClose $5
  System::Free $1
  System::Free $3
  Goto dumpdone
  nowindow:
  ; silent install: there is no details window; use the structured log
  CopyFiles /SILENT "$DataDir\logs\install.log" "$LogFile"
  dumpdone:
  ; the structured install log (JSON lines) is always available too
  CopyFiles /SILENT "$DataDir\logs\install.log" "$LogFile.jsonl"
  Pop $6
  Pop $5
  Pop $4
  Pop $3
  Pop $2
  Pop $1
  Pop $0
FunctionEnd

; ------------------------------------------------------------------ uninstall
Var un.Purge
Var un.hPurge
Var un.DataDir

Function un.onInit
  SetShellVarContext all
  SetRegView 64
  ReadRegStr $un.DataDir HKLM "${REGKEY}" "DataDir"
  ${If} $un.DataDir == ""
    StrCpy $un.DataDir "$APPDATA\Nexus"
  ${EndIf}
  StrCpy $un.Purge "0"
  ; Silent data removal needs an explicit /PURGEDATA=YES
  ${GetParameters} $R9
  ClearErrors
  ${GetOptions} $R9 "/PURGEDATA=" $R8
  ${IfNot} ${Errors}
  ${AndIf} $R8 == "YES"
    StrCpy $un.Purge "1"
  ${EndIf}
FunctionEnd

Function un.DataPage
  !insertmacro MUI_HEADER_TEXT "Your network data" "Choose what happens to the inventory."
  nsDialogs::Create 1018
  Pop $0
  ${NSD_CreateLabel} 0 0 100% 36u "By default Nexus keeps its data in $un.DataDir: the device inventory, topology, locations, users, encrypted credentials, keys, backups and logs. Installing Nexus again later continues with this data."
  Pop $0
  ${NSD_CreateCheckbox} 0 44u 100% 12u "Also delete all Nexus data (cannot be undone)"
  Pop $un.hPurge
  nsDialogs::Show
FunctionEnd

Function un.DataLeave
  ${NSD_GetState} $un.hPurge $0
  ${If} $0 == ${BST_CHECKED}
    MessageBox MB_YESNO|MB_ICONEXCLAMATION|MB_DEFBUTTON2 "Permanently delete ALL Nexus data?$\r$\n$\r$\nThis removes the network inventory, stored credentials, encryption keys, backups and logs in $un.DataDir.$\r$\n$\r$\nExport a backup first if you may need it." IDYES +2
    Abort
    StrCpy $un.Purge "1"
  ${Else}
    StrCpy $un.Purge "0"
  ${EndIf}
FunctionEnd

Section "Uninstall"
  SetShellVarContext all
  SetRegView 64
  ${DisableX64FSRedirection}
  ReadRegStr $R0 HKLM "${REGKEY}" "AppDir"
  ${IfNot} ${FileExists} "$R0\nexus.exe"
    ; fall back to any installed version
    FindFirst $R5 $R6 "$INSTDIR\app\*"
    FindClose $R5
    StrCpy $R0 "$INSTDIR\app\$R6"
  ${EndIf}
  ${If} ${FileExists} "$R0\nexus.exe"
    ${If} $un.Purge == "1"
      nsExec::ExecToLog '"$R0\nexus.exe" uninstall --data "$un.DataDir" --purge-data --confirm DELETE-ALL-DATA'
    ${Else}
      nsExec::ExecToLog '"$R0\nexus.exe" uninstall --data "$un.DataDir"'
    ${EndIf}
    Pop $0
    ${If} $0 != 0
      DetailPrint "The service could not be removed completely (exit code $0)."
    ${EndIf}
  ${EndIf}

  RMDir /r "$INSTDIR\app"
  Delete "$INSTDIR\nexus.ico"
  Delete "$INSTDIR\LICENSE.txt"
  Delete "$INSTDIR\Uninstall Nexus.exe"
  RMDir "$INSTDIR"
  Delete "$SMPROGRAMS\Nexus\Nexus.url"
  Delete "$SMPROGRAMS\Nexus\Nexus Diagnostics.lnk"
  RMDir "$SMPROGRAMS\Nexus"
  Delete "$DESKTOP\Nexus.url"
  DeleteRegKey HKLM "${UNINSTKEY}"
  DeleteRegKey HKLM "${REGKEY}"
  ${If} $un.Purge == "1"
    DetailPrint "All Nexus data was deleted."
  ${Else}
    DetailPrint "Your data was kept in $un.DataDir."
  ${EndIf}
  ${EnableX64FSRedirection}
SectionEnd
