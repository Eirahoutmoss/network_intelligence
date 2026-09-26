package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"

	"github.com/Eirahoutmoss/network_intelligence/backend/internal/deploy"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/platform"
)

// platformCommand handles Windows-only commands:
//
//	service run|start|stop|restart|status   Windows service
//	install / uninstall / preflight          used by the installer
//	open                                     open the web interface
func platformCommand(cmd string, args []string) (bool, error) {
	switch cmd {
	case "service":
		return true, serviceCommand(args)
	case "install":
		return true, installCommand(args)
	case "uninstall":
		return true, uninstallCommand(args)
	case "preflight":
		return true, preflightCommand(args)
	case "open":
		return true, openCommand()
	}
	return false, nil
}

func serviceRunning() (bool, error) {
	info, err := deploy.QueryService()
	return info.State == "running" || info.State == "starting", err
}

func serviceCommand(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: nexus service run|start|stop|restart|status")
	}
	switch args[0] {
	case "run":
		return runService()
	case "start":
		return deploy.StartService(3 * time.Minute)
	case "stop":
		return deploy.StopService(2 * time.Minute)
	case "restart":
		if err := deploy.StopService(2 * time.Minute); err != nil {
			return err
		}
		return deploy.StartService(3 * time.Minute)
	case "status":
		info, err := deploy.QueryService()
		if err != nil {
			return err
		}
		if !info.Installed {
			fmt.Println("not installed")
			return nil
		}
		fmt.Printf("%s (%s)\n%s\n", info.State, info.ServiceUser, info.BinaryPath)
		return nil
	}
	return fmt.Errorf("unknown service command %q", args[0])
}

// windowsService adapts serve() to the Service Control Manager.
type windowsService struct{ elog *eventlog.Log }

func (w *windowsService) Execute(_ []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending, WaitHint: 180000}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- serve(ctx, func(string) { close(ready) })
	}()
	const accepts = svc.AcceptStop | svc.AcceptShutdown
	for {
		select {
		case <-ready:
			status <- svc.Status{State: svc.Running, Accepts: accepts}
			w.info("Nexus is running")
			ready = nil
		case err := <-done:
			if err != nil {
				w.error("Nexus stopped with an error: " + redactor(nil).Redact(err.Error()))
				return true, 1 // service-specific error: triggers the recovery actions
			}
			return false, 0
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending, WaitHint: 90000}
				cancel()
				select {
				case <-done:
				case <-time.After(80 * time.Second):
					w.error("Nexus did not stop in time")
				}
				return false, 0
			}
		}
	}
}

func (w *windowsService) info(msg string) {
	if w.elog != nil {
		_ = w.elog.Info(1, msg)
	}
}

func (w *windowsService) error(msg string) {
	if w.elog != nil {
		_ = w.elog.Error(1, msg)
	}
}

func runService() error {
	isSvc, err := svc.IsWindowsService()
	if err != nil {
		return err
	}
	if !isSvc {
		return errors.New("'service run' is started by Windows; use 'nexus service start' or 'nexus serve'")
	}
	elog, _ := eventlog.Open(platform.ServiceName)
	if elog != nil {
		defer elog.Close()
	}
	// Services start in System32; relative paths in the configuration should
	// not depend on that.
	if exe, err := os.Executable(); err == nil {
		_ = os.Chdir(filepath.Dir(exe))
	}
	return svc.Run(platform.ServiceName, &windowsService{elog: elog})
}

// layoutFromExe derives the installation layout from this executable's
// location (ProgramDir\app\<version>\nexus.exe).
func layoutFromExe(dataRoot string) (deploy.Layout, error) {
	exe, err := os.Executable()
	if err != nil {
		return deploy.Layout{}, err
	}
	appDir := filepath.Dir(exe)
	programDir := filepath.Dir(filepath.Dir(appDir))
	if !strings.EqualFold(filepath.Base(filepath.Dir(appDir)), "app") {
		programDir = appDir
	}
	if dataRoot == "" {
		pd := os.Getenv("ProgramData")
		if pd == "" {
			pd = `C:\ProgramData`
		}
		dataRoot = filepath.Join(pd, "Nexus")
	}
	return deploy.Layout{ProgramDir: programDir, AppDir: appDir, DataRoot: dataRoot}, nil
}

func requireAdmin() error {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return errors.New("administrator rights are required (run from an elevated prompt or the installer)")
	}
	return nil
}

func preflightCommand(args []string) error {
	fs := flag.NewFlagSet("preflight", flag.ContinueOnError)
	data := fs.String("data", "", "data directory (default %ProgramData%\\Nexus)")
	port := fs.Int("port", 0, "preferred web port")
	lan := fs.Bool("lan", false, "web interface reachable from the network")
	ascii := fs.Bool("ascii", false, "plain markers")
	utf16 := fs.Bool("utf16", false, "write UTF-16LE (for the NSIS installer window)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	l, err := layoutFromExe(*data)
	if err != nil {
		return err
	}
	var out io.Writer = os.Stdout
	if *utf16 {
		out = &deploy.UTF16Writer{W: os.Stdout}
	}
	log := &deploy.Log{Out: out, ASCII: *ascii, DialogFont: *utf16}
	rep := deploy.Preflight(deploy.PreflightInput{Layout: l, PreferredPort: *port, LAN: *lan})
	log.Heading("Checking this computer...")
	for _, r := range rep.Results {
		log.Record("preflight", r.Component, r.Severity, r.Message, r.Hint)
	}
	if rep.Blocking {
		return reportedError{errors.New("this computer does not meet the requirements")}
	}
	return nil
}

func openCommand() error {
	l, err := layoutFromExe("")
	if err != nil {
		return err
	}
	env, err := deploy.ReadEnv(l.ConfigFile())
	if err != nil || env.ListenPort() == 0 {
		return errors.New("Nexus is not configured")
	}
	return openBrowser(env.URL())
}

func openBrowser(url string) error {
	return windows.ShellExecute(0, toUTF16("open"), toUTF16(url), nil, nil, windows.SW_SHOWNORMAL)
}

func toUTF16(s string) *uint16 {
	p, _ := windows.UTF16PtrFromString(s)
	return p
}

// installCommand is run by the installer after the files of this version
// were copied into ProgramDir\app\<version>. It is idempotent: running it
// again repairs an installation.
func installCommand(args []string) (err error) {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	data := fs.String("data", "", "data directory (default %ProgramData%\\Nexus)")
	port := fs.Int("port", 0, "preferred web port (default: keep current, else 8080)")
	lanFlag := fs.String("lan", "", "1 = reachable from the network (firewall rule for domain/private networks), 0 = this computer only; empty keeps the current choice")
	demo := fs.String("demo", "", "1 = start the simulated demo network; empty keeps the current choice")
	noStart := fs.Bool("no-start", false, "install without starting the service")
	result := fs.String("result", "", "write the outcome as an INI file (for the installer)")
	ascii := fs.Bool("ascii", false, "plain progress markers")
	utf16 := fs.Bool("utf16", false, "write progress as UTF-16LE (for the NSIS installer window)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	var out io.Writer = os.Stdout
	if *utf16 {
		out = &deploy.UTF16Writer{W: os.Stdout}
	}
	if err := requireAdmin(); err != nil {
		return err
	}
	l, err := layoutFromExe(*data)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(l.LogDir(), 0o750); err != nil {
		return err
	}
	log, err := deploy.OpenLog(filepath.Join(l.LogDir(), "install.log"), out)
	if err != nil {
		return err
	}
	defer log.Close()
	log.ASCII = *ascii
	log.DialogFont = *utf16
	log.Record("start", "Installer", deploy.Info, "Nexus "+version+" from "+l.AppDir, "")

	outcome := map[string]string{"status": "failed", "version": version}
	defer func() {
		if *result != "" {
			if err != nil {
				outcome["error"] = strings.ReplaceAll(err.Error(), "\n", " ")
			}
			writeResult(*result, outcome)
		}
		if err != nil {
			err = reportedError{err}
		}
	}()

	// 1. Preflight
	prev, _ := deploy.ReadEnv(l.ConfigFile())
	lan := prev.LAN()
	if *lanFlag != "" {
		lan = *lanFlag == "1" || strings.EqualFold(*lanFlag, "true")
	}
	sim := prev["NEXUS_SIMULATOR"] != ""
	if *demo != "" {
		sim = *demo == "1" || strings.EqualFold(*demo, "true")
	}
	log.Heading("Checking this computer...")
	rep := deploy.Preflight(deploy.PreflightInput{Layout: l, PreferredPort: *port, LAN: lan})
	for _, r := range rep.Results {
		log.Record("preflight", r.Component, r.Severity, r.Message, r.Hint)
	}
	if rep.Blocking {
		return errors.New("this computer does not meet the requirements (see above)")
	}

	// 2. Engine: the bundled runtime must start on this machine (catches
	// missing runtime DLLs or blocked executables before touching anything).
	log.Heading("Installing Nexus...")
	pgVer, err := verifyBundle(l)
	if err != nil {
		return log.Fail("install", "Engine", err.Error(), "Re-run the installer; if application whitelisting is active, allow the Nexus program folder.")
	}
	log.Step("install", "Engine", fmt.Sprintf("Nexus %s, PostgreSQL %s", version, pgVer))

	// 3. Existing installation: back up and stop it.
	svcInfo, _ := deploy.QueryService()
	upgrade := svcInfo.Installed
	oldBinary := svcInfo.BinaryPath
	if upgrade && svcInfo.State == "running" && l.HasData() {
		if path, err := preUpgradeBackup(l); err != nil {
			return log.Fail("upgrade", "Backup", err.Error(), "Nothing was changed. Check free disk space and logs\\nexus.log.")
		} else {
			log.Step("upgrade", "Backup", "current data saved to "+path)
		}
	}
	if upgrade {
		if err := deploy.StopService(2 * time.Minute); err != nil {
			return log.Fail("upgrade", "Service", "could not stop the running Nexus: "+err.Error(), "Stop the Nexus service in services.msc and run the installer again.")
		}
	}

	// 4. Directories and secrets
	if err := l.MkdirAll(); err != nil {
		return log.Fail("install", "Storage", err.Error(), "")
	}
	created, err := l.EnsureSecrets()
	if err != nil {
		return log.Fail("install", "Security", err.Error(), "")
	}
	if len(created) > 0 {
		log.Step("install", "Security", "new encryption key and database password generated (kept only on this computer)")
	} else {
		log.Step("install", "Security", "existing encryption key kept")
	}

	// 5. Configuration (previous version kept for rollback)
	prevConfig := l.ConfigFile() + ".previous"
	if _, err := os.Stat(l.ConfigFile()); err == nil {
		_ = copyFile(l.ConfigFile(), prevConfig)
	}
	env := deploy.BuildEnv(prev, l, rep.Port, lan, sim)
	if err := env.Write(l.ConfigFile()); err != nil {
		return log.Fail("install", "Configuration", err.Error(), "")
	}
	where := "this computer only"
	if lan {
		where = "this computer and the network"
	}
	log.Step("install", "Configuration", fmt.Sprintf("web interface on port %d (%s)", rep.Port, where))

	// 6. Service, permissions, event log, firewall
	cmdline := deploy.ServiceCommandLine(l.Exe(), l.ConfigFile())
	warns, err := deploy.InstallService(cmdline)
	if err != nil {
		return log.Fail("install", "Service", err.Error(), "")
	}
	for _, w := range warns {
		log.Warn("install", "Service", w, "")
	}
	sid, err := deploy.ServiceSID()
	if err == nil {
		err = deploy.SecureDataDirs(l, sid)
	}
	if err != nil {
		return log.Fail("install", "Permissions", err.Error(), "")
	}
	log.Step("install", "Permissions", "data readable only by administrators and the Nexus service")
	_ = eventlog.InstallAsEventCreate(platform.ServiceName, eventlog.Error|eventlog.Warning|eventlog.Info)
	log.Step("install", "Service", "runs as "+deploy.ServiceAccount+", starts automatically, restarts after failures")
	if lan {
		if err := deploy.AddFirewallRule(l.Exe(), rep.Port); err != nil {
			log.Warn("install", "Firewall", "could not add the inbound rule: "+err.Error(), fmt.Sprintf("Allow TCP port %d for Nexus in Windows Firewall to reach it from other computers.", rep.Port))
		} else {
			log.Step("install", "Firewall", fmt.Sprintf("TCP %d allowed on domain and private networks only", rep.Port))
		}
	} else {
		deploy.RemoveFirewallRule()
		log.Step("install", "Firewall", "no inbound rule needed (local access only)")
	}
	outcome["port"] = fmt.Sprint(rep.Port)
	outcome["url"] = env.URL()
	if *noStart {
		outcome["status"] = "installed"
		log.Step("install", "Service", "not started (--no-start)")
		return nil
	}

	// 7. Start and verify
	if err := startAndVerify(l, rep.Port, log, !l.HasData()); err != nil {
		if !upgrade || oldBinary == "" {
			return err
		}
		log.Warn("rollback", "Upgrade", "the new version did not become healthy; restoring the previous version", "")
		if rbErr := rollback(l, oldBinary, prevConfig, log); rbErr != nil {
			outcome["status"] = "rollback-failed"
			return log.Fail("rollback", "Rollback", rbErr.Error(), "Restore from the backup in the backups folder or contact support with a diagnostic bundle.")
		}
		outcome["status"] = "rolled-back"
		prevEnv, _ := deploy.ReadEnv(l.ConfigFile())
		outcome["url"] = prevEnv.URL()
		return fmt.Errorf("upgrade failed and the previous version was restored: %w", err)
	}
	_ = os.Remove(prevConfig)
	outcome["status"] = "ok"
	log.Heading("")
	log.Heading("Nexus is ready: " + env.URL())
	return nil
}

func startAndVerify(l deploy.Layout, port int, log *deploy.Log, fresh bool) error {
	if err := deploy.StartService(5 * time.Minute); err != nil {
		return log.Fail("verify", "Service", err.Error(), "See "+l.LogFile()+" and the Windows event log (source Nexus).")
	}
	log.Step("verify", "Service", "running")
	ctx := context.Background()
	h, err := deploy.WaitHealthy(ctx, port, 5*time.Minute, func(s string) { log.Record("verify", "Health check", deploy.Info, "waiting: "+s, "") })
	if err != nil {
		comp := "Health check"
		if h != nil && !h.Database {
			comp = "Database"
		}
		return log.Fail("verify", comp, err.Error(), "See "+l.LogFile()+" and "+l.LogDir()+"\\postgres-*.log.")
	}
	if fresh {
		log.Step("verify", "Database", "initialized")
	} else {
		log.Step("verify", "Database", "ready, existing data kept")
	}
	log.Step("verify", "Health check", "web interface and API answer (version "+h.Version+")")
	return nil
}

func rollback(l deploy.Layout, oldBinary, prevConfig string, log *deploy.Log) error {
	_ = deploy.StopService(2 * time.Minute)
	if _, err := os.Stat(prevConfig); err == nil {
		if err := copyFile(prevConfig, l.ConfigFile()); err != nil {
			return err
		}
	}
	if err := deploy.SetServiceBinary(oldBinary); err != nil {
		return err
	}
	env, _ := deploy.ReadEnv(l.ConfigFile())
	if err := deploy.StartService(5 * time.Minute); err != nil {
		return err
	}
	if _, err := deploy.WaitHealthy(context.Background(), env.ListenPort(), 5*time.Minute, nil); err != nil {
		return err
	}
	log.Step("rollback", "Rollback", "previous version is running again")
	return nil
}

// verifyBundle checks the files of this version and runs the bundled
// PostgreSQL once, which fails early when runtime DLLs are missing.
func verifyBundle(l deploy.Layout) (string, error) {
	for _, f := range []string{l.Exe(), filepath.Join(l.WebDir(), "index.html"), filepath.Join(l.PGBinDir(), "postgres.exe"),
		filepath.Join(l.PGBinDir(), "pg_ctl.exe"), filepath.Join(l.PGBinDir(), "initdb.exe")} {
		if _, err := os.Stat(f); err != nil {
			return "", fmt.Errorf("missing %s", f)
		}
	}
	cmd := exec.Command(filepath.Join(l.PGBinDir(), "postgres.exe"), "--version")
	hideConsole(cmd)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("the bundled database engine does not start (%v): %s", err, strings.TrimSpace(string(out)))
	}
	f := strings.Fields(string(out))
	if len(f) == 0 {
		return "", errors.New("unexpected database engine version output")
	}
	return f[len(f)-1], nil
}

func preUpgradeBackup(l deploy.Layout) (string, error) {
	if err := loadConfigFile(l.ConfigFile()); err != nil {
		return "", err
	}
	cfg, err := loadConfig()
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	db, done, err := openDatabase(ctx, cfg, cliLogger(cfg), true)
	if err != nil {
		return "", err
	}
	defer done()
	path := filepath.Join(l.BackupDir(), "nexus-before-upgrade-to-"+version+"-"+time.Now().Format("20060102-150405")+".nxbackup")
	if _, err := writeBackupFile(ctx, db, cfg, path, "", "before-upgrade"); err != nil {
		return "", err
	}
	pruneBackups(l.BackupDir(), "nexus-before-upgrade-", 5, cliLogger(cfg))
	return path, nil
}

func uninstallCommand(args []string) error {
	fs := flag.NewFlagSet("uninstall", flag.ContinueOnError)
	data := fs.String("data", "", "data directory (default %ProgramData%\\Nexus)")
	purge := fs.Bool("purge-data", false, "also delete all data: inventory database, credentials, keys, backups, logs")
	confirm := fs.String("confirm", "", "must be DELETE-ALL-DATA together with --purge-data")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := requireAdmin(); err != nil {
		return err
	}
	l, err := layoutFromExe(*data)
	if err != nil {
		return err
	}
	if err := deploy.RemoveService(); err != nil {
		return err
	}
	fmt.Println("  service removed")
	deploy.RemoveFirewallRule()
	_ = eventlog.Remove(platform.ServiceName)
	if *purge {
		if *confirm != "DELETE-ALL-DATA" {
			return errors.New("refusing to delete data without --confirm DELETE-ALL-DATA")
		}
		if err := removeDataRoot(l.DataRoot); err != nil {
			return err
		}
		fmt.Println("  all Nexus data deleted:", l.DataRoot)
	} else {
		fmt.Println("  data kept in", l.DataRoot)
	}
	return nil
}

// removeDataRoot deletes the data directory after sanity checks.
func removeDataRoot(root string) error {
	clean := filepath.Clean(root)
	if !strings.EqualFold(filepath.Base(clean), "Nexus") || len(clean) < len(`C:\X\Nexus`) {
		return fmt.Errorf("refusing to delete unexpected directory %s", clean)
	}
	return os.RemoveAll(clean)
}

func copyFile(src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, b, 0o640)
}

func writeResult(path string, kv map[string]string) {
	var b strings.Builder
	b.WriteString("[result]\r\n")
	for k, v := range kv {
		fmt.Fprintf(&b, "%s=%s\r\n", k, v)
	}
	// UTF-16LE with BOM so the installer (NSIS ReadINIStr) reads any text correctly.
	u := windows.StringToUTF16(b.String())
	out := []byte{0xFF, 0xFE}
	for _, c := range u[:len(u)-1] {
		out = append(out, byte(c), byte(c>>8))
	}
	_ = os.WriteFile(path, out, 0o644)
}

// diagnosticsGUI backs the "Nexus Diagnostics" Start menu shortcut: it
// elevates itself (UAC), writes a redacted bundle to the desktop of the user
// who clicked the shortcut and reports the result in a message box.
func diagnosticsGUI(outDir string) error {
	if outDir == "" {
		desktop, err := windows.KnownFolderPath(windows.FOLDERID_Desktop, 0)
		if err != nil {
			desktop = os.Getenv("USERPROFILE")
		}
		outDir = desktop
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		params := fmt.Sprintf(`diagnostics --gui --out-dir "%s"`, outDir)
		if err := windows.ShellExecute(0, toUTF16("runas"), toUTF16(exe), toUTF16(params), nil, windows.SW_SHOWMINNOACTIVE); err != nil {
			messageBox("Nexus Diagnostics", "Administrator rights are needed to read the Nexus logs and configuration.", windows.MB_ICONWARNING)
			return err
		}
		return nil
	}
	l, err := layoutFromExe(registryDataDir())
	if err != nil {
		return err
	}
	if err := loadConfigFile(l.ConfigFile()); err != nil {
		messageBox("Nexus Diagnostics", "Nexus is not configured on this computer:\n"+err.Error(), windows.MB_ICONERROR)
		return err
	}
	path := filepath.Join(outDir, "nexus-diagnostics-"+time.Now().Format("20060102-150405")+".zip")
	err = diagnosticsCommand([]string{"--out", path})
	if _, statErr := os.Stat(path); statErr != nil {
		msg := "The diagnostic bundle could not be created."
		if err != nil {
			msg += "\n\n" + redactor(nil).Redact(err.Error())
		}
		messageBox("Nexus Diagnostics", msg, windows.MB_ICONERROR)
		return err
	}
	note := "Passwords, keys, SNMP communities, tokens and cookies were removed."
	if err != nil {
		note = "The database was not reachable; the bundle contains logs and configuration.\n" + note
	}
	messageBox("Nexus Diagnostics", "Diagnostic bundle saved:\n"+path+"\n\n"+note, windows.MB_ICONINFORMATION)
	_ = exec.Command(filepath.Join(os.Getenv("WINDIR"), "explorer.exe"), "/select,", path).Start()
	return nil
}

func messageBox(title, text string, flags uint32) {
	_, _ = windows.MessageBox(0, toUTF16(text), toUTF16(title), flags|windows.MB_OK|windows.MB_SETFOREGROUND)
}

// registryDataDir returns the data directory recorded by the installer.
func registryDataDir() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `Software\Nexus`, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return ""
	}
	defer k.Close()
	v, _, _ := k.GetStringValue("DataDir")
	return v
}
