package deploy

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/Eirahoutmoss/network_intelligence/backend/internal/platform"
)

// ServiceAccount is the virtual account the service runs as. Windows creates
// it with the service; it has no password, no interactive logon and only the
// rights granted explicitly (plus the ACLs set by the installer).
const ServiceAccount = `NT SERVICE\` + platform.ServiceName

// FirewallRule is the name of the inbound rule created in LAN mode.
const FirewallRule = "Nexus Web Interface"

// ServiceCommandLine returns the service binary path with arguments.
func ServiceCommandLine(exe, configFile string) string {
	return fmt.Sprintf(`"%s" --config "%s" service run`, exe, configFile)
}

func connect() (*mgr.Mgr, error) {
	m, err := mgr.Connect()
	if err != nil {
		return nil, fmt.Errorf("open service manager: %w", err)
	}
	return m, nil
}

// ServiceInfo describes the installed service.
type ServiceInfo struct {
	Installed   bool
	State       string
	BinaryPath  string
	StartType   uint32
	ServiceUser string
}

// QueryService returns the current service installation and state.
func QueryService() (ServiceInfo, error) {
	m, err := connect()
	if err != nil {
		return ServiceInfo{}, err
	}
	defer m.Disconnect()
	s, err := m.OpenService(platform.ServiceName)
	if err != nil {
		return ServiceInfo{}, nil
	}
	defer s.Close()
	cfg, err := s.Config()
	if err != nil {
		return ServiceInfo{Installed: true}, err
	}
	st, err := s.Query()
	if err != nil {
		return ServiceInfo{Installed: true, BinaryPath: cfg.BinaryPathName}, err
	}
	return ServiceInfo{Installed: true, State: platform.StateName(uint32(st.State)), BinaryPath: cfg.BinaryPathName,
		StartType: cfg.StartType, ServiceUser: cfg.ServiceStartName}, nil
}

// InstallService creates the service or updates its command line. It
// returns warnings for optional settings the system did not accept.
func InstallService(cmdline string) (warnings []string, err error) {
	m, err := connect()
	if err != nil {
		return nil, err
	}
	defer m.Disconnect()
	const display = "Nexus Network Intelligence"
	const description = "Discovers and maps the network (SNMP/LLDP) and serves the Nexus web interface. Designed and developed by Hasan Güler."
	var h windows.Handle
	if s, err := m.OpenService(platform.ServiceName); err == nil {
		h = s.Handle
		if err := windows.ChangeServiceConfig(h, windows.SERVICE_WIN32_OWN_PROCESS, windows.SERVICE_AUTO_START, windows.SERVICE_ERROR_NORMAL,
			toPtr(cmdline), nil, nil, nil, toPtr(ServiceAccount), nil, toPtr(display)); err != nil {
			s.Close()
			return nil, fmt.Errorf("update service: %w", err)
		}
	} else {
		// The full command line goes into lpBinaryPathName as is
		// (mgr.CreateService would quote the arguments itself).
		h, err = windows.CreateService(m.Handle, toPtr(platform.ServiceName), toPtr(display),
			windows.SERVICE_ALL_ACCESS, windows.SERVICE_WIN32_OWN_PROCESS, windows.SERVICE_AUTO_START, windows.SERVICE_ERROR_NORMAL,
			toPtr(cmdline), nil, nil, nil, toPtr(ServiceAccount), nil)
		if err != nil {
			return nil, fmt.Errorf("create service: %w", err)
		}
	}
	s := &mgr.Service{Name: platform.ServiceName, Handle: h}
	defer s.Close()

	desc := windows.SERVICE_DESCRIPTION{Description: toPtr(description)}
	if err := windows.ChangeServiceConfig2(h, windows.SERVICE_CONFIG_DESCRIPTION, (*byte)(unsafe.Pointer(&desc))); err != nil {
		warnings = append(warnings, "description: "+err.Error())
	}
	sid := uint32(windows.SERVICE_SID_TYPE_UNRESTRICTED) // SERVICE_SID_INFO{dwServiceSidType}
	if err := windows.ChangeServiceConfig2(h, windows.SERVICE_CONFIG_SERVICE_SID_INFO, (*byte)(unsafe.Pointer(&sid))); err != nil {
		if !errors.Is(err, windows.ERROR_INVALID_LEVEL) {
			return warnings, fmt.Errorf("service SID type: %w", err)
		}
		warnings = append(warnings, "service SID type not supported by this system")
	}
	if err := setRecovery(s); err != nil {
		if !errors.Is(err, windows.ERROR_INVALID_LEVEL) {
			return warnings, err
		}
		warnings = append(warnings, "automatic restart after failures not supported by this system")
	}
	return warnings, nil
}

func toPtr(s string) *uint16 {
	p, _ := windows.UTF16PtrFromString(s)
	return p
}

// setRecovery restarts the service automatically after failures, including
// clean exits with an error code (e.g. database failure).
func setRecovery(s *mgr.Service) error {
	actions := []mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 15 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 60 * time.Second},
	}
	if err := s.SetRecoveryActions(actions, 24*60*60); err != nil {
		return fmt.Errorf("set recovery actions: %w", err)
	}
	return s.SetRecoveryActionsOnNonCrashFailures(true)
}

// SetServiceBinary changes only the command line (rollback).
func SetServiceBinary(cmdline string) error {
	m, err := connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(platform.ServiceName)
	if err != nil {
		return err
	}
	defer s.Close()
	cur, err := s.Config()
	if err != nil {
		return err
	}
	cur.BinaryPathName = cmdline
	return s.UpdateConfig(cur)
}

// StartService starts the service and waits until it runs (or stops again).
func StartService(timeout time.Duration) error {
	m, err := connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(platform.ServiceName)
	if err != nil {
		return err
	}
	defer s.Close()
	st, err := s.Query()
	if err != nil {
		return err
	}
	if st.State == svc.Running {
		return nil
	}
	if st.State != svc.StartPending {
		if err := s.Start(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
			return fmt.Errorf("start service: %w", err)
		}
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		st, err := s.Query()
		if err != nil {
			return err
		}
		switch st.State {
		case svc.Running:
			return nil
		case svc.Stopped:
			return fmt.Errorf("service stopped during startup (exit code %d/%d); see logs\\nexus.log", st.Win32ExitCode, st.ServiceSpecificExitCode)
		}
		time.Sleep(500 * time.Millisecond)
	}
	return errors.New("service did not report running in time")
}

// StopService stops the service and waits for it.
func StopService(timeout time.Duration) error {
	m, err := connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(platform.ServiceName)
	if err != nil {
		return nil // not installed
	}
	defer s.Close()
	st, err := s.Query()
	if err != nil {
		return err
	}
	if st.State == svc.Stopped {
		return nil
	}
	if st.State != svc.StopPending {
		if _, err := s.Control(svc.Stop); err != nil && !errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE) {
			return fmt.Errorf("stop service: %w", err)
		}
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		st, err := s.Query()
		if err != nil {
			return err
		}
		if st.State == svc.Stopped {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return errors.New("service did not stop in time")
}

// RemoveService stops and deletes the service.
func RemoveService() error {
	if err := StopService(2 * time.Minute); err != nil {
		return err
	}
	m, err := connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(platform.ServiceName)
	if err != nil {
		return nil
	}
	defer s.Close()
	if err := s.Delete(); err != nil {
		return fmt.Errorf("delete service: %w", err)
	}
	return nil
}

// ServiceSID returns the SID string of the service's virtual account. The
// system lookup is preferred; the SID is computed when the lookup is not
// available (it is fully determined by the service name).
func ServiceSID() (string, error) {
	if sid, _, _, err := windows.LookupSID("", ServiceAccount); err == nil {
		return sid.String(), nil
	}
	return VirtualServiceSID(platform.ServiceName), nil
}

// Access masks.
const (
	accessRead   = "0x1200a9" // read, execute/traverse
	accessModify = "0x1301bf" // read, write, delete (no ownership/ACL changes)
)

// SecureDataDirs applies protected ACLs: SYSTEM and Administrators have full
// control; the service account may read configuration and secrets and write
// only data, logs and backups. Ordinary users get no access at all.
func SecureDataDirs(l Layout, serviceSID string) error {
	base := "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
	dirs := []struct{ path, sddl string }{
		{l.DataRoot, base + "(A;OICI;" + accessRead + ";;;" + serviceSID + ")"},
		{l.ConfigDir(), base + "(A;OICI;" + accessRead + ";;;" + serviceSID + ")"},
		{l.SecretsDir(), base + "(A;OICI;" + accessRead + ";;;" + serviceSID + ")"},
		{l.DataDir(), base + "(A;OICI;" + accessModify + ";;;" + serviceSID + ")"},
		{l.LogDir(), base + "(A;OICI;" + accessModify + ";;;" + serviceSID + ")"},
		{l.BackupDir(), base + "(A;OICI;" + accessModify + ";;;" + serviceSID + ")"},
	}
	for _, d := range dirs {
		if err := setACL(d.path, d.sddl); err != nil {
			return fmt.Errorf("%s: %w", d.path, err)
		}
	}
	return nil
}

func setACL(path, sddl string) error {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

// netsh runs netsh with an exact command line (its parser needs name="…"
// quoting that Go's argument escaping would not produce).
func netsh(args string) error {
	exe := system32("netsh.exe")
	cmd := &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000, CmdLine: `"` + exe + `" ` + args}
	p, err := os.StartProcess(exe, nil, &os.ProcAttr{Sys: cmd, Files: []*os.File{nil, nil, nil}})
	if err != nil {
		return err
	}
	st, err := p.Wait()
	if err != nil {
		return err
	}
	if !st.Success() {
		return fmt.Errorf("netsh exited with %d", st.ExitCode())
	}
	return nil
}

// RemoveFirewallRule deletes the inbound rule (no error when absent).
func RemoveFirewallRule() {
	_ = netsh(`advfirewall firewall delete rule name="` + FirewallRule + `"`)
}

// AddFirewallRule allows inbound TCP to port for exe on domain and private
// networks only (never public networks). The firewall itself is not changed.
func AddFirewallRule(exe string, port int) error {
	RemoveFirewallRule()
	if strings.ContainsAny(exe, `"`) {
		return errors.New("invalid program path")
	}
	return netsh(fmt.Sprintf(`advfirewall firewall add rule name="%s" dir=in action=allow protocol=TCP localport=%d program="%s" profile=domain,private enable=yes description="Nexus web interface (added by the Nexus installer)"`,
		FirewallRule, port, filepath.Clean(exe)))
}
