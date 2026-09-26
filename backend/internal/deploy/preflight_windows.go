package deploy

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	machineAMD64 = 0x8664
	machineARM64 = 0xAA64
	// Windows 10 1809 / Server 2019: the oldest release with the service,
	// security and TLS behavior Nexus relies on.
	minBuild = 17763
)

func systemChecks() []Result {
	var res []Result
	maj, _, build := windows.RtlGetNtVersionNumbers()
	name := "Windows"
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE); err == nil {
		if v, _, err := k.GetStringValue("ProductName"); err == nil {
			name = v
		}
		if v, _, err := k.GetStringValue("DisplayVersion"); err == nil {
			name += " " + v
		}
		k.Close()
	}
	// Windows 11 still reports "Windows 10" in ProductName.
	if build >= 22000 {
		name = strings.Replace(name, "Windows 10", "Windows 11", 1)
	}
	if maj < 10 || build < minBuild {
		res = append(res, Result{"Windows", Error, fmt.Sprintf("%s (build %d) is not supported", name, build),
			"Nexus needs Windows 10 version 1809 / Windows Server 2019 or newer."})
	} else {
		res = append(res, Result{"Windows", Info, fmt.Sprintf("%s (build %d)", name, build), ""})
	}

	var proc, native uint16
	if err := windows.IsWow64Process2(windows.CurrentProcess(), &proc, &native); err == nil {
		switch native {
		case machineAMD64:
			res = append(res, Result{"Architecture", Info, "x64", ""})
		case machineARM64:
			res = append(res, Result{"Architecture", Warn, "ARM64 (running the x64 build under emulation)", "A native ARM64 build is planned; x64 emulation works but is slower."})
		default:
			res = append(res, Result{"Architecture", Error, fmt.Sprintf("unsupported processor (machine type 0x%x)", native), "Nexus needs a 64-bit (x64) Windows."})
		}
	}

	if windows.GetCurrentProcessToken().IsElevated() {
		res = append(res, Result{"Administrator rights", Info, "granted", ""})
	} else {
		res = append(res, Result{"Administrator rights", Error, "not elevated", "Run the installer again and accept the Windows administrator prompt (UAC)."})
	}

	if total, err := totalMemory(); err == nil {
		switch {
		case total < 2<<30:
			res = append(res, Result{"Memory", Warn, humanBytes(total) + " installed", "4 GB or more is recommended."})
		default:
			res = append(res, Result{"Memory", Info, humanBytes(total) + " installed", ""})
		}
	}

	res = append(res, firewallCheck())
	if p := proxySetting(); p != "" {
		res = append(res, Result{"Proxy", Info, p + " (Nexus talks to network devices directly; no proxy needed)", ""})
	}
	return res
}

type memoryStatusEx struct {
	Length               uint32
	MemoryLoad           uint32
	TotalPhys            uint64
	AvailPhys            uint64
	TotalPageFile        uint64
	AvailPageFile        uint64
	TotalVirtual         uint64
	AvailVirtual         uint64
	AvailExtendedVirtual uint64
}

var procGlobalMemoryStatusEx = windows.NewLazySystemDLL("kernel32.dll").NewProc("GlobalMemoryStatusEx")

func totalMemory() (uint64, error) {
	var m memoryStatusEx
	m.Length = uint32(unsafe.Sizeof(m))
	r, _, err := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&m)))
	if r == 0 {
		return 0, err
	}
	return m.TotalPhys, nil
}

// run executes a system tool without a console window.
func run(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func system32(exe string) string {
	dir, err := windows.GetSystemDirectory()
	if err != nil {
		return exe
	}
	return dir + `\` + exe
}

// firewallEnabled reads the effective firewall state per profile from the
// registry (group policy wins over local settings). netsh output is
// localized and therefore not parsed.
func firewallEnabled() (map[string]bool, error) {
	profiles := map[string]string{"Domain": "DomainProfile", "Private": "StandardProfile", "Public": "PublicProfile"}
	out := map[string]bool{}
	var anyErr error
	for label, key := range profiles {
		val := -1
		for _, base := range []string{`SOFTWARE\Policies\Microsoft\WindowsFirewall\`, `SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\`} {
			k, err := registry.OpenKey(registry.LOCAL_MACHINE, base+key, registry.QUERY_VALUE)
			if err != nil {
				continue
			}
			v, _, err := k.GetIntegerValue("EnableFirewall")
			k.Close()
			if err == nil {
				val = int(v)
				break
			}
		}
		if val < 0 {
			anyErr = fmt.Errorf("state of %s profile unknown", label)
			continue
		}
		out[label] = val != 0
	}
	return out, anyErr
}

func firewallCheck() Result {
	st, _ := firewallEnabled()
	if len(st) == 0 {
		return Result{"Windows Firewall", Info, "state unknown (left unchanged)", ""}
	}
	var on, off []string
	for _, p := range []string{"Domain", "Private", "Public"} {
		if v, ok := st[p]; ok {
			if v {
				on = append(on, p)
			} else {
				off = append(off, p)
			}
		}
	}
	switch {
	case len(off) == 0:
		return Result{"Windows Firewall", Info, "on (left unchanged)", ""}
	case len(on) == 0:
		return Result{"Windows Firewall", Warn, "off for all profiles (left unchanged)", "Nexus never disables the firewall; consider turning it on."}
	}
	return Result{"Windows Firewall", Info, "on for " + strings.Join(on, ", ") + " (left unchanged)", ""}
}

func proxySetting() string {
	for _, k := range []string{"HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy"} {
		if os.Getenv(k) != "" {
			return "environment proxy configured"
		}
	}
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections`, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer k.Close()
	// WinHttpSettings: byte 8 holds flags, 0x02 = proxy server set.
	if b, _, err := k.GetBinaryValue("WinHttpSettings"); err == nil && len(b) > 8 && b[8]&0x02 != 0 {
		return "WinHTTP proxy configured"
	}
	return ""
}

var (
	iphlpapi                = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTcpTable = iphlpapi.NewProc("GetExtendedTcpTable")
)

const tcpTableOwnerPIDListener = 3

type tcpRowOwnerPID struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	OwningPID  uint32
}

// listenerPID returns the process listening on an IPv4 TCP port.
func listenerPID(port int) (uint32, bool) {
	var size uint32
	procGetExtendedTcpTable.Call(0, uintptr(unsafe.Pointer(&size)), 0, windows.AF_INET, tcpTableOwnerPIDListener, 0)
	if size == 0 {
		return 0, false
	}
	buf := make([]byte, size)
	r, _, _ := procGetExtendedTcpTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0, windows.AF_INET, tcpTableOwnerPIDListener, 0)
	if r != 0 || len(buf) < 4 {
		return 0, false
	}
	n := *(*uint32)(unsafe.Pointer(&buf[0]))
	rowSize := unsafe.Sizeof(tcpRowOwnerPID{})
	for i := uint32(0); i < n; i++ {
		off := 4 + uintptr(i)*rowSize
		if off+rowSize > uintptr(len(buf)) {
			break
		}
		row := (*tcpRowOwnerPID)(unsafe.Pointer(&buf[off]))
		p := int((row.LocalPort&0xff)<<8 | (row.LocalPort>>8)&0xff) // network byte order
		if p == port {
			return row.OwningPID, true
		}
	}
	return 0, false
}

func processName(pid uint32) string {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, windows.MAX_PATH)
	n := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &n); err != nil {
		return ""
	}
	full := windows.UTF16ToString(buf[:n])
	if i := strings.LastIndexAny(full, `\/`); i >= 0 {
		return full[i+1:]
	}
	return full
}

// PortOwner describes the process listening on port (best effort), e.g.
// " by httpd.exe (PID 4312)".
func PortOwner(port int) string {
	pid, ok := listenerPID(port)
	if !ok {
		return ""
	}
	if name := processName(pid); name != "" {
		return fmt.Sprintf(" by %s (PID %d)", name, pid)
	}
	if pid == 4 {
		return " by Windows (HTTP.sys / System)"
	}
	return fmt.Sprintf(" by PID %d", pid)
}
