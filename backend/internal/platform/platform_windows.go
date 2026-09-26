package platform

import (
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc/mgr"
)

// ServiceName is the Windows service that runs Nexus.
const ServiceName = "Nexus"

// Info returns operating-system facts for diagnostics.
func Info() map[string]any {
	m := Base()
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE); err == nil {
		for _, n := range []string{"ProductName", "DisplayVersion", "CurrentBuild", "EditionID", "InstallationType"} {
			if v, _, err := k.GetStringValue(n); err == nil {
				m["windows_"+n] = v
			}
		}
		if v, _, err := k.GetIntegerValue("UBR"); err == nil {
			m["windows_UBR"] = v
		}
		k.Close()
	}
	maj, min, build := windows.RtlGetNtVersionNumbers()
	m["windows_version"] = []uint32{maj, min, build}
	m["service"] = ServiceState()
	return m
}

// ServiceState returns the state of the Nexus Windows service.
func ServiceState() string {
	h, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return "unknown: " + err.Error()
	}
	m := &mgr.Mgr{Handle: h}
	defer m.Disconnect()
	name, _ := windows.UTF16PtrFromString(ServiceName)
	sh, err := windows.OpenService(h, name, windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return "not installed"
	}
	s := &mgr.Service{Name: ServiceName, Handle: sh}
	defer s.Close()
	st, err := s.Query()
	if err != nil {
		return "unknown: " + err.Error()
	}
	return StateName(uint32(st.State))
}

// StateName renders a service state.
func StateName(s uint32) string {
	switch s {
	case windows.SERVICE_STOPPED:
		return "stopped"
	case windows.SERVICE_START_PENDING:
		return "starting"
	case windows.SERVICE_STOP_PENDING:
		return "stopping"
	case windows.SERVICE_RUNNING:
		return "running"
	case windows.SERVICE_PAUSED:
		return "paused"
	}
	return "unknown"
}

// DiskFree returns free and total bytes of the volume holding path.
func DiskFree(path string) (free, total uint64, err error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, 0, err
	}
	var avail, tot, totFree uint64
	if err := windows.GetDiskFreeSpaceEx(p, &avail, &tot, &totFree); err != nil {
		return 0, 0, err
	}
	return avail, tot, nil
}
