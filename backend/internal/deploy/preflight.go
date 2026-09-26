package deploy

import (
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/Eirahoutmoss/network_intelligence/backend/internal/platform"
)

// Result of a preflight check.
type Result struct {
	Component string `json:"component"`
	Severity  string `json:"severity"` // info (passed), warning, error (blocks installation)
	Message   string `json:"message"`
	Hint      string `json:"hint,omitempty"`
}

// PreflightInput describes the planned installation.
type PreflightInput struct {
	Layout        Layout
	PreferredPort int
	LAN           bool
}

// PreflightReport is the outcome of all checks.
type PreflightReport struct {
	Results  []Result `json:"results"`
	Port     int      `json:"port"`
	Upgrade  bool     `json:"upgrade"`
	HasData  bool     `json:"has_data"`
	Blocking bool     `json:"blocking"`
}

// Preflight inspects this computer before installing.
func Preflight(in PreflightInput) PreflightReport {
	var r PreflightReport
	add := func(res Result) {
		r.Results = append(r.Results, res)
		if res.Severity == Error {
			r.Blocking = true
		}
	}
	for _, res := range systemChecks() {
		add(res)
	}

	// Disk space where program files and data go.
	for _, d := range []struct{ name, path string }{{"Program disk", in.Layout.ProgramDir}, {"Data disk", in.Layout.DataRoot}} {
		free, total, err := platform.DiskFree(existingParent(d.path))
		switch {
		case err != nil:
			add(Result{d.name, Warn, "free space unknown: " + err.Error(), ""})
		case free < 1<<30:
			add(Result{d.name, Error, fmt.Sprintf("only %s free on %s", humanBytes(free), volumeOf(d.path)), "Free at least 1 GB (5 GB recommended) and run the installer again."})
		case free < 5<<30:
			add(Result{d.name, Warn, fmt.Sprintf("%s free of %s", humanBytes(free), humanBytes(total)), "5 GB or more is recommended for inventory history and backups."})
		default:
			add(Result{d.name, Info, fmt.Sprintf("%s free", humanBytes(free)), ""})
		}
	}

	// Existing installation and data.
	env, _ := ReadEnv(in.Layout.ConfigFile())
	current := env.ListenPort()
	r.Upgrade = len(env) > 0
	r.HasData = in.Layout.HasData()
	switch {
	case r.HasData:
		add(Result{"Existing data", Info, "found in " + in.Layout.DataRoot + "; it will be kept", ""})
	case r.Upgrade:
		add(Result{"Existing configuration", Info, "found; it will be kept", ""})
	default:
		add(Result{"Installation", Info, "new installation", ""})
	}
	if r.HasData {
		if _, err := os.Stat(in.Layout.MasterKeyFile()); err != nil {
			add(Result{"Master key", Error, "the database exists but secrets\\master.key is missing",
				"Restore master.key from your backup into " + in.Layout.SecretsDir() + "; without it stored device credentials cannot be decrypted."})
		}
	}

	// Port.
	host := "127.0.0.1"
	if in.LAN {
		host = "0.0.0.0"
	}
	preferred := in.PreferredPort
	if preferred == 0 {
		preferred = current
	}
	if preferred == 0 {
		preferred = DefaultPort
	}
	port, isPreferred := ChoosePort(host, preferred, current)
	r.Port = port
	switch {
	case port == 0:
		add(Result{"Port", Error, "no free TCP port found", "Close programs listening on ports 8080-28080."})
	case isPreferred:
		add(Result{"Port", Info, fmt.Sprintf("%d available", port), ""})
	default:
		add(Result{"Port", Warn, fmt.Sprintf("%d is in use%s; Nexus will use %d", preferred, PortOwner(preferred), port), ""})
	}

	// Network.
	if ip := primaryIPv4(); ip == "" {
		add(Result{"Network", Warn, "no active network adapter with an IPv4 address", "Discovery needs network access to the devices."})
	} else {
		add(Result{"Network", Info, "connected (" + ip + ")", ""})
	}
	add(Result{"Internet access", Info, "not required (all components are bundled)", ""})
	add(Result{"Docker / WSL", Info, "not required (Nexus runs as a native Windows service)", ""})
	return r
}

func existingParent(p string) string {
	for {
		if _, err := os.Stat(p); err == nil {
			return p
		}
		parent := filepath.Dir(p)
		if parent == p {
			return p
		}
		p = parent
	}
}

func volumeOf(p string) string {
	if v := filepath.VolumeName(p); v != "" {
		return v
	}
	return existingParent(p)
}

func primaryIPv4() string {
	ifs, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, i := range ifs {
		if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok {
				if v4 := ipn.IP.To4(); v4 != nil && !v4.IsLinkLocalUnicast() {
					return v4.String()
				}
			}
		}
	}
	return ""
}

func humanBytes(b uint64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(b)/(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.0f MB", float64(b)/(1<<20))
	}
	return fmt.Sprintf("%d bytes", b)
}
