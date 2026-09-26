//go:build !windows

package deploy

import (
	"os"
	"runtime"
)

func systemChecks() []Result {
	res := []Result{{"Operating system", Info, runtime.GOOS + "/" + runtime.GOARCH, ""}}
	if os.Geteuid() != 0 {
		res = append(res, Result{"Privileges", Warn, "not running as root", "Service installation needs administrative rights."})
	}
	return res
}

// PortOwner describes the process listening on port (best effort).
func PortOwner(int) string { return "" }
