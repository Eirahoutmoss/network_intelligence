// Package platform isolates operating-system specific facts used by
// diagnostics and the installer. Discovery and inventory code never imports it.
package platform

import (
	"os"
	"runtime"
)

// Base returns facts available on every platform.
func Base() map[string]any {
	host, _ := os.Hostname()
	return map[string]any{"os": runtime.GOOS, "arch": runtime.GOARCH, "go": runtime.Version(), "hostname": host, "cpus": runtime.NumCPU()}
}
