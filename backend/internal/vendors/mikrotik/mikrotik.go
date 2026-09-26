// Package mikrotik parses MikroTik RouterOS identity information.
package mikrotik

import (
	"strings"

	"github.com/Eirahoutmoss/network_intelligence/backend/internal/collectors"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/model"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/vendors"
)

type Adapter struct{}

func (Adapter) Name() string { return "mikrotik" }
func (Adapter) Match(sys model.System) bool {
	return vendors.EnterpriseOf(sys.ObjectID) == 14988 || strings.HasPrefix(sys.Descr, "RouterOS")
}
func (Adapter) Enrich(sys *model.System) {
	sys.Vendor = "MikroTik"
	sys.OSName = "RouterOS"
	if rest, ok := strings.CutPrefix(sys.Descr, "RouterOS "); ok && sys.Model == "" {
		sys.Model = strings.TrimSpace(rest)
	}
}
func (Adapter) Collectors() []collectors.Collector { return nil }
