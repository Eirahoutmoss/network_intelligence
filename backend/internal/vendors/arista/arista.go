// Package arista parses Arista EOS identity information.
package arista

import (
	"regexp"

	"github.com/Eirahoutmoss/network_intelligence/backend/internal/collectors"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/model"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/vendors"
)

type Adapter struct{}

var reDescr = regexp.MustCompile(`(?i)EOS version (\S+) running on an Arista Networks (\S+)`)

func (Adapter) Name() string                { return "arista" }
func (Adapter) Match(sys model.System) bool { return vendors.EnterpriseOf(sys.ObjectID) == 30065 }
func (Adapter) Enrich(sys *model.System) {
	sys.Vendor = "Arista"
	if m := reDescr.FindStringSubmatch(sys.Descr); m != nil {
		sys.OSName, sys.OSVersion = "EOS", m[1]
		if sys.Model == "" {
			sys.Model = m[2]
		}
	}
}
func (Adapter) Collectors() []collectors.Collector { return nil }
