// Package hpe parses HPE / Aruba / ProCurve / H3C Comware identity information.
package hpe

import (
	"regexp"
	"strings"

	"github.com/Eirahoutmoss/network_intelligence/backend/internal/collectors"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/model"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/vendors"
)

type Adapter struct{}

var (
	// "HP J9772A 2530-48G-PoEP Switch, revision YA.16.10.0012, ROM YA.15.20 (...)"
	reProCurve = regexp.MustCompile(`(?i)^(?:HP|Aruba|HPE)\s+(J\w+|JL\w+)\s+(.+?)(?:\s+Switch)?,\s+revision\s+([\w.]+)`)
	// "Aruba JL658A 6300M 24SFP+ 4SFP56 Swch FL.10.08.1010"
	reCX           = regexp.MustCompile(`(?i)^Aruba\s+(JL\w+)\s+(.+?)\s+([A-Z]{2}\.\d+\.\d+\.\d+)$`)
	reComware      = regexp.MustCompile(`(?i)Comware (?:Platform )?Software,?\s*Software Version ([\w.]+)(?:, Release (\w+))?`)
	reComwareModel = regexp.MustCompile(`(?m)^(?:H3C|HPE|HP)\s+(\S+)\s*$`)
)

func (Adapter) Name() string { return "hpe" }
func (Adapter) Match(sys model.System) bool {
	switch vendors.EnterpriseOf(sys.ObjectID) {
	case 11, 47196, 14823, 25506:
		return true
	}
	return false
}
func (Adapter) Enrich(sys *model.System) {
	d := strings.TrimSpace(sys.Descr)
	if m := reProCurve.FindStringSubmatch(d); m != nil {
		sys.Vendor = "HPE"
		if sys.Model == "" {
			sys.Model = strings.TrimSpace(m[2]) + " (" + m[1] + ")"
		}
		sys.OSName, sys.OSVersion = "ArubaOS-Switch", m[3]
		return
	}
	if m := reCX.FindStringSubmatch(d); m != nil {
		sys.Vendor = "Aruba"
		if sys.Model == "" {
			sys.Model = strings.TrimSpace(m[2]) + " (" + m[1] + ")"
		}
		sys.OSName, sys.OSVersion = "AOS-CX", m[3]
		return
	}
	if m := reComware.FindStringSubmatch(d); m != nil {
		sys.OSName, sys.OSVersion = "Comware", strings.TrimSpace(m[1]+" "+m[2])
		if mm := reComwareModel.FindStringSubmatch(d); mm != nil && sys.Model == "" {
			sys.Model = mm[1]
		}
	}
}
func (Adapter) Collectors() []collectors.Collector { return nil }
