// Package juniper parses Junos identity information.
package juniper

import (
	"regexp"
	"strings"

	"github.com/Eirahoutmoss/network_intelligence/backend/internal/collectors"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/model"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/vendors"
)

type Adapter struct{}

var (
	reModel = regexp.MustCompile(`(?i)Juniper Networks, Inc\.\s+(\S+)`)
	reOS    = regexp.MustCompile(`(?i)JUNOS\s+([\w.\-]+)`)
)

func (Adapter) Name() string { return "juniper" }
func (Adapter) Match(sys model.System) bool {
	e := vendors.EnterpriseOf(sys.ObjectID)
	return e == 2636 || strings.Contains(strings.ToLower(sys.Descr), "junos")
}
func (Adapter) Enrich(sys *model.System) {
	sys.Vendor = "Juniper"
	if m := reModel.FindStringSubmatch(sys.Descr); m != nil && sys.Model == "" {
		sys.Model = m[1]
	}
	if m := reOS.FindStringSubmatch(sys.Descr); m != nil {
		sys.OSName, sys.OSVersion = "Junos", strings.TrimRight(m[1], ",")
	}
}
func (Adapter) Collectors() []collectors.Collector { return nil }
