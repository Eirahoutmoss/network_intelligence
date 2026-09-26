// Package classify derives device type, operating system and vendor from
// heterogeneous evidence, with explicit confidence.
//
// Each rule contributes weighted evidence to a candidate value. Weights are
// combined with a noisy-OR (1 - Π(1-w)), so independent weak signals add up
// while no single weak signal can claim certainty. Competing candidates
// reduce the winner's confidence. Nothing here asserts facts: callers must
// present results together with their confidence and evidence.
package classify

import (
	"sort"
	"strings"

	"github.com/Eirahoutmoss/network_intelligence/backend/internal/fingerprint"
)

// Evidence is one supporting signal.
type Evidence struct {
	Attribute string  `json:"attribute"` // device_type|os|vendor
	Value     string  `json:"value"`
	Source    string  `json:"source"` // e.g. "OUI", "SNMP sysDescr", "SMB", "LLDP"
	Detail    string  `json:"detail"`
	Weight    float64 `json:"weight"`
}

// Result is a classification outcome.
type Result struct {
	Value      string     `json:"value"`
	Confidence float64    `json:"confidence"`
	Evidence   []Evidence `json:"evidence"`
}

// Facts are all known inputs about one device.
type Facts struct {
	Managed      bool
	SysDescr     string
	SysObjectID  string
	SNMPVendor   string // from sysObjectID/sysDescr
	NetworkOS    string // parsed by vendor adapter, e.g. "VRP 8.191"
	Model        string
	IsRouter     bool
	IsBridge     bool
	IsPrinter    bool
	OUIVendor    string
	OUIOrg       string
	RandomMAC    bool
	Hostnames    []string
	NeighborCaps []string // capabilities announced via LLDP/CDP
	NeighborDesc string   // LLDP sysDescr / CDP platform announced by the device
	Obs          fingerprint.Observation
}

type scorer struct {
	attr  string
	cands map[string][]Evidence
}

func newScorer(attr string) *scorer { return &scorer{attr: attr, cands: map[string][]Evidence{}} }

func (s *scorer) add(value, source, detail string, w float64) {
	if value == "" || w <= 0 {
		return
	}
	s.cands[value] = append(s.cands[value], Evidence{Attribute: s.attr, Value: value, Source: source, Detail: detail, Weight: w})
}

func noisyOR(ev []Evidence) float64 {
	p := 1.0
	for _, e := range ev {
		p *= 1 - e.Weight
	}
	return 1 - p
}

type ranked struct {
	value string
	score float64
	ev    []Evidence
}

func (s *scorer) rank() []ranked {
	var out []ranked
	for v, ev := range s.cands {
		out = append(out, ranked{v, noisyOR(ev), ev})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].score != out[j].score {
			return out[i].score > out[j].score
		}
		return out[i].value < out[j].value
	})
	return out
}

// best returns the winner, discounted by the runner-up.
func (s *scorer) best(min float64, fallback string) Result {
	r := s.rank()
	if len(r) == 0 || r[0].score < min {
		res := Result{Value: fallback}
		for _, x := range r {
			res.Evidence = append(res.Evidence, x.ev...)
		}
		return res
	}
	conf := r[0].score
	if len(r) > 1 {
		conf *= 1 - 0.5*r[1].score
	}
	return Result{Value: r[0].value, Confidence: round2(conf), Evidence: sortEv(r[0].ev)}
}

func sortEv(ev []Evidence) []Evidence {
	sort.SliceStable(ev, func(i, j int) bool { return ev[i].Weight > ev[j].Weight })
	return ev
}

func round2(f float64) float64 {
	if f > 0.99 {
		f = 0.99
	}
	return float64(int(f*100+0.5)) / 100
}

func lower(s string) string { return strings.ToLower(s) }

func containsAny(s string, needles ...string) (string, bool) {
	l := lower(s)
	for _, n := range needles {
		if strings.Contains(l, n) {
			return n, true
		}
	}
	return "", false
}
