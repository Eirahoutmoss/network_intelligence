// Package collectors turns standard MIB data into the normalized domain model.
//
// Each collector answers a domain question ("what are this device's
// interfaces?") rather than mapping OIDs to rows. Collectors must tolerate
// missing MIBs: a device that does not implement a MIB simply contributes no
// data. Vendor-specific collectors live in internal/vendors/*.
package collectors

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/Eirahoutmoss/network_intelligence/backend/internal/model"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/snmp"
)

// Session is the per-device collection context.
type Session struct {
	Client snmp.Client
	Target string
	Log    *slog.Logger
	// ContextClient returns a client bound to an SNMP context (v3 context name
	// or v2c community@context). Used for per-VLAN BRIDGE-MIB instances on
	// some vendors. May be nil.
	ContextClient func(ctx context.Context, name string) (snmp.Client, error)
}

// Collector gathers one capability.
type Collector interface {
	Name() string
	Collect(ctx context.Context, s *Session, snap *model.Snapshot) error
}

// Func adapts a function into a Collector.
type Func struct {
	N string
	F func(ctx context.Context, s *Session, snap *model.Snapshot) error
}

func (f Func) Name() string { return f.N }
func (f Func) Collect(ctx context.Context, s *Session, snap *model.Snapshot) error {
	return f.F(ctx, s, snap)
}

// Result reports one collector execution.
type Result struct {
	Name     string
	Duration time.Duration
	Err      error
}

// Run executes collectors sequentially. Failures are recorded on the snapshot
// and in results but never abort the remaining collectors.
func Run(ctx context.Context, s *Session, snap *model.Snapshot, cs []Collector) []Result {
	var out []Result
	for _, c := range cs {
		if ctx.Err() != nil {
			break
		}
		start := time.Now()
		err := safeCollect(ctx, c, s, snap)
		r := Result{Name: c.Name(), Duration: time.Since(start), Err: err}
		if err != nil {
			snap.Errors = append(snap.Errors, model.CollectorError{Collector: c.Name(), Error: err.Error()})
			if s.Log != nil {
				s.Log.Warn("collector failed", "collector", c.Name(), "target", s.Target, "err", err)
			}
		}
		out = append(out, r)
	}
	return out
}

func safeCollect(ctx context.Context, c Collector, s *Session, snap *model.Snapshot) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("collector panic: %v", r)
		}
	}()
	return c.Collect(ctx, s, snap)
}

// Standard returns the vendor-neutral collectors in dependency order.
func Standard() []Collector {
	return []Collector{
		Func{"system", CollectSystem},
		Func{"interfaces", CollectInterfaces},
		Func{"ip_addresses", CollectIPAddresses},
		Func{"inventory", CollectEntities},
		Func{"lldp", CollectLLDP},
		Func{"vlans", CollectVLANs},
		Func{"fdb", CollectFDB},
		Func{"arp", CollectARP},
		Func{"routes", CollectRoutes},
		Func{"host_resources", CollectHostResources},
		Func{"entity_sensors", CollectEntitySensors},
	}
}

// Poll returns the lightweight collectors used for periodic polling.
func Poll() []Collector {
	return []Collector{
		Func{"system", CollectSystem},
		Func{"interfaces", CollectInterfaces},
		Func{"host_resources", CollectHostResources},
		Func{"entity_sensors", CollectEntitySensors},
	}
}

// Finalize derives cross-collector facts (e.g. port medium) after all
// collectors (including vendor ones) have run.
func Finalize(snap *model.Snapshot) {
	deriveOpticsFromEntities(snap)
	deriveMedium(snap)
	if snap.System.Model == "" {
		for _, e := range snap.Inventory {
			if e.Class == "chassis" && e.Model != "" {
				snap.System.Model = e.Model
				break
			}
		}
	}
}

func f64(v float64) *float64 { return &v }

// deriveOpticsFromEntities registers pluggable transceivers found in ENTITY-MIB
// (vendor/part/serial) on the interface they are plugged into.
func deriveOpticsFromEntities(snap *model.Snapshot) {
	have := map[int]int{}
	for i, o := range snap.Optics {
		have[o.IfIndex] = i
	}
	byIndex := map[int]*model.Entity{}
	for i := range snap.Inventory {
		byIndex[snap.Inventory[i].Index] = &snap.Inventory[i]
	}
	for _, e := range snap.Inventory {
		if e.Class != "module" && e.Class != "port" && e.Class != "other" {
			continue
		}
		text := e.Descr + " " + e.Model + " " + e.Name
		if !isTransceiverText(text) {
			continue
		}
		ifIndex := e.AliasIfIndex
		for p, depth := byIndex[e.ParentIndex], 0; ifIndex == 0 && p != nil && depth < 8; p, depth = byIndex[p.ParentIndex], depth+1 {
			ifIndex = p.AliasIfIndex
		}
		if ifIndex == 0 {
			continue
		}
		if i, ok := have[ifIndex]; ok {
			o := &snap.Optics[i]
			if o.Vendor == "" {
				o.Vendor = e.Manufacturer
			}
			if o.PartNumber == "" {
				o.PartNumber = e.Model
			}
			if o.Serial == "" {
				o.Serial = e.Serial
			}
			if o.Type == "" {
				o.Type = e.Descr
			}
			continue
		}
		snap.Optics = append(snap.Optics, model.Optic{IfIndex: ifIndex, Vendor: e.Manufacturer, PartNumber: e.Model, Serial: e.Serial, Type: e.Descr})
		have[ifIndex] = len(snap.Optics) - 1
	}
}

func isTransceiverText(t string) bool {
	l := strings.ToLower(t)
	for _, w := range []string{"sfp", "xfp", "qsfp", "transceiver", "gbic", "optic"} {
		if strings.Contains(l, w) {
			return true
		}
	}
	return false
}
