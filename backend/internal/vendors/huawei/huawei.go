// Package huawei adds Huawei VRP/CE specific discovery.
//
// OIDs used (HUAWEI-ENTITY-EXTENT-MIB, HUAWEI-L2MAM-MIB):
//
//	hwEntityCpuUsage        1.3.6.1.4.1.2011.5.25.31.1.1.1.1.5   (percent, per entPhysicalIndex)
//	hwEntityMemUsage        1.3.6.1.4.1.2011.5.25.31.1.1.1.1.7   (percent)
//	hwEntityTemperature     1.3.6.1.4.1.2011.5.25.31.1.1.1.1.11  (°C)
//	hwEntityOpticalRxPower  1.3.6.1.4.1.2011.5.25.31.1.1.3.1.8   (µW)
//	hwEntityOpticalTxPower  1.3.6.1.4.1.2011.5.25.31.1.1.3.1.9   (µW)
//	hwDynFdbPort            1.3.6.1.4.1.2011.5.25.42.2.1.3.1.4   (index mac.vlan.vsi)
//
// These must be verified against real hardware; values outside plausible
// ranges are discarded rather than shown.
package huawei

import (
	"context"
	"math"
	"regexp"
	"strconv"
	"strings"

	"github.com/Eirahoutmoss/network_intelligence/backend/internal/collectors"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/model"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/snmp"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/vendors"
)

const (
	OIDCPU        = "1.3.6.1.4.1.2011.5.25.31.1.1.1.1.5"
	OIDMem        = "1.3.6.1.4.1.2011.5.25.31.1.1.1.1.7"
	OIDTemp       = "1.3.6.1.4.1.2011.5.25.31.1.1.1.1.11"
	OIDOpticRx    = "1.3.6.1.4.1.2011.5.25.31.1.1.3.1.8"
	OIDOpticTx    = "1.3.6.1.4.1.2011.5.25.31.1.1.3.1.9"
	OIDDynFdbPort = "1.3.6.1.4.1.2011.5.25.42.2.1.3.1.4"
	enterprise    = 2011
)

type Adapter struct{}

func (Adapter) Name() string { return "huawei" }

func (Adapter) Match(sys model.System) bool {
	return vendors.EnterpriseOf(sys.ObjectID) == enterprise || strings.Contains(strings.ToLower(sys.Descr), "huawei")
}

var (
	reVRP   = regexp.MustCompile(`(?i)Version\s+([\d.]+)\s*\(([A-Za-z0-9]+)\s+(V\d+R\d+\w*)\)`)
	reModel = regexp.MustCompile(`^(?:HUAWEI\s+|Quidway\s+)?([A-Z]{1,6}\d{2,5}[A-Z0-9]*(?:-[A-Z0-9+]+)+)$`)
)

func (Adapter) Enrich(sys *model.System) {
	sys.Vendor = "Huawei"
	if m := reVRP.FindStringSubmatch(sys.Descr); m != nil {
		sys.OSName = "VRP"
		sys.OSVersion = m[1] + " " + m[3]
		if sys.Model == "" {
			sys.Model = m[2]
		}
	} else if strings.Contains(sys.Descr, "VRP") {
		sys.OSName = "VRP"
	}
	// Full model name is often the first or last line of sysDescr.
	lines := strings.FieldsFunc(sys.Descr, func(r rune) bool { return r == '\n' || r == '\r' })
	for _, l := range lines {
		if m := reModel.FindStringSubmatch(strings.TrimSpace(l)); m != nil {
			if sys.Model == "" || strings.HasPrefix(m[1], sys.Model) {
				sys.Model = m[1]
			}
		}
	}
}

func (Adapter) Collectors() []collectors.Collector {
	return []collectors.Collector{
		collectors.Func{N: "huawei_health", F: collectHealth},
		collectors.Func{N: "huawei_optics", F: collectOptics},
		collectors.Func{N: "huawei_fdb", F: collectFDB},
	}
}

func entityNames(snap *model.Snapshot) map[int]model.Entity {
	m := map[int]model.Entity{}
	for _, e := range snap.Inventory {
		m[e.Index] = e
	}
	return m
}

func collectHealth(ctx context.Context, s *collectors.Session, snap *model.Snapshot) error {
	ents := entityNames(snap)
	// CPU/memory are reported per board; use the main board (highest non-zero value on an MPU)
	pick := func(oid string) (float64, bool) {
		vals, err := s.Client.Walk(ctx, oid)
		if err != nil || len(vals) == 0 {
			return 0, false
		}
		best, ok := 0.0, false
		for _, v := range vals {
			n := float64(v.Int())
			if n <= 0 || n > 100 {
				continue
			}
			if !ok || n > best {
				best, ok = n, true
			}
		}
		return best, ok
	}
	if v, ok := pick(OIDCPU); ok {
		snap.System.CPUPercent = &v
	}
	if v, ok := pick(OIDMem); ok {
		snap.System.MemoryPercent = &v
	}
	temps, err := s.Client.Walk(ctx, OIDTemp)
	if err != nil {
		return nil
	}
	for _, t := range temps {
		v := float64(t.Int())
		if v <= 0 || v > 150 {
			continue
		}
		idx, _ := snmp.Suffix(t.OID, OIDTemp)
		n, _ := strconv.Atoi(idx)
		name := ents[n].Name
		if name == "" {
			name = "Board " + idx
		}
		status := "ok"
		if v >= 75 {
			status = "warning"
		}
		if v >= 90 {
			status = "critical"
		}
		snap.Sensors = append(snap.Sensors, model.Sensor{Kind: "temperature", Name: name, Value: &v, Unit: "°C", Status: status})
	}
	return nil
}

// uWToDBm converts microwatts to dBm; returns nil for implausible values.
func uWToDBm(uw int64) *float64 {
	if uw <= 0 || uw > 100000 {
		return nil
	}
	v := math.Round(10*math.Log10(float64(uw)/1000)*100) / 100
	return &v
}

func collectOptics(ctx context.Context, s *collectors.Session, snap *model.Snapshot) error {
	rx, err := s.Client.Walk(ctx, OIDOpticRx)
	if err != nil || len(rx) == 0 {
		return nil
	}
	tx, _ := s.Client.Walk(ctx, OIDOpticTx)
	txBy := map[string]int64{}
	for _, p := range tx {
		idx, _ := snmp.Suffix(p.OID, OIDOpticTx)
		txBy[idx] = p.Int()
	}
	ents := entityNames(snap)
	for _, p := range rx {
		idx, _ := snmp.Suffix(p.OID, OIDOpticRx)
		n, _ := strconv.Atoi(idx)
		e, ok := ents[n]
		if !ok {
			continue
		}
		ifIndex := e.AliasIfIndex
		if ifIndex == 0 {
			if it := snap.InterfaceByName(e.Name); it != nil {
				ifIndex = it.IfIndex
			} else if parent, ok := ents[e.ParentIndex]; ok {
				ifIndex = parent.AliasIfIndex
			}
		}
		if ifIndex == 0 {
			continue
		}
		o := model.Optic{IfIndex: ifIndex, RxDBm: uWToDBm(p.Int()), TxDBm: uWToDBm(txBy[idx]),
			Vendor: e.Manufacturer, PartNumber: e.Model, Serial: e.Serial, Type: e.Descr}
		if o.RxDBm == nil && o.TxDBm == nil {
			continue // not a transceiver or no DOM
		}
		merged := false
		for i := range snap.Optics {
			if snap.Optics[i].IfIndex == ifIndex {
				snap.Optics[i].RxDBm, snap.Optics[i].TxDBm = o.RxDBm, o.TxDBm
				merged = true
			}
		}
		if !merged {
			snap.Optics = append(snap.Optics, o)
		}
	}
	return nil
}

// collectFDB uses the Huawei dynamic MAC table when the standard bridge MIBs are empty.
func collectFDB(ctx context.Context, s *collectors.Session, snap *model.Snapshot) error {
	if len(snap.FDB) > 0 {
		return nil
	}
	rows, err := s.Client.Walk(ctx, OIDDynFdbPort)
	if err != nil {
		return nil
	}
	for _, p := range rows {
		idx, _ := snmp.Suffix(p.OID, OIDDynFdbPort)
		parts := snmp.IndexInts(idx)
		if len(parts) < 7 {
			continue
		}
		mac := snmp.NormalizeMAC(strings.Join(func() []string {
			out := make([]string, 6)
			for i := 0; i < 6; i++ {
				out[i] = strconv.FormatInt(int64(parts[i])+0x100, 16)[1:]
			}
			return out
		}(), ":"))
		ifIndex := int(p.Int())
		if mac == "" || snap.InterfaceByIndex(ifIndex) == nil {
			continue
		}
		snap.FDB = append(snap.FDB, model.FDBEntry{MAC: mac, VLAN: parts[6], IfIndex: ifIndex, Status: "learned"})
	}
	return nil
}
