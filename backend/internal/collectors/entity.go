package collectors

import (
	"context"
	"strconv"
	"strings"

	"github.com/Eirahoutmoss/network_intelligence/backend/internal/model"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/snmp"
)

const (
	oidEntPhysicalEntry = "1.3.6.1.2.1.47.1.1.1.1"
	oidEntAliasMapping  = "1.3.6.1.2.1.47.1.3.2.1.2"
	oidIfIndexPrefix    = "1.3.6.1.2.1.2.2.1.1."
)

var entClass = map[int64]string{1: "other", 2: "unknown", 3: "chassis", 4: "backplane", 5: "container",
	6: "powerSupply", 7: "fan", 8: "sensor", 9: "module", 10: "port", 11: "stack", 12: "cpu"}

// CollectEntities reads ENTITY-MIB physical inventory: chassis model/serial,
// modules, transceivers, PSUs and fans.
func CollectEntities(ctx context.Context, s *Session, snap *model.Snapshot) error {
	rows, order, err := snmp.Table(ctx, s.Client, oidEntPhysicalEntry, 2, 4, 5, 7, 8, 9, 10, 11, 12, 13)
	if err != nil {
		return err
	}
	alias := map[int]int{}
	if am, err := s.Client.Walk(ctx, oidEntAliasMapping); err == nil {
		for _, p := range am {
			idx, _ := snmp.Suffix(p.OID, oidEntAliasMapping)
			parts := snmp.IndexInts(idx)
			if len(parts) == 0 {
				continue
			}
			target := p.String()
			if strings.HasPrefix(target, oidIfIndexPrefix) {
				n, _ := strconv.Atoi(strings.TrimPrefix(target, oidIfIndexPrefix))
				alias[parts[0]] = n
			}
		}
	}
	for _, idx := range order {
		n, err := strconv.Atoi(idx)
		if err != nil {
			continue
		}
		r := rows[idx]
		e := model.Entity{
			Index:        n,
			Descr:        r[2].String(),
			ParentIndex:  int(r[4].Int()),
			Class:        entClass[r[5].Int()],
			Name:         r[7].String(),
			HWRev:        r[8].String(),
			FWRev:        r[9].String(),
			SWRev:        r[10].String(),
			Serial:       r[11].String(),
			Manufacturer: r[12].String(),
			Model:        r[13].String(),
			AliasIfIndex: alias[n],
		}
		snap.Inventory = append(snap.Inventory, e)
	}
	// Chassis identity: prefer the first chassis with a serial.
	var chassis *model.Entity
	for i := range snap.Inventory {
		e := &snap.Inventory[i]
		if e.Class != "chassis" {
			continue
		}
		if chassis == nil || (chassis.Serial == "" && e.Serial != "") {
			chassis = e
		}
	}
	if chassis != nil {
		if snap.System.Serial == "" {
			snap.System.Serial = chassis.Serial
		}
		if snap.System.Model == "" && chassis.Model != "" {
			snap.System.Model = chassis.Model
		}
		if snap.System.HardwareRev == "" {
			snap.System.HardwareRev = chassis.HWRev
		}
	}
	// Link port entities to interfaces by name when alias mapping is missing.
	for i := range snap.Inventory {
		e := &snap.Inventory[i]
		if e.AliasIfIndex == 0 && (e.Class == "port" || e.Class == "module") && e.Name != "" {
			if it := snap.InterfaceByName(e.Name); it != nil {
				e.AliasIfIndex = it.IfIndex
			}
		}
	}
	return nil
}
