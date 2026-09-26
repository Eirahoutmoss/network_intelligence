package collectors

import (
	"context"
	"math"

	"github.com/Eirahoutmoss/network_intelligence/backend/internal/model"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/snmp"
)

const (
	oidHrProcessorLoad = "1.3.6.1.2.1.25.3.3.1.2"
	oidHrStorageEntry  = "1.3.6.1.2.1.25.2.3.1" // 2 type, 3 descr, 4 units, 5 size, 6 used
	hrStorageRAM       = "1.3.6.1.2.1.25.2.1.2"
)

// CollectHostResources reads CPU and RAM usage from HOST-RESOURCES-MIB.
// Vendor collectors may override these with more accurate values.
func CollectHostResources(ctx context.Context, s *Session, snap *model.Snapshot) error {
	if loads, err := s.Client.Walk(ctx, oidHrProcessorLoad); err == nil && len(loads) > 0 {
		var sum float64
		for _, l := range loads {
			sum += float64(l.Int())
		}
		snap.System.CPUPercent = f64(math.Round(sum/float64(len(loads))*10) / 10)
	}
	rows, order, err := snmp.Table(ctx, s.Client, oidHrStorageEntry, 2, 4, 5, 6)
	if err != nil {
		return nil
	}
	for _, idx := range order {
		r := rows[idx]
		if r[2].String() != hrStorageRAM {
			continue
		}
		size, used := float64(r[5].Int()), float64(r[6].Int())
		if size > 0 {
			snap.System.MemoryPercent = f64(math.Round(used/size*1000) / 10)
		}
		break
	}
	return nil
}
