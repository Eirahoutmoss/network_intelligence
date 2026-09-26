package collectors

import (
	"context"
	"math"
	"strconv"

	"github.com/Eirahoutmoss/network_intelligence/backend/internal/model"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/snmp"
)

const oidEntPhySensorEntry = "1.3.6.1.2.1.99.1.1.1" // 1 type, 2 scale, 3 precision, 4 value, 5 operStatus

var sensorType = map[int64]struct{ kind, unit string }{
	3: {"voltage", "V"}, 4: {"voltage", "V"}, 5: {"current", "A"}, 6: {"power", "W"},
	7: {"frequency", "Hz"}, 8: {"temperature", "°C"}, 9: {"humidity", "%"}, 10: {"fan", "rpm"},
	11: {"airflow", "cmm"},
}

// CollectEntitySensors reads ENTITY-SENSOR-MIB (temperatures, fans, PSU power, optics DOM on some vendors).
func CollectEntitySensors(ctx context.Context, s *Session, snap *model.Snapshot) error {
	rows, order, err := snmp.Table(ctx, s.Client, oidEntPhySensorEntry, 1, 2, 3, 4, 5)
	if err != nil {
		return err
	}
	names := map[int]string{}
	for _, e := range snap.Inventory {
		names[e.Index] = firstNonEmpty(e.Name, e.Descr)
	}
	for _, idx := range order {
		r := rows[idx]
		t, ok := sensorType[r[1].Int()]
		if !ok {
			continue
		}
		n, _ := strconv.Atoi(idx)
		exp := scaleExp(r[2].Int()) - int(r[3].Int())
		v := float64(r[4].Int()) * math.Pow10(exp)
		v = math.Round(v*100) / 100
		status := "ok"
		switch r[5].Int() {
		case 2:
			status = "unknown"
		case 3:
			status = "critical"
		}
		name := names[n]
		if name == "" {
			name = t.kind + " " + idx
		}
		snap.Sensors = append(snap.Sensors, model.Sensor{Kind: t.kind, Name: name, Value: f64(v), Unit: t.unit, Status: status})
	}
	return nil
}

func scaleExp(scale int64) int {
	// yocto(1)..units(9)..yotta(17), step 3
	if scale < 1 || scale > 17 {
		return 0
	}
	return int(scale-9) * 3
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}
