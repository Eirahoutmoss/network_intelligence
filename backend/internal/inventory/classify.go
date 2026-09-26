package inventory

import (
	"context"
	"encoding/json"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/Eirahoutmoss/network_intelligence/backend/internal/classify"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/fingerprint"
)

type devFacts struct {
	id    int64
	facts classify.Facts
	names []hostCand
	fp    fingerprint.Observation
}

type hostCand struct{ name, source string }

var hostPriority = map[string]int{"user": 0, "snmp": 1, "dns": 2, "netbios": 3, "dhcp": 4, "lldp": 5, "cdp": 6}

// ClassifyAll recomputes device type, OS and vendor (with evidence) for every
// device. Machine facts are inputs; results land in the derived columns only.
func (s *Store) ClassifyAll(ctx context.Context) (int, error) {
	n := 0
	err := pgx.BeginFunc(ctx, s.DB.Pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT d.id, d.managed, COALESCE(d.sys_descr,''), COALESCE(d.sys_object_id,''), COALESCE(d.vendor,''),
			COALESCE(d.os_version,''), COALESCE(d.model,''), d.is_router, d.is_bridge, d.is_printer, COALESCE(d.oui_vendor,''), d.random_mac,
			d.fingerprint, COALESCE((SELECT array_agg(name||'|'||source) FROM device_hostnames h WHERE h.device_id=d.id), '{}'),
			COALESCE((SELECT array_agg(DISTINCT c) FROM neighbors n, unnest(n.remote_capabilities) c WHERE n.remote_device_id=d.id), '{}'),
			COALESCE((SELECT string_agg(DISTINCT COALESCE(NULLIF(n.remote_sys_descr,''), n.remote_platform), ' | ') FROM neighbors n WHERE n.remote_device_id=d.id), ''),
			COALESCE((SELECT string_agg(DISTINCT n.remote_platform, ' | ') FROM neighbors n WHERE n.remote_device_id=d.id AND n.remote_platform IS NOT NULL), '')
			FROM devices d`)
		if err != nil {
			return err
		}
		var all []devFacts
		for rows.Next() {
			var d devFacts
			var fpRaw []byte
			var hosts []string
			var platform string
			f := &d.facts
			if err := rows.Scan(&d.id, &f.Managed, &f.SysDescr, &f.SysObjectID, &f.SNMPVendor, &f.NetworkOS, &f.Model,
				&f.IsRouter, &f.IsBridge, &f.IsPrinter, &f.OUIVendor, &f.RandomMAC, &fpRaw, &hosts, &f.NeighborCaps, &f.NeighborDesc, &platform); err != nil {
				rows.Close()
				return err
			}
			if platform != "" && !strings.Contains(f.NeighborDesc, platform) {
				f.NeighborDesc = strings.TrimSpace(f.NeighborDesc + " " + platform)
			}
			if len(fpRaw) > 0 {
				_ = json.Unmarshal(fpRaw, &d.fp)
			}
			f.Obs = d.fp
			if !f.Managed {
				f.NetworkOS = "" // os_version is only a fact for SNMP-managed devices
			}
			for _, h := range hosts {
				name, src, _ := strings.Cut(h, "|")
				d.names = append(d.names, hostCand{name, src})
				f.Hostnames = append(f.Hostnames, strings.ToLower(name))
			}
			all = append(all, d)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		b := &pgx.Batch{}
		for _, d := range all {
			dt := classify.DeviceType(d.facts)
			os := classify.OS(d.facts)
			vendor := classify.Vendor(d.facts)
			host := bestHostname(d.names)
			b.Queue(`UPDATE devices SET device_type=$2, device_type_confidence=$3, os_name=$4, os_confidence=$5,
				vendor=CASE WHEN managed AND vendor IS NOT NULL THEN vendor ELSE COALESCE($6, vendor) END,
				vendor_confidence=$7, vendor_source=CASE WHEN managed AND vendor_source IS NOT NULL THEN vendor_source ELSE $8 END,
				hostname=COALESCE($9, hostname) WHERE id=$1`,
				d.id, dt.Value, dt.Confidence, nz(os.Value), os.Confidence, nz(vendor.Value), vendor.Confidence, nz(evSource(vendor)), nz(host))
			b.Queue(`DELETE FROM evidence WHERE device_id=$1 AND attribute IN ('device_type','os','vendor')`, d.id)
			for _, r := range []classify.Result{dt, os, vendor} {
				for _, e := range r.Evidence {
					if r.Value == "" || r.Value == "unknown" {
						continue
					}
					b.Queue(`INSERT INTO evidence(device_id, attribute, value, source, detail, weight) VALUES ($1,$2,$3,$4,$5,$6)`,
						d.id, e.Attribute, e.Value, e.Source, nz(e.Detail), e.Weight)
				}
			}
			n++
		}
		return tx.SendBatch(ctx, b).Close()
	})
	return n, err
}

func evSource(r classify.Result) string {
	if len(r.Evidence) == 0 {
		return ""
	}
	return r.Evidence[0].Source
}

func bestHostname(c []hostCand) string {
	if len(c) == 0 {
		return ""
	}
	sort.SliceStable(c, func(i, j int) bool {
		pi, ok := hostPriority[c[i].source]
		if !ok {
			pi = 9
		}
		pj, ok := hostPriority[c[j].source]
		if !ok {
			pj = 9
		}
		return pi < pj
	})
	return c[0].name
}
