package inventory

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/Eirahoutmoss/network_intelligence/backend/internal/events"
)

// MergeDevices folds device drop into keep. Both are the same physical device
// according to identity resolution. User context on keep wins; user context
// that exists only on drop is carried over.
func MergeDevices(ctx context.Context, tx pgx.Tx, keep, drop int64, reason string) error {
	if keep == drop {
		return nil
	}
	stmts := []string{
		// fill discovered facts that keep does not have yet
		`UPDATE devices k SET
			hostname=COALESCE(k.hostname,d.hostname), sys_name=COALESCE(k.sys_name,d.sys_name), sys_descr=COALESCE(k.sys_descr,d.sys_descr),
			sys_object_id=COALESCE(k.sys_object_id,d.sys_object_id), vendor=COALESCE(k.vendor,d.vendor), model=COALESCE(k.model,d.model),
			serial=COALESCE(k.serial,d.serial), os_version=COALESCE(k.os_version,d.os_version), mgmt_ip=COALESCE(k.mgmt_ip,d.mgmt_ip),
			chassis_id=COALESCE(k.chassis_id,d.chassis_id), managed=k.managed OR d.managed,
			snmp_credential_id=COALESCE(k.snmp_credential_id,d.snmp_credential_id), ssh_credential_id=COALESCE(k.ssh_credential_id,d.ssh_credential_id),
			telnet_credential_id=COALESCE(k.telnet_credential_id,d.telnet_credential_id), telnet_enabled=k.telnet_enabled OR d.telnet_enabled,
			oui_vendor=COALESCE(k.oui_vendor,d.oui_vendor),
			fingerprint=CASE WHEN k.fingerprint='{}'::jsonb THEN d.fingerprint ELSE k.fingerprint END,
			first_seen=LEAST(k.first_seen,d.first_seen), last_seen=GREATEST(k.last_seen,d.last_seen)
		 FROM devices d WHERE k.id=$1 AND d.id=$2`,
		`INSERT INTO device_addresses(device_id,ip,prefix_len,if_index,source,first_seen,last_seen)
		 SELECT $1,ip,prefix_len,if_index,source,first_seen,last_seen FROM device_addresses WHERE device_id=$2 ON CONFLICT DO NOTHING`,
		`INSERT INTO device_macs(device_id,mac,source,first_seen,last_seen)
		 SELECT $1,mac,source,first_seen,last_seen FROM device_macs WHERE device_id=$2 ON CONFLICT DO NOTHING`,
		`INSERT INTO device_hostnames(device_id,name,source,last_seen)
		 SELECT $1,name,source,last_seen FROM device_hostnames WHERE device_id=$2 ON CONFLICT DO NOTHING`,
		`UPDATE evidence SET device_id=$1 WHERE device_id=$2 AND attribute='identity'`,
		// managed-device tables move only when keep has none
		`UPDATE interfaces SET device_id=$1 WHERE device_id=$2 AND NOT EXISTS (SELECT 1 FROM interfaces WHERE device_id=$1)`,
		`UPDATE neighbors SET device_id=$1 WHERE device_id=$2 AND NOT EXISTS (SELECT 1 FROM neighbors WHERE device_id=$1)`,
		`UPDATE fdb_entries SET device_id=$1 WHERE device_id=$2 AND NOT EXISTS (SELECT 1 FROM fdb_entries WHERE device_id=$1)`,
		`UPDATE arp_entries SET device_id=$1 WHERE device_id=$2 AND NOT EXISTS (SELECT 1 FROM arp_entries WHERE device_id=$1)`,
		`UPDATE routes SET device_id=$1 WHERE device_id=$2 AND NOT EXISTS (SELECT 1 FROM routes WHERE device_id=$1)`,
		`UPDATE vlans SET device_id=$1 WHERE device_id=$2 AND NOT EXISTS (SELECT 1 FROM vlans WHERE device_id=$1)`,
		`UPDATE inventory_items SET device_id=$1 WHERE device_id=$2 AND NOT EXISTS (SELECT 1 FROM inventory_items WHERE device_id=$1)`,
		`UPDATE sensors SET device_id=$1 WHERE device_id=$2 AND NOT EXISTS (SELECT 1 FROM sensors WHERE device_id=$1)`,
		`UPDATE neighbors SET remote_device_id=$1 WHERE remote_device_id=$2`,
		// attachment history: end drop's current attachment if keep has one
		`UPDATE attachments SET ended_at=now() WHERE device_id=$2 AND ended_at IS NULL AND EXISTS (SELECT 1 FROM attachments WHERE device_id=$1 AND ended_at IS NULL)`,
		`UPDATE attachments SET device_id=$1 WHERE device_id=$2`,
		`UPDATE attachments SET switch_id=$1 WHERE switch_id=$2`,
		`DELETE FROM topology_edges WHERE a_device_id=$2 OR b_device_id=$2`,
		`UPDATE manual_links SET a_device_id=$1 WHERE a_device_id=$2`,
		`UPDATE manual_links SET b_device_id=$1 WHERE b_device_id=$2`,
		`UPDATE topology_layout SET device_id=$1 WHERE device_id=$2 AND NOT EXISTS (SELECT 1 FROM topology_layout WHERE device_id=$1)`,
		`UPDATE device_context SET device_id=$1 WHERE device_id=$2 AND NOT EXISTS (SELECT 1 FROM device_context WHERE device_id=$1)`,
		`INSERT INTO device_tags(device_id,tag) SELECT $1,tag FROM device_tags WHERE device_id=$2 ON CONFLICT DO NOTHING`,
		`UPDATE network_jacks SET switch_device_id=$1 WHERE switch_device_id=$2`,
		`UPDATE alerts SET resolved_at=now() WHERE device_id=$2 AND resolved_at IS NULL`,
		`UPDATE alerts SET device_id=$1 WHERE device_id=$2`,
		`UPDATE events SET device_id=$1 WHERE device_id=$2`,
		`UPDATE cli_sessions SET device_id=$1 WHERE device_id=$2`,
		`UPDATE poll_runs SET device_id=$1 WHERE device_id=$2`,
		`UPDATE subnets SET gateway_device_id=$1 WHERE gateway_device_id=$2`,
		`DELETE FROM devices WHERE id=$2`,
	}
	for i, q := range stmts {
		if _, err := tx.Exec(ctx, q, keep, drop); err != nil {
			return fmt.Errorf("merge %d into %d (step %d): %w", drop, keep, i, err)
		}
	}
	if _, err := tx.Exec(ctx, `INSERT INTO evidence(device_id, attribute, value, source, detail, weight) VALUES ($1,'identity','merged',$2,$3,1)`,
		keep, "Identity resolution", fmt.Sprintf("record #%d merged: %s", drop, reason)); err != nil {
		return err
	}
	events.Record(ctx, tx, keep, events.DevicesMerged, events.Info, fmt.Sprintf("Merged duplicate record #%d (%s)", drop, reason), nil)
	return nil
}
