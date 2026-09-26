package discovery

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/Eirahoutmoss/network_intelligence/backend/internal/collectors"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/credentials"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/model"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/snmp"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/vendors"
)

// Step is a user-visible progress item ("✓ SNMP authenticated").
type Step struct {
	Key    string    `json:"key"`
	Label  string    `json:"label"`
	Status string    `json:"status"` // running|done|failed|skipped|warning
	Detail string    `json:"detail,omitempty"`
	Device string    `json:"device,omitempty"`
	At     time.Time `json:"at"`
}

// Progress receives steps as they happen.
type Progress func(Step)

// Collector gathers a full snapshot from one device.
type Collector struct {
	Dialer   snmp.Dialer
	Registry *vendors.Registry
	Log      *slog.Logger
}

// autodetect tries the usual SNMPv3 protocol combinations with the password
// the user gave: other auth hashes first, then authPriv reusing the same
// password for privacy (a very common configuration).
func (c *Collector) autodetect(ctx context.Context, host string, cred credentials.SNMP, firstErr error, step func(key, label, status, detail string)) (snmp.Client, credentials.SNMP, model.System, error) {
	type combo struct{ level, auth, priv string }
	var combos []combo
	for _, a := range []string{"SHA", "SHA256", "MD5", "SHA512", "SHA224", "SHA384"} {
		if a != cred.AuthProtocol || cred.SecurityLevel != "authNoPriv" {
			combos = append(combos, combo{"authNoPriv", a, ""})
		}
	}
	for _, a := range []string{"SHA", "SHA256", "MD5"} {
		for _, p := range []string{"AES", "AES256", "DES"} {
			combos = append(combos, combo{"authPriv", a, p})
		}
	}
	step("autodetect", "Trying other SNMPv3 security settings", "running", "")
	lastErr := firstErr
	// A device that requires privacy for this user answers authNoPriv requests
	// with "unsupported security level"; only then are authPriv combos worth trying.
	needPriv := strings.Contains(strings.ToLower(fmt.Sprint(lastErr)), "security level")
	// A failed attempt means: "security level" in the error → try authPriv.
	for _, cb := range combos {
		if ctx.Err() != nil {
			return nil, cred, model.System{}, ctx.Err()
		}
		if cb.level == "authPriv" && !needPriv {
			break
		}
		try := cred
		try.SecurityLevel, try.AuthProtocol, try.PrivProtocol = cb.level, cb.auth, cb.priv
		try.PrivPassword = ""
		if cb.level == "authPriv" {
			try.PrivPassword = cred.AuthPassword
		}
		cl, err := c.Dialer.Dial(ctx, host, try)
		if err != nil {
			lastErr = err
			continue
		}
		sys, err := collectors.Identify(ctx, cl)
		if err == nil {
			try.Autodetect = false
			detail := try.SecurityLevel + " " + try.AuthProtocol
			if try.PrivProtocol != "" {
				detail += "/" + try.PrivProtocol
			}
			step("autodetect", "SNMPv3 security settings detected", "done", detail)
			return cl, try, sys, nil
		}
		cl.Close()
		lastErr = err
		if strings.Contains(strings.ToLower(err.Error()), "security level") {
			needPriv = true
		}
	}
	step("autodetect", "SNMPv3 security settings", "failed", "no combination of the given password and common protocols was accepted")
	return nil, cred, model.System{}, fmt.Errorf("%w", lastErr)
}

// ErrUnreachable/ErrAuth are returned for the two failure modes users care about.
var (
	ErrUnreachable = errors.New("device did not answer SNMP")
	ErrAuthFailed  = errors.New("SNMP authentication failed")
)

// Collect runs reachability, authentication, identification and every
// applicable collector against host. Collector failures are recorded on the
// snapshot but do not fail the whole collection.
func (c *Collector) Collect(ctx context.Context, host string, cred credentials.SNMP, full bool, progress Progress) (*model.Snapshot, error) {
	snap, _, err := c.CollectWithCredential(ctx, host, cred, full, progress)
	return snap, err
}

// CollectWithCredential is Collect that also returns the credential that
// worked (it differs from the input when SNMPv3 settings were auto-detected).
func (c *Collector) CollectWithCredential(ctx context.Context, host string, cred credentials.SNMP, full bool, progress Progress) (*model.Snapshot, credentials.SNMP, error) {
	snap, err := c.collect(ctx, host, &cred, full, progress)
	return snap, cred, err
}

func (c *Collector) collect(ctx context.Context, host string, credp *credentials.SNMP, full bool, progress Progress) (*model.Snapshot, error) {
	cred := *credp
	defer func() { *credp = cred }()
	if progress == nil {
		progress = func(Step) {}
	}
	step := func(key, label, status, detail string) {
		progress(Step{Key: key, Label: label, Status: status, Detail: detail, Device: host, At: time.Now()})
	}
	if err := cred.Normalize(); err != nil {
		return nil, err
	}
	step("reachable", "Connecting to "+host, "running", "")
	client, err := c.Dialer.Dial(ctx, host, cred)
	if err != nil {
		step("reachable", "Connecting to "+host, "failed", err.Error())
		if errors.Is(err, snmp.ErrTimeout) {
			return nil, fmt.Errorf("%w: %v", ErrUnreachable, err)
		}
		return nil, err
	}
	defer client.Close()

	sys, err := collectors.Identify(ctx, client)
	if err != nil && errors.Is(err, snmp.ErrAuth) && cred.Autodetect {
		client.Close()
		var detected credentials.SNMP
		client, detected, sys, err = c.autodetect(ctx, host, cred, err, step)
		if err == nil {
			cred = detected
			defer client.Close()
		}
	}
	if err != nil {
		switch {
		case errors.Is(err, snmp.ErrAuth):
			step("reachable", "Device reachable", "done", "")
			step("auth", "SNMP authentication", "failed", err.Error())
			return nil, fmt.Errorf("%w: %v", ErrAuthFailed, err)
		case errors.Is(err, snmp.ErrTimeout):
			step("reachable", "Device reachable", "failed", "no SNMP response — check the IP address, credentials, SNMP ACLs and firewalls")
			return nil, fmt.Errorf("%w: %v", ErrUnreachable, err)
		}
		step("auth", "SNMP authentication", "failed", err.Error())
		return nil, err
	}
	step("reachable", "Device reachable", "done", "")
	ver := "SNMPv" + cred.Version
	if cred.Version == "3" {
		ver += " " + cred.SecurityLevel
	}
	step("auth", "SNMP authenticated", "done", ver)

	snap := &model.Snapshot{Target: host, CollectedAt: time.Now(), System: sys, Raw: map[string]string{}}
	session := &collectors.Session{Client: client, Target: host, Log: c.Log,
		ContextClient: func(ctx context.Context, name string) (snmp.Client, error) {
			return c.Dialer.Dial(ctx, host, snmp.WithContext(cred, name))
		}}

	cs := collectors.Poll()
	if full {
		cs = collectors.Standard()
	}
	// system first so vendor detection can use it
	collectors.Run(ctx, session, snap, cs[:1])
	vendor, source := vendors.DetectVendor(snap.System)
	snap.System.Vendor, snap.System.VendorSource = vendor, source
	var adapter vendors.Adapter
	if c.Registry != nil {
		adapter = c.Registry.For(snap.System)
	}
	if vendor != "" {
		step("vendor", vendor+" detected", "done", "from "+source)
	} else {
		step("vendor", "Vendor detection", "warning", "vendor not recognized; using standard MIBs only")
	}

	labels := map[string]string{
		"interfaces": "Interfaces", "ip_addresses": "IP addresses", "inventory": "Hardware inventory",
		"lldp": "LLDP neighbors", "vlans": "VLANs", "fdb": "MAC address table", "arp": "ARP table",
		"routes": "Routing table", "host_resources": "CPU / memory", "entity_sensors": "Sensors",
		"cdp": "CDP neighbors",
	}
	rest := cs[1:]
	if adapter != nil {
		rest = append(rest, adapter.Collectors()...)
	}
	for _, col := range rest {
		key := col.Name()
		label := labels[key]
		if label == "" {
			label = strings.ReplaceAll(key, "_", " ")
		}
		res := collectors.Run(ctx, session, snap, []collectors.Collector{col})
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if len(res) == 1 && res[0].Err != nil {
			if full {
				step(key, label, "warning", res[0].Err.Error())
			}
			continue
		}
		if full {
			step(key, label, "done", summarize(key, snap))
		}
	}
	collectors.Finalize(snap)
	if adapter != nil {
		adapter.Enrich(&snap.System)
	}
	if snap.System.Model != "" {
		step("model", "Model detected", "done", snap.System.Model)
	}
	return snap, nil
}

func summarize(key string, s *model.Snapshot) string {
	switch key {
	case "interfaces":
		up := 0
		for _, i := range s.Interfaces {
			if i.OperStatus == "up" {
				up++
			}
		}
		return fmt.Sprintf("%d interfaces (%d up)", len(s.Interfaces), up)
	case "ip_addresses":
		return fmt.Sprintf("%d addresses", len(s.IPs))
	case "inventory":
		return fmt.Sprintf("%d components", len(s.Inventory))
	case "lldp", "cdp":
		n := 0
		for _, x := range s.Neighbors {
			if x.Protocol == key {
				n++
			}
		}
		return fmt.Sprintf("%d neighbors", n)
	case "vlans":
		return fmt.Sprintf("%d VLANs", len(s.VLANs))
	case "fdb", "huawei_fdb", "cisco_fdb":
		return fmt.Sprintf("%d MAC entries", len(s.FDB))
	case "arp":
		return fmt.Sprintf("%d ARP entries", len(s.ARP))
	case "routes":
		return fmt.Sprintf("%d routes", len(s.Routes))
	case "entity_sensors":
		return fmt.Sprintf("%d sensors", len(s.Sensors))
	case "huawei_optics":
		return fmt.Sprintf("%d transceivers", len(s.Optics))
	}
	return ""
}
