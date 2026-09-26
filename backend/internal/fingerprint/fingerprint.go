// Package fingerprint gathers endpoint evidence (hostname, OS hints, services)
// used by classification.
//
// Two modes exist:
//   - passive: reverse DNS only (always safe)
//   - active:  NetBIOS name query, a short TCP connect check of well-known
//     service ports, HTTP banner, SMB negotiate and SNMP sysDescr with the
//     discovery credential. Active probing is opt-in, limited to the
//     authorized discovery scope and rate limited.
package fingerprint

import (
	"context"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// Observation is everything learned about one IP.
type Observation struct {
	IP             string   `json:"ip"`
	Hostname       string   `json:"hostname,omitempty"`
	HostnameSource string   `json:"hostname_source,omitempty"` // dns|netbios|dhcp|snmp
	NetBIOSName    string   `json:"netbios_name,omitempty"`
	NetBIOSGroup   string   `json:"netbios_group,omitempty"`
	SMBNativeOS    string   `json:"smb_native_os,omitempty"`
	SMBDialect     string   `json:"smb_dialect,omitempty"`
	SMBLanMan      string   `json:"smb_lanman,omitempty"`
	HTTPServer     string   `json:"http_server,omitempty"`
	HTTPTitle      string   `json:"http_title,omitempty"`
	OpenPorts      []int    `json:"open_ports,omitempty"`
	TTL            int      `json:"ttl,omitempty"`
	SNMPSysDescr   string   `json:"snmp_sys_descr,omitempty"`
	SNMPObjectID   string   `json:"snmp_object_id,omitempty"`
	SNMPIsPrinter  bool     `json:"snmp_is_printer,omitempty"`
	DHCPVendor     string   `json:"dhcp_vendor_class,omitempty"`
	DHCPParams     string   `json:"dhcp_params,omitempty"` // option 55 list, comma separated
	Notes          []string `json:"notes,omitempty"`
}

// HasPort reports whether port was found open.
func (o Observation) HasPort(p int) bool {
	for _, x := range o.OpenPorts {
		if x == p {
			return true
		}
	}
	return false
}

// Options controls what a Prober may do.
type Options struct {
	Active  bool
	Timeout time.Duration
}

// Prober gathers observations for IPs.
type Prober interface {
	Probe(ctx context.Context, ip string, opt Options) Observation
}

// Resolver does reverse DNS lookups.
type Resolver interface {
	LookupAddr(ctx context.Context, addr string) ([]string, error)
}

// ProbeAll probes many IPs with bounded concurrency and a minimum spacing
// between probe starts (rate limit), preserving input order.
func ProbeAll(ctx context.Context, p Prober, ips []string, opt Options, workers int, spacing time.Duration) []Observation {
	if workers <= 0 {
		workers = 8
	}
	out := make([]Observation, len(ips))
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	tick := time.NewTicker(max(spacing, time.Millisecond))
	defer tick.Stop()
	for i, ip := range ips {
		if ctx.Err() != nil {
			break
		}
		if spacing > 0 {
			select {
			case <-tick.C:
			case <-ctx.Done():
			}
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(i int, ip string) {
			defer wg.Done()
			defer func() { <-sem }()
			out[i] = p.Probe(ctx, ip, opt)
		}(i, ip)
	}
	wg.Wait()
	return out
}

// StaticProber returns canned observations (simulator and tests).
type StaticProber struct {
	Obs map[string]Observation
}

func (s StaticProber) Probe(ctx context.Context, ip string, opt Options) Observation {
	o, ok := s.Obs[ip]
	if !ok {
		return Observation{IP: ip}
	}
	o.IP = ip
	if !opt.Active {
		// Passive mode only exposes DNS-derived data.
		return Observation{IP: ip, Hostname: o.Hostname, HostnameSource: o.HostnameSource}
	}
	return o
}

// CleanHostname strips domains' trailing dot and lowercases.
func CleanHostname(h string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(h), "."))
}

// ShortName returns the host part of an FQDN.
func ShortName(h string) string {
	h = CleanHostname(h)
	if net.ParseIP(h) != nil {
		return h
	}
	if i := strings.IndexByte(h, '.'); i > 0 {
		return h[:i]
	}
	return h
}

func sortedPorts(p []int) []int {
	sort.Ints(p)
	return p
}
