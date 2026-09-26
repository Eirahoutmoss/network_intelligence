package fingerprint

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Eirahoutmoss/network_intelligence/backend/internal/credentials"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/snmp"
)

// ProbePorts are the TCP services checked in active mode. Only a connect is
// attempted (no payload), except for HTTP and SMB identification.
var ProbePorts = []int{22, 23, 80, 135, 139, 443, 445, 515, 554, 631, 3389, 5060, 8080, 9100}

// NetProber gathers real observations.
type NetProber struct {
	Dialer   snmp.Dialer
	Resolver Resolver
	// Community used for the optional SNMP identification probe (default "public").
	Community string
}

func (p NetProber) Probe(ctx context.Context, ip string, opt Options) Observation {
	o := Observation{IP: ip}
	if opt.Timeout <= 0 {
		opt.Timeout = 2 * time.Second
	}
	res := p.Resolver
	if res == nil {
		res = net.DefaultResolver
	}
	dctx, cancel := context.WithTimeout(ctx, opt.Timeout)
	if names, err := res.LookupAddr(dctx, ip); err == nil && len(names) > 0 {
		o.Hostname, o.HostnameSource = CleanHostname(names[0]), "dns"
	}
	cancel()
	if !opt.Active {
		return o
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	for _, port := range ProbePorts {
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			d := net.Dialer{Timeout: 700 * time.Millisecond}
			c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
			if err == nil {
				c.Close()
				mu.Lock()
				o.OpenPorts = append(o.OpenPorts, port)
				mu.Unlock()
			}
		}(port)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		name, group := netbiosStatus(ctx, ip, opt.Timeout)
		mu.Lock()
		o.NetBIOSName, o.NetBIOSGroup = name, group
		mu.Unlock()
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		p.snmpProbe(ctx, ip, &o, &mu)
	}()
	wg.Wait()
	o.OpenPorts = sortedPorts(o.OpenPorts)
	if o.HasPort(80) || o.HasPort(8080) || o.HasPort(443) {
		o.HTTPServer, o.HTTPTitle = httpBanner(ctx, ip, o)
	}
	if o.HasPort(445) {
		smb := SMBProbe(ctx, net.JoinHostPort(ip, "445"), opt.Timeout)
		o.SMBDialect, o.SMBNativeOS, o.SMBLanMan = smb.Dialect, smb.NativeOS, smb.LanMan
		if o.NetBIOSName == "" && smb.NetBIOSName != "" {
			o.NetBIOSName = smb.NetBIOSName
		}
		if o.NetBIOSGroup == "" && smb.Domain != "" {
			o.NetBIOSGroup = smb.Domain
		}
	}
	if o.Hostname == "" && o.NetBIOSName != "" {
		o.Hostname, o.HostnameSource = strings.ToLower(o.NetBIOSName), "netbios"
	}
	return o
}

func (p NetProber) snmpProbe(ctx context.Context, ip string, o *Observation, mu *sync.Mutex) {
	if p.Dialer == nil {
		return
	}
	community := p.Community
	if community == "" {
		community = "public"
	}
	c, err := p.Dialer.Dial(ctx, ip, credentials.SNMP{Community: community})
	if err != nil {
		return
	}
	defer c.Close()
	res, err := c.Get(ctx, "1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.2.0")
	if err != nil || len(res) < 2 {
		return
	}
	mu.Lock()
	o.SNMPSysDescr, o.SNMPObjectID = res[0].String(), res[1].String()
	mu.Unlock()
	if pr, err := c.Walk(ctx, "1.3.6.1.2.1.43.5.1.1.16"); err == nil && len(pr) > 0 {
		mu.Lock()
		o.SNMPIsPrinter = true
		mu.Unlock()
	}
}

var reTitle = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

func httpBanner(ctx context.Context, ip string, o Observation) (server, title string) {
	client := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			// Identification only: no credentials are sent, certificates of
			// embedded devices are almost always self-signed.
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
			Proxy:           nil,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 2 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	var urls []string
	if o.HasPort(80) {
		urls = append(urls, "http://"+ip+"/")
	}
	if o.HasPort(443) {
		urls = append(urls, "https://"+ip+"/")
	}
	if o.HasPort(8080) {
		urls = append(urls, "http://"+ip+":8080/")
	}
	for _, u := range urls {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Nexus-Network-Discovery/1.0")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		resp.Body.Close()
		server = resp.Header.Get("Server")
		if m := reTitle.FindSubmatch(body); m != nil {
			title = strings.Join(strings.Fields(string(m[1])), " ")
			if len(title) > 120 {
				title = title[:120]
			}
		}
		if server != "" || title != "" {
			return
		}
	}
	return
}

// ---- NetBIOS node status (UDP 137)

func netbiosStatus(ctx context.Context, ip string, timeout time.Duration) (name, group string) {
	conn, err := net.DialTimeout("udp", net.JoinHostPort(ip, "137"), timeout)
	if err != nil {
		return
	}
	defer conn.Close()
	id := uint16(rand.IntN(65535))
	q := make([]byte, 0, 50)
	q = binary.BigEndian.AppendUint16(q, id)
	q = append(q, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0)
	q = append(q, 0x20)
	raw := make([]byte, 16) // "*" padded with NULs
	raw[0] = '*'
	for _, b := range raw {
		q = append(q, 'A'+(b>>4), 'A'+(b&0x0f))
	}
	q = append(q, 0, 0, 0x21, 0, 1)
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(q); err != nil {
		return
	}
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil || n < 57 {
		return
	}
	return parseNBStat(buf[:n])
}

func parseNBStat(b []byte) (name, group string) {
	// header(12) + name(34) + type(2) class(2) ttl(4) rdlen(2) = 56, then count
	if len(b) < 57 {
		return
	}
	count := int(b[56])
	off := 57
	for i := 0; i < count && off+18 <= len(b); i++ {
		n := strings.TrimRight(string(b[off:off+15]), " \x00")
		suffix := b[off+15]
		flags := binary.BigEndian.Uint16(b[off+16 : off+18])
		isGroup := flags&0x8000 != 0
		if suffix == 0x00 && !isGroup && name == "" {
			name = n
		}
		if suffix == 0x00 && isGroup && group == "" {
			group = n
		}
		off += 18
	}
	return
}
