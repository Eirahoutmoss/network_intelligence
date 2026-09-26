package lab

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"

	"golang.org/x/crypto/ssh"
)

// Simulated console credentials for demo mode.
const (
	SSHUser = "netadmin"
	SSHPass = "nexus-demo-pass"
)

// StartSSH launches a tiny simulated SSH console for every managed device and
// returns mgmtIP:22 → listen address. It supports a handful of read-only
// "display"/"show" commands built from lab data.
func (l *Lab) StartSSH(ctx context.Context, host string) (map[string]string, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, d := range l.Devices {
		if !d.Managed {
			continue
		}
		cfg := &ssh.ServerConfig{PasswordCallback: func(c ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
			if c.User() == SSHUser && string(pw) == SSHPass {
				return nil, nil
			}
			return nil, fmt.Errorf("access denied")
		}}
		cfg.AddHostKey(signer)
		ln, err := net.Listen("tcp", host+":0")
		if err != nil {
			return nil, err
		}
		out[net.JoinHostPort(d.MgmtIP, "22")] = ln.Addr().String()
		dev := d
		go func() {
			<-ctx.Done()
			ln.Close()
		}()
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				go l.serveSSH(c, cfg, dev)
			}
		}()
	}
	return out, nil
}

func (l *Lab) serveSSH(c net.Conn, cfg *ssh.ServerConfig, d *Device) {
	defer c.Close()
	_, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		if nc.ChannelType() != "session" {
			nc.Reject(ssh.UnknownChannelType, "unsupported")
			continue
		}
		ch, in, err := nc.Accept()
		if err != nil {
			return
		}
		go func() {
			for r := range in {
				switch r.Type {
				case "pty-req", "shell", "window-change":
					r.Reply(true, nil)
				default:
					r.Reply(false, nil)
				}
			}
		}()
		l.shell(ch, d)
		ch.Close()
	}
}

func (l *Lab) prompt(d *Device) string {
	switch d.Family {
	case "huawei":
		return "<" + d.Name + ">"
	case "hpe":
		return d.Name + "# "
	}
	return d.Name + "#"
}

func (l *Lab) shell(ch io.ReadWriter, d *Device) {
	w := func(s string) { _, _ = io.WriteString(ch, strings.ReplaceAll(s, "\n", "\r\n")) }
	w(fmt.Sprintf("\nInfo: Nexus lab simulator — %s (%s). Read-only demo console.\nType ? for available commands.\n\n", d.Name, d.Model))
	w(l.prompt(d))
	var line []byte
	buf := make([]byte, 256)
	for {
		n, err := ch.Read(buf)
		if err != nil {
			return
		}
		for _, b := range buf[:n] {
			switch b {
			case '\r', '\n':
				w("\n")
				cmd := strings.TrimSpace(string(line))
				line = line[:0]
				if cmd == "quit" || cmd == "exit" || cmd == "logout" {
					w("Bye.\n")
					return
				}
				if cmd != "" {
					w(l.run(d, cmd))
				}
				w(l.prompt(d))
			case 127, 8:
				if len(line) > 0 {
					line = line[:len(line)-1]
					w("\b \b")
				}
			case 3:
				line = line[:0]
				w("^C\n" + l.prompt(d))
			default:
				if b >= 32 && b < 127 {
					line = append(line, b)
					_, _ = ch.Write([]byte{b})
				}
			}
		}
	}
}

func (l *Lab) run(d *Device, cmd string) string {
	c := strings.ToLower(strings.Join(strings.Fields(cmd), " "))
	has := func(prefixes ...string) bool {
		for _, p := range prefixes {
			if strings.HasPrefix(c, p) {
				return true
			}
		}
		return false
	}
	switch {
	case c == "?" || c == "help":
		return "  display version | show version\n  display interface brief | show interfaces status\n  display lldp neighbor brief | show lldp neighbors\n  display mac-address | show mac address-table\n  quit\n"
	case has("dis ver", "display ver", "sh ver", "show ver"):
		return d.Descr + "\n" + fmt.Sprintf("Serial: %s\nUptime: 99 days, 17 hours\n", d.Serial)
	case has("dis int b", "display interface b", "sh int st", "show interfaces status", "show ip int b", "show interface b"):
		var b strings.Builder
		fmt.Fprintf(&b, "%-28s %-6s %-8s %s\n", "Interface", "Status", "Speed", "Description")
		for _, p := range d.Ports {
			st := "down"
			if p.Up {
				st = "up"
			}
			fmt.Fprintf(&b, "%-28s %-6s %-8s %s\n", p.Name, st, fmt.Sprintf("%dM", p.Speed/1_000_000), p.Alias)
		}
		return b.String()
	case has("dis lldp", "display lldp", "sh lldp", "show lldp"):
		var b strings.Builder
		fmt.Fprintf(&b, "%-26s %-22s %-26s\n", "Local Intf", "Neighbor", "Neighbor Intf")
		for _, p := range d.Ports {
			if pd, pp := l.peer(d.Name, p.Name); pd != nil {
				fmt.Fprintf(&b, "%-26s %-22s %-26s\n", p.Name, pd.Name, pp.Short)
			}
		}
		for _, e := range l.Endpoints {
			if e.Switch == d.Name && len(e.LLDPCaps) > 0 {
				fmt.Fprintf(&b, "%-26s %-22s %-26s\n", e.Port, e.Name, "eth0")
			}
		}
		return b.String()
	case has("dis mac", "display mac", "sh mac", "show mac"):
		rows := l.fdbFor(d)
		sort.Slice(rows, func(i, j int) bool { return rows[i].port.IfIndex < rows[j].port.IfIndex })
		var b strings.Builder
		fmt.Fprintf(&b, "%-18s %-6s %-26s\n", "MAC Address", "VLAN", "Port")
		for _, r := range rows {
			fmt.Fprintf(&b, "%-18s %-6d %-26s\n", r.mac, r.vlan, r.port.Name)
		}
		return b.String()
	}
	if d.Family == "huawei" {
		return "              ^\nError: Unrecognized command found at '^' position.\n"
	}
	return "% Invalid input detected at '^' marker.\n"
}
