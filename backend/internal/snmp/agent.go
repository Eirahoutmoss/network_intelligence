package snmp

import (
	"context"
	"errors"
	"io"
	"log"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"
)

// Agent is a minimal SNMP v1/v2c agent serving a MIB over UDP. It exists for
// fixtures, demos and end-to-end tests — it is not a production agent.
type Agent struct {
	MIB       *MIB
	Community string
	// V3Users enables SNMPv3 (noAuthNoPriv / authNoPriv). Privacy is not simulated.
	V3Users map[string]V3User
	Log     *slog.Logger
	conn    net.PacketConn

	engineID string
	started  time.Time
	keys     map[string][]byte
}

// V3User is a simulated USM user.
type V3User struct {
	AuthProtocol string // "" (noAuth) | MD5 | SHA | SHA256 ...
	AuthPassword string
}

// Listen binds addr (e.g. "127.0.1.1:16100").
func (a *Agent) Listen(addr string) error {
	c, err := net.ListenPacket("udp", addr)
	if err != nil {
		return err
	}
	a.conn = c
	return nil
}

// Addr returns the bound address.
func (a *Agent) Addr() net.Addr { return a.conn.LocalAddr() }

// Serve processes requests until ctx is cancelled.
func (a *Agent) Serve(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		a.conn.Close()
	}()
	logger := gosnmp.NewLogger(log.New(io.Discard, "", 0))
	dec := &gosnmp.GoSNMP{Version: gosnmp.Version2c, Logger: logger}
	a.initV3()
	buf := make([]byte, 65535)
	for {
		n, from, err := a.conn.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		raw := append([]byte(nil), buf[:n]...)
		if isV3(raw) {
			if out := a.handleV3(raw, logger); out != nil {
				_, _ = a.conn.WriteTo(out, from)
			}
			continue
		}
		pkt, err := dec.SnmpDecodePacket(raw)
		if err != nil || pkt.Version == gosnmp.Version3 {
			continue
		}
		if a.Community != "" && pkt.Community != a.Community {
			continue // like real agents: silently drop wrong community
		}
		resp := a.handle(pkt)
		if resp == nil {
			continue
		}
		out, err := resp.MarshalMsg()
		if err != nil {
			if a.Log != nil {
				a.Log.Warn("simulator marshal", "err", err)
			}
			continue
		}
		_, _ = a.conn.WriteTo(out, from)
	}
}

func (a *Agent) toWire(p PDU, name string) gosnmp.SnmpPDU {
	w := gosnmp.SnmpPDU{Name: "." + name}
	switch p.Kind {
	case KindInteger:
		w.Type, w.Value = gosnmp.Integer, int(p.Value.(int64))
	case KindOctetString:
		w.Type, w.Value = gosnmp.OctetString, p.Bytes()
	case KindOID:
		w.Type, w.Value = gosnmp.ObjectIdentifier, "."+p.Value.(string)
	case KindIPAddress:
		w.Type, w.Value = gosnmp.IPAddress, p.Value.(string)
	case KindCounter32:
		w.Type, w.Value = gosnmp.Counter32, uint32(p.Value.(uint64))
	case KindGauge32:
		w.Type, w.Value = gosnmp.Gauge32, uint32(p.Value.(uint64))
	case KindTimeTicks:
		w.Type, w.Value = gosnmp.TimeTicks, uint32(p.Value.(uint64))
	case KindCounter64:
		w.Type, w.Value = gosnmp.Counter64, p.Value.(uint64)
	case KindNoSuchInstance:
		w.Type = gosnmp.NoSuchInstance
	case KindEndOfMib:
		w.Type = gosnmp.EndOfMibView
	default:
		w.Type = gosnmp.NoSuchObject
	}
	return w
}

func (a *Agent) handle(req *gosnmp.SnmpPacket) *gosnmp.SnmpPacket {
	resp := &gosnmp.SnmpPacket{
		Version:   req.Version,
		Community: req.Community,
		PDUType:   gosnmp.GetResponse,
		RequestID: req.RequestID,
		Error:     gosnmp.NoError,
	}
	names := make([]string, len(req.Variables))
	for i, v := range req.Variables {
		names[i] = strings.TrimPrefix(v.Name, ".")
	}
	endOfMib := func(name string) gosnmp.SnmpPDU {
		return gosnmp.SnmpPDU{Name: "." + name, Type: gosnmp.EndOfMibView}
	}
	switch req.PDUType {
	case gosnmp.GetRequest:
		for _, n := range names {
			if p, ok := a.MIB.Lookup(n); ok {
				resp.Variables = append(resp.Variables, a.toWire(p, n))
			} else {
				resp.Variables = append(resp.Variables, gosnmp.SnmpPDU{Name: "." + n, Type: gosnmp.NoSuchObject})
			}
		}
	case gosnmp.GetNextRequest:
		for _, n := range names {
			if p, ok := a.MIB.Next(n); ok {
				resp.Variables = append(resp.Variables, a.toWire(p, p.OID))
			} else {
				resp.Variables = append(resp.Variables, endOfMib(n))
			}
		}
	case gosnmp.GetBulkRequest:
		nr := int(req.NonRepeaters)
		if nr > len(names) {
			nr = len(names)
		}
		for _, n := range names[:nr] {
			if p, ok := a.MIB.Next(n); ok {
				resp.Variables = append(resp.Variables, a.toWire(p, p.OID))
			} else {
				resp.Variables = append(resp.Variables, endOfMib(n))
			}
		}
		reps := int(req.MaxRepetitions)
		if reps <= 0 {
			reps = 1
		}
		if reps > 50 {
			reps = 50
		}
		cursors := append([]string(nil), names[nr:]...)
		for r := 0; r < reps && len(cursors) > 0; r++ {
			allEnd := true
			for i, c := range cursors {
				if p, ok := a.MIB.Next(c); ok {
					resp.Variables = append(resp.Variables, a.toWire(p, p.OID))
					cursors[i] = p.OID
					allEnd = false
				} else {
					resp.Variables = append(resp.Variables, endOfMib(c))
				}
			}
			if allEnd {
				break
			}
		}
	default:
		return nil
	}
	return resp
}
