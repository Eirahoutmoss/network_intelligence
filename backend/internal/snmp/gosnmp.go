package snmp

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/Eirahoutmoss/network_intelligence/backend/internal/credentials"
)

// Options controls transport behaviour.
type Options struct {
	Timeout        time.Duration
	Retries        int
	MaxRepetitions uint32
}

// Dial creates a gosnmp-backed client. It does not send any packet yet.
func Dial(ctx context.Context, host string, cred credentials.SNMP, opt Options) (Client, error) {
	if err := cred.Normalize(); err != nil {
		return nil, err
	}
	if opt.Timeout == 0 {
		opt.Timeout = 3 * time.Second
	}
	if opt.MaxRepetitions == 0 {
		opt.MaxRepetitions = 25
	}
	g := &gosnmp.GoSNMP{
		Target:             host,
		Port:               uint16(cred.Port),
		Transport:          "udp",
		Timeout:            opt.Timeout,
		Retries:            opt.Retries,
		MaxOids:            gosnmp.MaxOids,
		MaxRepetitions:     opt.MaxRepetitions,
		Context:            ctx,
		ExponentialTimeout: false,
	}
	switch cred.Version {
	case "1":
		g.Version = gosnmp.Version1
		g.Community = cred.Community
	case "2c":
		g.Version = gosnmp.Version2c
		g.Community = cred.Community
	case "3":
		g.Version = gosnmp.Version3
		g.SecurityModel = gosnmp.UserSecurityModel
		g.ContextName = cred.ContextName
		usm := &gosnmp.UsmSecurityParameters{UserName: cred.Username}
		switch cred.SecurityLevel {
		case "noAuthNoPriv":
			g.MsgFlags = gosnmp.NoAuthNoPriv
		case "authNoPriv":
			g.MsgFlags = gosnmp.AuthNoPriv
		case "authPriv":
			g.MsgFlags = gosnmp.AuthPriv
		default:
			return nil, fmt.Errorf("unknown security level %q", cred.SecurityLevel)
		}
		if g.MsgFlags != gosnmp.NoAuthNoPriv {
			ap, err := authProto(cred.AuthProtocol)
			if err != nil {
				return nil, err
			}
			usm.AuthenticationProtocol = ap
			usm.AuthenticationPassphrase = cred.AuthPassword
		}
		if g.MsgFlags == gosnmp.AuthPriv {
			pp, err := privProto(cred.PrivProtocol)
			if err != nil {
				return nil, err
			}
			usm.PrivacyProtocol = pp
			usm.PrivacyPassphrase = cred.PrivPassword
		}
		g.SecurityParameters = usm
	}
	if err := g.Connect(); err != nil {
		return nil, fmt.Errorf("snmp connect %s: %w", host, err)
	}
	return &goClient{g: g, bulk: g.Version != gosnmp.Version1}, nil
}

func authProto(s string) (gosnmp.SnmpV3AuthProtocol, error) {
	switch strings.ToUpper(strings.ReplaceAll(s, "-", "")) {
	case "MD5":
		return gosnmp.MD5, nil
	case "SHA", "SHA1":
		return gosnmp.SHA, nil
	case "SHA224":
		return gosnmp.SHA224, nil
	case "SHA256":
		return gosnmp.SHA256, nil
	case "SHA384":
		return gosnmp.SHA384, nil
	case "SHA512":
		return gosnmp.SHA512, nil
	}
	return 0, fmt.Errorf("unsupported auth protocol %q", s)
}

func privProto(s string) (gosnmp.SnmpV3PrivProtocol, error) {
	switch strings.ToUpper(strings.ReplaceAll(s, "-", "")) {
	case "DES":
		return gosnmp.DES, nil
	case "AES", "AES128":
		return gosnmp.AES, nil
	case "AES192":
		return gosnmp.AES192, nil
	case "AES256":
		return gosnmp.AES256, nil
	case "AES192C":
		return gosnmp.AES192C, nil
	case "AES256C":
		return gosnmp.AES256C, nil
	}
	return 0, fmt.Errorf("unsupported privacy protocol %q", s)
}

type goClient struct {
	mu   sync.Mutex // gosnmp.GoSNMP is not safe for concurrent use
	g    *gosnmp.GoSNMP
	bulk bool
}

func (c *goClient) Close() error {
	if c.g.Conn != nil {
		return c.g.Conn.Close()
	}
	return nil
}

// ClassifyError maps gosnmp errors to ErrTimeout/ErrAuth where possible.
func ClassifyError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrAuth) || errors.Is(err, ErrTimeout) {
		return err
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "timeout"), strings.Contains(msg, "connection refused"):
		return fmt.Errorf("%w: %v", ErrTimeout, err)
	case strings.Contains(msg, "unknown user"), strings.Contains(msg, "wrong digest"),
		strings.Contains(msg, "authentication"), strings.Contains(msg, "decryption"),
		strings.Contains(msg, "usmstats"), strings.Contains(msg, "unknown security"),
		strings.Contains(msg, "not authentic"), strings.Contains(msg, "unknown engine"):
		return fmt.Errorf("%w: %v", ErrAuth, err)
	}
	return err
}

func convert(v gosnmp.SnmpPDU) PDU {
	p := PDU{OID: strings.TrimPrefix(v.Name, ".")}
	switch v.Type {
	case gosnmp.Integer:
		p.Kind = KindInteger
		p.Value = gosnmp.ToBigInt(v.Value).Int64()
	case gosnmp.OctetString, gosnmp.Opaque, gosnmp.BitString:
		p.Kind = KindOctetString
		if b, ok := v.Value.([]byte); ok {
			p.Value = b
		} else {
			p.Value = []byte(fmt.Sprint(v.Value))
		}
	case gosnmp.ObjectIdentifier:
		p.Kind = KindOID
		p.Value = strings.TrimPrefix(fmt.Sprint(v.Value), ".")
	case gosnmp.IPAddress:
		p.Kind = KindIPAddress
		p.Value = fmt.Sprint(v.Value)
	case gosnmp.Counter32:
		p.Kind = KindCounter32
		p.Value = gosnmp.ToBigInt(v.Value).Uint64()
	case gosnmp.Gauge32, gosnmp.Uinteger32:
		p.Kind = KindGauge32
		p.Value = gosnmp.ToBigInt(v.Value).Uint64()
	case gosnmp.TimeTicks:
		p.Kind = KindTimeTicks
		p.Value = gosnmp.ToBigInt(v.Value).Uint64()
	case gosnmp.Counter64:
		p.Kind = KindCounter64
		p.Value = gosnmp.ToBigInt(v.Value).Uint64()
	case gosnmp.NoSuchObject:
		p.Kind = KindNoSuchObject
	case gosnmp.NoSuchInstance:
		p.Kind = KindNoSuchInstance
	case gosnmp.EndOfMibView:
		p.Kind = KindEndOfMib
	default:
		p.Kind = KindNull
	}
	return p
}

func (c *goClient) Get(ctx context.Context, oids ...string) ([]PDU, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.g.Context = ctx
	out := make([]PDU, 0, len(oids))
	const chunk = 20
	for i := 0; i < len(oids); i += chunk {
		end := min(i+chunk, len(oids))
		pkt, err := c.g.Get(oids[i:end])
		if err != nil {
			return nil, ClassifyError(err)
		}
		if pkt.Error == gosnmp.AuthorizationError {
			return nil, fmt.Errorf("%w: access denied (authorizationError) — the user may need a higher security level or read access to this view", ErrAuth)
		}
		if pkt.Error != gosnmp.NoError && pkt.Error != gosnmp.NoSuchName {
			return nil, fmt.Errorf("snmp get error: %s", pkt.Error)
		}
		for _, v := range pkt.Variables {
			out = append(out, convert(v))
		}
	}
	return out, nil
}

func (c *goClient) Walk(ctx context.Context, root string) ([]PDU, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.g.Context = ctx
	var res []gosnmp.SnmpPDU
	var err error
	if c.bulk {
		res, err = c.g.BulkWalkAll(root)
	} else {
		res, err = c.g.WalkAll(root)
	}
	if err != nil {
		return nil, ClassifyError(err)
	}
	out := make([]PDU, 0, len(res))
	for _, v := range res {
		p := convert(v)
		if p.Exists() {
			out = append(out, p)
		}
	}
	return out, nil
}
