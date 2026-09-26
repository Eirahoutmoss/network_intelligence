package snmp

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"
)

var (
	oidUnknownEngineIDs = ".1.3.6.1.6.3.15.1.1.4.0"
	oidUnknownUserNames = ".1.3.6.1.6.3.15.1.1.3.0"
	oidWrongDigests     = ".1.3.6.1.6.3.15.1.1.5.0"
	oidUnsupportedLevel = ".1.3.6.1.6.3.15.1.1.1.0"
)

func (a *Agent) initV3() {
	a.started = time.Now()
	id := make([]byte, 12)
	_, _ = rand.Read(id)
	// RFC 3411 format: enterprise (8072 net-snmp) with high bit + format 4 (octets)
	a.engineID = string(append([]byte{0x80, 0x00, 0x1f, 0x88, 0x04}, id[:8]...))
	a.keys = map[string][]byte{}
	for name, u := range a.V3Users {
		p, err := authProto(u.AuthProtocol)
		if u.AuthProtocol == "" || err != nil {
			continue
		}
		sp := &gosnmp.UsmSecurityParameters{AuthenticationProtocol: p, AuthenticationPassphrase: u.AuthPassword, AuthoritativeEngineID: a.engineID}
		if err := sp.InitSecurityKeys(); err == nil {
			a.keys[name] = sp.SecretKey
		}
	}
}

// isV3 peeks at the BER version field: SEQUENCE, len, INTEGER(1) = 3.
func isV3(b []byte) bool {
	if len(b) < 5 || b[0] != 0x30 {
		return false
	}
	i := 2
	if b[1]&0x80 != 0 {
		i = 2 + int(b[1]&0x7f)
	}
	return i+2 < len(b) && b[i] == 0x02 && b[i+1] == 0x01 && b[i+2] == 0x03
}

func (a *Agent) engineTime() uint32 { return uint32(time.Since(a.started).Seconds()) + 1000 }

func (a *Agent) handleV3(raw []byte, logger gosnmp.Logger) []byte {
	// Decode the header and security parameters. Authenticated requests only
	// parse when an auth protocol is configured, so try the plausible ones.
	var req *gosnmp.SnmpPacket
	var err error
	for _, proto := range []gosnmp.SnmpV3AuthProtocol{gosnmp.NoAuth, gosnmp.SHA, gosnmp.MD5, gosnmp.SHA256, gosnmp.SHA512, gosnmp.SHA224, gosnmp.SHA384} {
		flags := gosnmp.NoAuthNoPriv
		usm := &gosnmp.UsmSecurityParameters{UserName: "probe"}
		if proto != gosnmp.NoAuth {
			flags = gosnmp.AuthNoPriv
			usm.AuthenticationProtocol = proto
			usm.AuthenticationPassphrase = "probe-passphrase"
		}
		dec := &gosnmp.GoSNMP{Version: gosnmp.Version3, SecurityModel: gosnmp.UserSecurityModel, MsgFlags: flags,
			SecurityParameters: usm, Logger: logger}
		req, err = dec.SnmpDecodePacket(append([]byte(nil), raw...))
		if err == nil {
			break
		}
	}
	if err != nil {
		return nil
	}
	sp, ok := req.SecurityParameters.(*gosnmp.UsmSecurityParameters)
	if !ok {
		return nil
	}
	report := func(oid string, flags gosnmp.SnmpV3MsgFlags, user *V3User) []byte {
		rsp := &gosnmp.UsmSecurityParameters{
			UserName:                 sp.UserName,
			AuthoritativeEngineID:    a.engineID,
			AuthoritativeEngineBoots: 1,
			AuthoritativeEngineTime:  a.engineTime(),
			Logger:                   logger,
		}
		if user != nil && flags&gosnmp.AuthNoPriv != 0 {
			p, _ := authProto(user.AuthProtocol)
			rsp.AuthenticationProtocol = p
			rsp.AuthenticationPassphrase = user.AuthPassword
			rsp.SecretKey = a.keys[sp.UserName]
		}
		pkt := &gosnmp.SnmpPacket{Version: gosnmp.Version3, MsgFlags: flags, SecurityModel: gosnmp.UserSecurityModel,
			SecurityParameters: rsp, ContextEngineID: a.engineID, MsgID: req.MsgID, RequestID: req.RequestID,
			MsgMaxSize: 65507, PDUType: gosnmp.Report, Logger: logger,
			Variables: []gosnmp.SnmpPDU{{Name: oid, Type: gosnmp.Counter32, Value: uint32(1)}}}
		out, err := pkt.MarshalMsg()
		if err != nil {
			return nil
		}
		return out
	}
	if sp.AuthoritativeEngineID != a.engineID {
		return report(oidUnknownEngineIDs, gosnmp.NoAuthNoPriv, nil)
	}
	user, ok := a.V3Users[sp.UserName]
	if !ok {
		return report(oidUnknownUserNames, gosnmp.NoAuthNoPriv, nil)
	}
	reqAuth := req.MsgFlags&gosnmp.AuthNoPriv != 0
	if req.MsgFlags&gosnmp.AuthPriv == gosnmp.AuthPriv {
		return report(oidUnsupportedLevel, gosnmp.NoAuthNoPriv, nil) // privacy not simulated
	}
	if user.AuthProtocol != "" && !reqAuth {
		return report(oidUnsupportedLevel, gosnmp.NoAuthNoPriv, nil)
	}
	if reqAuth {
		if !a.verifyDigest(raw, sp, user) {
			return report(oidWrongDigests, gosnmp.NoAuthNoPriv, nil)
		}
	}
	resp := a.handle(req)
	if resp == nil {
		return nil
	}
	flags := gosnmp.NoAuthNoPriv
	rsp := &gosnmp.UsmSecurityParameters{UserName: sp.UserName, AuthoritativeEngineID: a.engineID,
		AuthoritativeEngineBoots: 1, AuthoritativeEngineTime: a.engineTime(), Logger: logger}
	if reqAuth {
		flags = gosnmp.AuthNoPriv
		p, _ := authProto(user.AuthProtocol)
		rsp.AuthenticationProtocol = p
		rsp.AuthenticationPassphrase = user.AuthPassword
		rsp.SecretKey = a.keys[sp.UserName]
	}
	resp.Version = gosnmp.Version3
	resp.MsgFlags = flags
	resp.SecurityModel = gosnmp.UserSecurityModel
	resp.SecurityParameters = rsp
	resp.ContextEngineID = a.engineID
	resp.ContextName = req.ContextName
	resp.MsgID = req.MsgID
	resp.MsgMaxSize = 65507
	resp.Logger = logger
	out, err := resp.MarshalMsg()
	if err != nil {
		if a.Log != nil {
			a.Log.Warn("simulator v3 marshal", "err", err)
		}
		return nil
	}
	return out
}

func (a *Agent) verifyDigest(raw []byte, sp *gosnmp.UsmSecurityParameters, u V3User) bool {
	key := a.keys[sp.UserName]
	sig := []byte(sp.AuthenticationParameters)
	if len(key) == 0 || len(sig) == 0 {
		return false
	}
	i := bytes.Index(raw, sig)
	if i < 0 {
		return false
	}
	msg := append([]byte(nil), raw...)
	for j := range sig {
		msg[i+j] = 0
	}
	var h func() hash.Hash
	switch strings.ToUpper(u.AuthProtocol) {
	case "MD5":
		h = md5.New
	case "SHA", "SHA1":
		h = sha1.New
	case "SHA224":
		h = sha256.New224
	case "SHA256":
		h = sha256.New
	case "SHA384":
		h = sha512.New384
	case "SHA512":
		h = sha512.New
	default:
		return false
	}
	mac := hmac.New(h, key)
	mac.Write(msg)
	sum := mac.Sum(nil)
	if len(sig) > len(sum) {
		return false // signature produced with a different hash
	}
	return hmac.Equal(sum[:len(sig)], sig)
}
