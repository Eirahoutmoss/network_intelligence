package fingerprint

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
	"unicode/utf16"
)

// SMBInfo is what an unauthenticated SMB handshake reveals. No credentials
// are sent: the session setup stops after the server's NTLM challenge.
type SMBInfo struct {
	Dialect     string // "NT LM 0.12", "SMB 2.1", "SMB 3.0.2" …
	NativeOS    string // SMB1 native OS string, or "Windows 10.0 Build 19045" from NTLM
	LanMan      string // SMB1 native LAN manager (e.g. "Samba 4.15")
	NetBIOSName string
	Domain      string
	DNSName     string
}

// SMBProbe performs negotiate + anonymous NTLM session setup (first leg only).
func SMBProbe(ctx context.Context, addr string, timeout time.Duration) SMBInfo {
	var info SMBInfo
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return info
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * timeout))
	// SMB1 negotiate offering SMB1 and SMB2 so both kinds of servers answer.
	if err := writeNB(conn, smb1Negotiate()); err != nil {
		return info
	}
	resp, err := readNB(conn)
	if err != nil || len(resp) < 4 {
		return info
	}
	switch {
	case bytes.HasPrefix(resp, []byte("\xffSMB")):
		info.Dialect = "NT LM 0.12"
		smb1Session(conn, resp, &info)
	case bytes.HasPrefix(resp, []byte("\xfeSMB")):
		smb2Session(conn, &info)
	}
	return info
}

func writeNB(w io.Writer, msg []byte) error {
	hdr := []byte{0, byte(len(msg) >> 16), byte(len(msg) >> 8), byte(len(msg))}
	_, err := w.Write(append(hdr, msg...))
	return err
}

func readNB(r io.Reader) ([]byte, error) {
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, err
	}
	n := int(hdr[1])<<16 | int(hdr[2])<<8 | int(hdr[3])
	if n > 1<<20 {
		return nil, fmt.Errorf("smb message too large")
	}
	b := make([]byte, n)
	_, err := io.ReadFull(r, b)
	return b, err
}

func smb1Header(cmd byte, flags2 uint16) []byte {
	h := make([]byte, 32)
	copy(h, "\xffSMB")
	h[4] = cmd
	h[9] = 0x18
	binary.LittleEndian.PutUint16(h[10:], flags2)
	binary.LittleEndian.PutUint16(h[26:], 0xfeff) // PID
	binary.LittleEndian.PutUint16(h[30:], 1)      // MID
	return h
}

func smb1Negotiate() []byte {
	var dialects []byte
	for _, d := range []string{"NT LM 0.12", "SMB 2.002", "SMB 2.???"} {
		dialects = append(dialects, 0x02)
		dialects = append(dialects, d...)
		dialects = append(dialects, 0)
	}
	msg := smb1Header(0x72, 0xc853)
	msg = append(msg, 0) // word count
	msg = binary.LittleEndian.AppendUint16(msg, uint16(len(dialects)))
	return append(msg, dialects...)
}

// ntlmNegotiate builds an NTLMSSP NEGOTIATE message requesting version info.
func ntlmNegotiate() []byte {
	m := []byte("NTLMSSP\x00")
	m = binary.LittleEndian.AppendUint32(m, 1)
	m = binary.LittleEndian.AppendUint32(m, 0xe2088297)
	m = append(m, make([]byte, 16)...)           // domain + workstation fields
	m = append(m, 6, 1, 0xb1, 0x1d, 0, 0, 0, 15) // version 6.1.7601, NTLM rev 15
	return m
}

func derLen(n int) []byte {
	switch {
	case n < 0x80:
		return []byte{byte(n)}
	case n < 0x100:
		return []byte{0x81, byte(n)}
	}
	return []byte{0x82, byte(n >> 8), byte(n)}
}

func der(tag byte, content ...[]byte) []byte {
	body := bytes.Join(content, nil)
	return append(append([]byte{tag}, derLen(len(body))...), body...)
}

// spnegoInit wraps an NTLMSSP token in a GSS-API SPNEGO NegTokenInit.
func spnegoInit(token []byte) []byte {
	spnegoOID := []byte{0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02}
	ntlmOID := []byte{0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a}
	negInit := der(0x30, der(0xa0, der(0x30, ntlmOID)), der(0xa2, der(0x04, token)))
	return der(0x60, spnegoOID, der(0xa0, negInit))
}

func smb1Session(conn net.Conn, negResp []byte, info *SMBInfo) {
	blob := spnegoInit(ntlmNegotiate())
	msg := smb1Header(0x73, 0xc807)
	words := []byte{12, 0xff, 0, 0, 0}
	words = binary.LittleEndian.AppendUint16(words, 0xffff) // max buffer
	words = binary.LittleEndian.AppendUint16(words, 2)      // max mpx
	words = binary.LittleEndian.AppendUint16(words, 1)      // vc
	words = binary.LittleEndian.AppendUint32(words, 0)      // session key
	words = binary.LittleEndian.AppendUint16(words, uint16(len(blob)))
	words = binary.LittleEndian.AppendUint32(words, 0)          // reserved
	words = binary.LittleEndian.AppendUint32(words, 0x800000d4) // capabilities: ext security, NT status, unicode…
	msg = append(msg, words...)
	data := append([]byte(nil), blob...)
	if (len(msg)+2+len(data))%2 == 1 {
		data = append(data, 0)
	}
	data = append(data, 0, 0, 0, 0) // empty native OS / LanMan (unicode)
	msg = binary.LittleEndian.AppendUint16(msg, uint16(len(data)))
	msg = append(msg, data...)
	if writeNB(conn, msg) != nil {
		return
	}
	resp, err := readNB(conn)
	if err != nil || len(resp) < 37 || !bytes.HasPrefix(resp, []byte("\xffSMB")) {
		return
	}
	wc := int(resp[32])
	off := 33 + wc*2
	if wc < 4 || off+2 > len(resp) {
		return
	}
	blobLen := int(binary.LittleEndian.Uint16(resp[33+6:]))
	bc := int(binary.LittleEndian.Uint16(resp[off:]))
	start := off + 2
	if start+bc > len(resp) || blobLen > bc {
		return
	}
	parseNTLMChallenge(resp[start:start+blobLen], info, false)
	strs := resp[start+blobLen : start+bc]
	if (start+blobLen)%2 == 1 && len(strs) > 0 {
		strs = strs[1:]
	}
	parts := splitUTF16(strs)
	if len(parts) > 0 && parts[0] != "" {
		info.NativeOS = parts[0]
	}
	if len(parts) > 1 {
		info.LanMan = parts[1]
	}
}

func splitUTF16(b []byte) []string {
	var out []string
	var cur []uint16
	for i := 0; i+1 < len(b); i += 2 {
		c := binary.LittleEndian.Uint16(b[i:])
		if c == 0 {
			out = append(out, string(utf16.Decode(cur)))
			cur = nil
			continue
		}
		cur = append(cur, c)
	}
	if len(cur) > 0 {
		out = append(out, string(utf16.Decode(cur)))
	}
	return out
}

func utf16String(b []byte) string {
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	return string(utf16.Decode(u))
}

// parseNTLMChallenge extracts OS version and names from an NTLM CHALLENGE.
func parseNTLMChallenge(blob []byte, info *SMBInfo, setOS bool) {
	i := bytes.Index(blob, []byte("NTLMSSP\x00"))
	if i < 0 || len(blob)-i < 48 {
		return
	}
	m := blob[i:]
	if binary.LittleEndian.Uint32(m[8:]) != 2 {
		return
	}
	flags := binary.LittleEndian.Uint32(m[20:])
	if tiLen, tiOff := int(binary.LittleEndian.Uint16(m[40:])), int(binary.LittleEndian.Uint32(m[44:])); tiOff+tiLen <= len(m) {
		ti := m[tiOff : tiOff+tiLen]
		for p := 0; p+4 <= len(ti); {
			id := binary.LittleEndian.Uint16(ti[p:])
			l := int(binary.LittleEndian.Uint16(ti[p+2:]))
			if id == 0 || p+4+l > len(ti) {
				break
			}
			v := utf16String(ti[p+4 : p+4+l])
			switch id {
			case 1:
				info.NetBIOSName = v
			case 2:
				info.Domain = v
			case 3:
				info.DNSName = v
			}
			p += 4 + l
		}
	}
	if flags&0x02000000 != 0 && len(m) >= 56 && setOS {
		major, minor := m[48], m[49]
		build := binary.LittleEndian.Uint16(m[50:])
		switch {
		case major > 0 && build == 0:
			// Real Windows always reports a build number; Samba reports 6.1 build 0.
			info.LanMan = "Samba (NTLM version without build number)"
		case major > 0:
			info.NativeOS = fmt.Sprintf("Windows %d.%d Build %d", major, minor, build)
		}
	}
}

func smb2Header(cmd uint16, msgID uint64) []byte {
	h := make([]byte, 64)
	copy(h, "\xfeSMB")
	binary.LittleEndian.PutUint16(h[4:], 64)
	binary.LittleEndian.PutUint16(h[12:], cmd)
	binary.LittleEndian.PutUint16(h[14:], 1) // credits
	binary.LittleEndian.PutUint64(h[24:], msgID)
	return h
}

var smb2Dialects = map[uint16]string{0x0202: "SMB 2.0.2", 0x0210: "SMB 2.1", 0x0300: "SMB 3.0", 0x0302: "SMB 3.0.2", 0x0311: "SMB 3.1.1"}

func smb2Session(conn net.Conn, info *SMBInfo) {
	dialects := []uint16{0x0202, 0x0210, 0x0300, 0x0302}
	body := binary.LittleEndian.AppendUint16(nil, 36)
	body = binary.LittleEndian.AppendUint16(body, uint16(len(dialects)))
	body = binary.LittleEndian.AppendUint16(body, 1) // signing enabled
	body = append(body, 0, 0, 0, 0, 0, 0)            // reserved + capabilities
	guid := make([]byte, 16)
	_, _ = rand.Read(guid)
	body = append(body, guid...)
	body = append(body, make([]byte, 8)...)
	for _, d := range dialects {
		body = binary.LittleEndian.AppendUint16(body, d)
	}
	if writeNB(conn, append(smb2Header(0, 1), body...)) != nil {
		return
	}
	resp, err := readNB(conn)
	if err != nil || len(resp) < 64+6 || !bytes.HasPrefix(resp, []byte("\xfeSMB")) {
		return
	}
	info.Dialect = smb2Dialects[binary.LittleEndian.Uint16(resp[64+4:])]
	blob := spnegoInit(ntlmNegotiate())
	ss := binary.LittleEndian.AppendUint16(nil, 25)
	ss = append(ss, 0, 1)                            // flags, security mode
	ss = append(ss, 0, 0, 0, 0, 0, 0, 0, 0)          // capabilities, channel
	ss = binary.LittleEndian.AppendUint16(ss, 64+24) // buffer offset
	ss = binary.LittleEndian.AppendUint16(ss, uint16(len(blob)))
	ss = append(ss, make([]byte, 8)...) // previous session
	ss = append(ss, blob...)
	if writeNB(conn, append(smb2Header(1, 2), ss...)) != nil {
		return
	}
	resp, err = readNB(conn)
	if err != nil || len(resp) < 64+8 {
		return
	}
	off := int(binary.LittleEndian.Uint16(resp[64+4:]))
	l := int(binary.LittleEndian.Uint16(resp[64+6:]))
	if off+l <= len(resp) && l > 0 {
		parseNTLMChallenge(resp[off:off+l], info, true)
	}
}
