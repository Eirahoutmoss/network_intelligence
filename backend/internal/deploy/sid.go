package deploy

import (
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"strings"
	"unicode/utf16"
)

// VirtualServiceSID computes the SID of the virtual account NT SERVICE\<name>:
// S-1-5-80 followed by the SHA-1 of the upper-case service name (UTF-16LE)
// as five little-endian sub-authorities. This is the documented scheme
// behind "sc showsid"; computing it avoids depending on account lookups.
func VirtualServiceSID(name string) string {
	u := utf16.Encode([]rune(strings.ToUpper(name)))
	b := make([]byte, 2*len(u))
	for i, c := range u {
		binary.LittleEndian.PutUint16(b[2*i:], c)
	}
	h := sha1.Sum(b)
	var parts [5]uint32
	for i := range parts {
		parts[i] = binary.LittleEndian.Uint32(h[4*i:])
	}
	return fmt.Sprintf("S-1-5-80-%d-%d-%d-%d-%d", parts[0], parts[1], parts[2], parts[3], parts[4])
}
