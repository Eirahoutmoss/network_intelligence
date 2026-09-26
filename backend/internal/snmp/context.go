package snmp

import (
	"strings"

	"github.com/Eirahoutmoss/network_intelligence/backend/internal/credentials"
)

// WithContext returns a credential addressing an SNMP context: v3 contextName,
// or the Cisco-style community@<n> convention for v1/v2c ("vlan-10" → "@10").
func WithContext(c credentials.SNMP, name string) credentials.SNMP {
	if c.Version == "3" {
		c.ContextName = name
		return c
	}
	c.Community = c.Community + "@" + strings.TrimPrefix(name, "vlan-")
	return c
}
