// Package all wires every vendor adapter into a registry.
package all

import (
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/vendors"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/vendors/arista"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/vendors/cisco"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/vendors/hpe"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/vendors/huawei"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/vendors/juniper"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/vendors/mikrotik"
)

// Registry returns the default adapter registry.
func Registry() *vendors.Registry {
	return vendors.NewRegistry(huawei.Adapter{}, cisco.Adapter{}, juniper.Adapter{}, arista.Adapter{}, mikrotik.Adapter{}, hpe.Adapter{})
}
