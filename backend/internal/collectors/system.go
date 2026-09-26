package collectors

import (
	"context"
	"strings"

	"github.com/Eirahoutmoss/network_intelligence/backend/internal/model"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/snmp"
)

// Standard OIDs used by the system collector.
const (
	oidSysDescr              = "1.3.6.1.2.1.1.1.0"
	oidSysObjectID           = "1.3.6.1.2.1.1.2.0"
	oidSysUpTime             = "1.3.6.1.2.1.1.3.0"
	oidSysContact            = "1.3.6.1.2.1.1.4.0"
	oidSysName               = "1.3.6.1.2.1.1.5.0"
	oidSysLocation           = "1.3.6.1.2.1.1.6.0"
	oidSysServices           = "1.3.6.1.2.1.1.7.0"
	oidIPForwarding          = "1.3.6.1.2.1.4.1.0"
	oidBridgeAddress         = "1.3.6.1.2.1.17.1.1.0"
	oidLldpLocChassisSubtype = "1.0.8802.1.1.2.1.3.1.0"
	oidLldpLocChassisID      = "1.0.8802.1.1.2.1.3.2.0"
	oidHrDeviceType          = "1.3.6.1.2.1.25.3.2.1.2"
	hrDevicePrinter          = "1.3.6.1.2.1.25.3.1.5"
	oidPrtGeneralName        = "1.3.6.1.2.1.43.5.1.1.16"
)

// Identify performs the minimal authentication/reachability probe: a GET of
// the system group. It is used before full discovery.
func Identify(ctx context.Context, c snmp.Client) (model.System, error) {
	var sys model.System
	res, err := c.Get(ctx, oidSysDescr, oidSysObjectID, oidSysUpTime, oidSysName)
	if err != nil {
		return sys, err
	}
	for _, p := range res {
		if !p.Exists() {
			continue
		}
		switch p.OID {
		case oidSysDescr:
			sys.Descr = p.String()
		case oidSysObjectID:
			sys.ObjectID = p.String()
		case oidSysUpTime:
			sys.UptimeSeconds = int64(p.Uint() / 100)
		case oidSysName:
			sys.Name = p.String()
		}
	}
	return sys, nil
}

func CollectSystem(ctx context.Context, s *Session, snap *model.Snapshot) error {
	res, err := s.Client.Get(ctx, oidSysDescr, oidSysObjectID, oidSysUpTime, oidSysContact, oidSysName,
		oidSysLocation, oidSysServices, oidIPForwarding, oidBridgeAddress, oidLldpLocChassisSubtype, oidLldpLocChassisID)
	if err != nil {
		return err
	}
	sys := &snap.System
	var chassisSubtype int64
	var chassisRaw snmp.PDU
	for _, p := range res {
		if !p.Exists() {
			continue
		}
		switch p.OID {
		case oidSysDescr:
			sys.Descr = p.String()
		case oidSysObjectID:
			sys.ObjectID = p.String()
		case oidSysUpTime:
			sys.UptimeSeconds = int64(p.Uint() / 100)
		case oidSysContact:
			sys.Contact = p.String()
		case oidSysName:
			sys.Name = p.String()
		case oidSysLocation:
			sys.Location = p.String()
		case oidSysServices:
			sys.Services = int(p.Int())
		case oidIPForwarding:
			sys.IsRouter = p.Int() == 1
		case oidBridgeAddress:
			sys.IsBridge = true
			if sys.ChassisID == "" {
				sys.ChassisID = p.MAC()
			}
		case oidLldpLocChassisSubtype:
			chassisSubtype = p.Int()
		case oidLldpLocChassisID:
			chassisRaw = p
		}
	}
	if chassisRaw.Exists() {
		if id := formatChassisID(chassisSubtype, chassisRaw); id != "" {
			sys.ChassisID = id
		}
	}
	if snap.Raw == nil {
		snap.Raw = map[string]string{}
	}
	snap.Raw["sysObjectID"] = sys.ObjectID
	snap.Raw["sysDescr"] = sys.Descr

	// Printer detection (HOST-RESOURCES hrDeviceType / Printer-MIB).
	if types, err := s.Client.Walk(ctx, oidHrDeviceType); err == nil {
		for _, t := range types {
			if t.String() == hrDevicePrinter {
				sys.IsPrinter = true
				break
			}
		}
	}
	if !sys.IsPrinter {
		if names, err := s.Client.Walk(ctx, oidPrtGeneralName); err == nil && len(names) > 0 {
			sys.IsPrinter = true
		}
	}
	return nil
}

// formatChassisID renders an LLDP chassis id by subtype.
func formatChassisID(subtype int64, p snmp.PDU) string {
	b := p.Bytes()
	switch subtype {
	case 4: // macAddress
		if len(b) == 6 {
			return p.MAC()
		}
		return snmp.NormalizeMAC(string(b))
	case 5: // networkAddress: family byte + address
		if len(b) == 5 && b[0] == 1 {
			return snmp.PDU{Value: b[1:]}.IP()
		}
	}
	if mac := p.MAC(); mac != "" && len(b) == 6 {
		return mac
	}
	return strings.TrimSpace(p.String())
}
