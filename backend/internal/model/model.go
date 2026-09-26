// Package model defines the normalized, vendor-neutral network domain model
// produced by collectors. Nothing here knows about OIDs or SNMP.
package model

import "time"

// System is identity and health information about a managed device.
type System struct {
	Descr         string   `json:"descr"`
	ObjectID      string   `json:"object_id"`
	Name          string   `json:"name"`
	Contact       string   `json:"contact"`
	Location      string   `json:"location"`
	UptimeSeconds int64    `json:"uptime_seconds"`
	Vendor        string   `json:"vendor"`
	VendorSource  string   `json:"vendor_source"`
	Model         string   `json:"model"`
	Serial        string   `json:"serial"`
	OSName        string   `json:"os_name"`
	OSVersion     string   `json:"os_version"`
	HardwareRev   string   `json:"hardware_rev"`
	ChassisID     string   `json:"chassis_id"` // LLDP local chassis id (usually base MAC)
	Services      int      `json:"services"`   // sysServices bitmask
	CPUPercent    *float64 `json:"cpu_percent,omitempty"`
	MemoryPercent *float64 `json:"memory_percent,omitempty"`
	IsPrinter     bool     `json:"is_printer"` // Printer-MIB/HOST-RESOURCES says so
	IsBridge      bool     `json:"is_bridge"`  // BRIDGE-MIB present
	IsRouter      bool     `json:"is_router"`  // ipForwarding = forwarding
}

// Interface is a port or logical interface.
type Interface struct {
	IfIndex           int    `json:"if_index"`
	Name              string `json:"name"`
	Descr             string `json:"descr"`
	Alias             string `json:"alias"`
	Type              int    `json:"type"`
	MTU               int    `json:"mtu"`
	SpeedBps          uint64 `json:"speed_bps"`
	MAC               string `json:"mac"`
	AdminStatus       string `json:"admin_status"`
	OperStatus        string `json:"oper_status"`
	Duplex            string `json:"duplex"` // full|half|unknown
	Medium            string `json:"medium"` // copper|fiber|wireless|virtual|unknown
	PVID              int    `json:"pvid"`
	InOctets          uint64 `json:"in_octets"`
	OutOctets         uint64 `json:"out_octets"`
	InErrors          uint64 `json:"in_errors"`
	OutErrors         uint64 `json:"out_errors"`
	LastChangeSeconds int64  `json:"last_change_seconds"`
	// BridgePort is the dot1dBasePort number mapping to this ifIndex (0 = none).
	BridgePort int `json:"bridge_port"`
}

// Physical returns true for ethernet-like physical ports.
func (i Interface) Physical() bool {
	switch i.Type {
	case 6, 62, 69, 117, 7, 26, 71: // ethernetCsmacd, fastEther, fastEtherFX, gigabitEthernet, iso88023, ethernet3Mbit, ieee80211
		return true
	}
	return false
}

type IPAddress struct {
	IP        string `json:"ip"`
	PrefixLen int    `json:"prefix_len"`
	IfIndex   int    `json:"if_index"`
}

// Neighbor is an LLDP/CDP adjacency seen from the local device.
type Neighbor struct {
	Protocol     string   `json:"protocol"` // lldp|cdp
	LocalIfIndex int      `json:"local_if_index"`
	LocalPort    string   `json:"local_port"`
	ChassisID    string   `json:"chassis_id"`
	PortID       string   `json:"port_id"`
	PortDescr    string   `json:"port_descr"`
	SysName      string   `json:"sys_name"`
	SysDescr     string   `json:"sys_descr"`
	Platform     string   `json:"platform"`
	MgmtIP       string   `json:"mgmt_ip"`
	Capabilities []string `json:"capabilities"` // bridge, router, wlan-ap, phone, station, docsis, repeater, other
}

type FDBEntry struct {
	MAC     string `json:"mac"`
	VLAN    int    `json:"vlan"`
	IfIndex int    `json:"if_index"`
	Status  string `json:"status"` // learned|static|self|other
}

type ARPEntry struct {
	IP      string `json:"ip"`
	MAC     string `json:"mac"`
	IfIndex int    `json:"if_index"`
}

type VLAN struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

type Route struct {
	Dest     string `json:"dest"` // CIDR
	NextHop  string `json:"next_hop"`
	IfIndex  int    `json:"if_index"`
	Protocol string `json:"protocol"`
	Metric   int    `json:"metric"`
}

type Sensor struct {
	Kind   string   `json:"kind"` // temperature|fan|power|voltage|current|cpu|memory
	Name   string   `json:"name"`
	Value  *float64 `json:"value,omitempty"`
	Unit   string   `json:"unit"`
	Status string   `json:"status"` // ok|warning|critical|unknown
}

type Optic struct {
	IfIndex      int      `json:"if_index"`
	Vendor       string   `json:"vendor"`
	PartNumber   string   `json:"part_number"`
	Serial       string   `json:"serial"`
	Type         string   `json:"type"`
	WavelengthNm int      `json:"wavelength_nm"`
	RxDBm        *float64 `json:"rx_dbm,omitempty"`
	TxDBm        *float64 `json:"tx_dbm,omitempty"`
	TempC        *float64 `json:"temp_c,omitempty"`
}

// Entity is an ENTITY-MIB physical inventory item.
type Entity struct {
	Index        int    `json:"index"`
	ParentIndex  int    `json:"parent_index"`
	Class        string `json:"class"` // chassis|module|port|powerSupply|fan|sensor|stack|container|cpu|other
	Name         string `json:"name"`
	Descr        string `json:"descr"`
	Model        string `json:"model"`
	Serial       string `json:"serial"`
	HWRev        string `json:"hw_rev"`
	FWRev        string `json:"fw_rev"`
	SWRev        string `json:"sw_rev"`
	Manufacturer string `json:"manufacturer"`
	// AliasIfIndex is set when entAliasMappingTable links this entity to an ifIndex.
	AliasIfIndex int `json:"alias_if_index"`
}

// Snapshot is everything collected from one device in one discovery pass.
type Snapshot struct {
	Target      string      `json:"target"`
	CollectedAt time.Time   `json:"collected_at"`
	System      System      `json:"system"`
	Interfaces  []Interface `json:"interfaces"`
	IPs         []IPAddress `json:"ips"`
	Neighbors   []Neighbor  `json:"neighbors"`
	FDB         []FDBEntry  `json:"fdb"`
	ARP         []ARPEntry  `json:"arp"`
	VLANs       []VLAN      `json:"vlans"`
	// PortVLANs maps ifIndex → VLAN memberships (untagged first when known).
	PortVLANs map[int][]PortVLAN `json:"port_vlans"`
	Routes    []Route            `json:"routes"`
	Sensors   []Sensor           `json:"sensors"`
	Optics    []Optic            `json:"optics"`
	Inventory []Entity           `json:"inventory"`
	// Errors records per-collector failures; a failing collector never aborts discovery.
	Errors []CollectorError `json:"errors"`
	// Raw holds a few interesting raw values for the "Advanced details" view.
	Raw map[string]string `json:"raw"`
}

type PortVLAN struct {
	VLAN   int  `json:"vlan"`
	Tagged bool `json:"tagged"`
}

type CollectorError struct {
	Collector string `json:"collector"`
	Error     string `json:"error"`
}

// InterfaceByIndex returns a pointer to the interface with ifIndex, or nil.
func (s *Snapshot) InterfaceByIndex(idx int) *Interface {
	for i := range s.Interfaces {
		if s.Interfaces[i].IfIndex == idx {
			return &s.Interfaces[i]
		}
	}
	return nil
}

// InterfaceByName finds an interface by name/descr/alias (case-insensitive, exact).
func (s *Snapshot) InterfaceByName(name string) *Interface {
	if name == "" {
		return nil
	}
	n := lower(name)
	for i := range s.Interfaces {
		it := &s.Interfaces[i]
		if lower(it.Name) == n || lower(it.Descr) == n {
			return it
		}
	}
	for i := range s.Interfaces {
		if lower(s.Interfaces[i].Alias) == n {
			return &s.Interfaces[i]
		}
	}
	return nil
}

func lower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}

// Device types used across classification, UI and queries.
const (
	TypeRouter      = "router"
	TypeSwitch      = "switch"
	TypeFirewall    = "firewall"
	TypeAccessPoint = "access_point"
	TypeWLC         = "wireless_controller"
	TypePrinter     = "printer"
	TypeComputer    = "computer"
	TypeServer      = "server"
	TypePhone       = "phone"
	TypeCamera      = "camera"
	TypeStorage     = "storage"
	TypeUPS         = "ups"
	TypeIoT         = "iot"
	TypeVirtual     = "virtual_machine"
	TypeMobile      = "mobile"
	TypeUnknown     = "unknown"
)

// DeviceTypes lists all known types (for validation/UI).
var DeviceTypes = []string{TypeRouter, TypeSwitch, TypeFirewall, TypeAccessPoint, TypeWLC, TypePrinter,
	TypeComputer, TypeServer, TypePhone, TypeCamera, TypeStorage, TypeUPS, TypeIoT, TypeVirtual, TypeMobile, TypeUnknown}

// IsNetworkInfra reports whether a type is network infrastructure (topology backbone).
func IsNetworkInfra(t string) bool {
	switch t {
	case TypeRouter, TypeSwitch, TypeFirewall, TypeAccessPoint, TypeWLC:
		return true
	}
	return false
}
