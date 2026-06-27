// Package netinterfaces enumerates physical and virtual network
// interfaces on the host: Ethernet, Wi-Fi, cellular, loopback,
// VLAN, bridge, bond, veth (container pair), TUN/TAP, dummy,
// tunnel, vxlan, geneve, wireguard, openvpn.
//
// Per-OS Sources live in build-tagged files. Tests inject a
// fakeSource.
//
// PII discipline: the MAC address is SHA-256 hashed before
// persistence; the OUI (first 3 bytes) is kept in cleartext for
// vendor lookups since it's not unique to the host.
//
// Read-only by intent.
package netinterfaces

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	MaxRows        = 1024
	RecentlyWindow = 5 * time.Minute
	// LowSpeedThresholdMbps flags any physical interface negotiated
	// below 1 Gb (suggests a degraded link, bad cable, or a slow
	// hub on a path where Gb is expected).
	LowSpeedThresholdMbps = 1000
)

// IfaceType pinned to host_net_interfaces.iface_type.
type IfaceType string

const (
	TypeUnknown    IfaceType = "unknown"
	TypeEthernet   IfaceType = "ethernet"
	TypeWifi       IfaceType = "wifi"
	TypeCellular   IfaceType = "cellular"
	TypeLoopback   IfaceType = "loopback"
	TypeVLAN       IfaceType = "vlan"
	TypeBridge     IfaceType = "bridge"
	TypeBond       IfaceType = "bond"
	TypeVeth       IfaceType = "veth"
	TypeTUN        IfaceType = "tun"
	TypeTAP        IfaceType = "tap"
	TypeDummy      IfaceType = "dummy"
	TypeTunnel     IfaceType = "tunnel"
	TypeSIT        IfaceType = "sit"
	TypeVXLAN      IfaceType = "vxlan"
	TypeGeneve     IfaceType = "geneve"
	TypeWireguard  IfaceType = "wireguard"
	TypeOpenVPN    IfaceType = "openvpn"
	TypeInfiniband IfaceType = "infiniband"
	TypeCAN        IfaceType = "can"
	TypePPP        IfaceType = "ppp"
	TypeTAPVPN     IfaceType = "tap-vpn"
	TypeTAPVirt    IfaceType = "tap-virt"
	TypeOther      IfaceType = "other"
)

// Operstate pinned to host_net_interfaces.operstate.
type Operstate string

const (
	OpUnknown        Operstate = "unknown"
	OpUp             Operstate = "up"
	OpDown           Operstate = "down"
	OpDormant        Operstate = "dormant"
	OpTesting        Operstate = "testing"
	OpLowerLayerDown Operstate = "lowerlayerdown"
	OpNotPresent     Operstate = "notpresent"
)

// Duplex pinned to host_net_interfaces.duplex.
type Duplex string

const (
	DuplexNone    Duplex = ""
	DuplexHalf    Duplex = "half"
	DuplexFull    Duplex = "full"
	DuplexUnknown Duplex = "unknown"
)

// Iface mirrors host_net_interfaces columns.
type Iface struct {
	Duplex            Duplex    `json:"duplex,omitempty"`
	IfaceType         IfaceType `json:"iface_type"`
	MACAddressHash    string    `json:"mac_address_hash,omitempty"`
	OUIHex            string    `json:"oui_hex,omitempty"`
	Driver            string    `json:"driver,omitempty"`
	Operstate         Operstate `json:"operstate"`
	rawMAC            string
	PCIBDF            string `json:"pci_bdf,omitempty"`
	Iface             string `json:"iface"`
	TxQueueLen        int    `json:"tx_queue_len"`
	SpeedMbps         int    `json:"speed_mbps"`
	MTU               int    `json:"mtu"`
	IsPhysical        bool   `json:"is_physical"`
	IsWireless        bool   `json:"is_wireless"`
	IsVPN             bool   `json:"is_vpn"`
	IsContainer       bool   `json:"is_container"`
	IsPromiscuous     bool   `json:"is_promiscuous"`
	IsPromiscuousRisk bool   `json:"is_promiscuous_risk"`
	IsNoCarrierRisk   bool   `json:"is_no_carrier_risk"`
	IsLowSpeedRisk    bool   `json:"is_low_speed_risk"`
	IsRecent          bool   `json:"is_recent"`
	Carrier           bool   `json:"carrier"`
}

// SetRawMAC lets the Source feed the raw MAC for hashing.
func (i *Iface) SetRawMAC(mac string) { i.rawMAC = mac }

// Source enumerates interfaces.
type Source interface {
	Enumerate(ctx context.Context) ([]Iface, error)
}

// Collector is the read-only contract.
type Collector interface {
	Name() string
	Collect(ctx context.Context) ([]Iface, error)
}

type collector struct {
	src Source
	now func() time.Time
}

func NewCollector() Collector             { return &collector{src: newSource(), now: time.Now} }
func NewCollectorWith(s Source) Collector { return &collector{src: s, now: time.Now} }
func (c *collector) Name() string         { return "netinterfaces" }

func (c *collector) Collect(ctx context.Context) ([]Iface, error) {
	rows, err := c.src.Enumerate(ctx)
	if err != nil {
		return nil, fmt.Errorf("netinterfaces enumerate: %w", err)
	}
	if len(rows) > MaxRows {
		rows = rows[:MaxRows]
	}
	for i := range rows {
		Normalize(&rows[i])
		Annotate(&rows[i])
	}
	SortIfaces(rows)
	return rows, nil
}

// Normalize back-fills derived type / category flags from the
// iface name + driver hints.
func Normalize(i *Iface) {
	if i.IfaceType == "" || i.IfaceType == TypeUnknown {
		i.IfaceType = TypeFromName(i.Iface, i.Driver)
	}
	if i.Operstate == "" {
		i.Operstate = OpUnknown
	}
	switch i.IfaceType {
	case TypeEthernet, TypeWifi, TypeCellular, TypeInfiniband:
		i.IsPhysical = true
	case TypeVLAN, TypeBridge, TypeBond, TypeVeth, TypeTUN, TypeTAP,
		TypeDummy, TypeTunnel, TypeSIT, TypeVXLAN, TypeGeneve,
		TypeWireguard, TypeOpenVPN, TypeLoopback, TypeCAN, TypePPP,
		TypeTAPVPN, TypeTAPVirt, TypeOther, TypeUnknown:
		i.IsPhysical = false
	}
	if i.IfaceType == TypeWifi {
		i.IsWireless = true
	}
	if i.IfaceType == TypeWireguard || i.IfaceType == TypeOpenVPN ||
		i.IfaceType == TypeTAPVPN {
		i.IsVPN = true
	}
	if i.IfaceType == TypeVeth || i.IfaceType == TypeTAPVirt {
		i.IsContainer = true
	}
}

// Annotate hashes the MAC, derives OUI, and sets risk rollups.
func Annotate(i *Iface) {
	i.IsRecent = true
	if i.rawMAC != "" {
		i.MACAddressHash = hashMAC(i.rawMAC)
		i.OUIHex = extractOUI(i.rawMAC)
		i.rawMAC = ""
	}
	if i.IsPromiscuous {
		i.IsPromiscuousRisk = true
	}
	if i.IsPhysical && !i.Carrier && i.Operstate != OpDown {
		i.IsNoCarrierRisk = true
	}
	if i.IsPhysical && i.SpeedMbps > 0 && i.SpeedMbps < LowSpeedThresholdMbps {
		i.IsLowSpeedRisk = true
	}
}

// TypeFromName infers a type from the iface name + driver. The
// Linux convention is reliable enough that this heuristic
// catches > 95% of real-world interfaces without a syscall.
func TypeFromName(name, driver string) IfaceType {
	n := strings.ToLower(name)
	d := strings.ToLower(driver)
	switch {
	case n == "lo" || strings.HasPrefix(n, "lo"):
		return TypeLoopback
	case strings.HasPrefix(n, "eth") || strings.HasPrefix(n, "en") || strings.HasPrefix(n, "em"):
		return TypeEthernet
	case strings.HasPrefix(n, "wl") || strings.HasPrefix(n, "wlan") ||
		strings.HasPrefix(n, "wifi") || strings.HasPrefix(n, "wlp"):
		return TypeWifi
	case strings.HasPrefix(n, "ww") || strings.HasPrefix(n, "wwan"):
		return TypeCellular
	case strings.HasPrefix(n, "br") || strings.HasPrefix(n, "docker") ||
		strings.HasPrefix(n, "virbr"):
		return TypeBridge
	case strings.HasPrefix(n, "bond"):
		return TypeBond
	case strings.HasPrefix(n, "veth"):
		return TypeVeth
	case strings.HasPrefix(n, "vlan") || strings.Contains(n, ".") && strings.HasPrefix(n, "eth"):
		return TypeVLAN
	case strings.HasPrefix(n, "tun"):
		return TypeTUN
	case strings.HasPrefix(n, "tap"):
		return TypeTAP
	case strings.HasPrefix(n, "dummy"):
		return TypeDummy
	case strings.HasPrefix(n, "sit"):
		return TypeSIT
	case strings.HasPrefix(n, "vxlan"):
		return TypeVXLAN
	case strings.HasPrefix(n, "geneve"):
		return TypeGeneve
	case strings.HasPrefix(n, "wg"):
		return TypeWireguard
	case strings.HasPrefix(n, "ovpn") || strings.HasPrefix(n, "openvpn"):
		return TypeOpenVPN
	case strings.HasPrefix(n, "ib"):
		return TypeInfiniband
	case strings.HasPrefix(n, "can"):
		return TypeCAN
	case strings.HasPrefix(n, "ppp"):
		return TypePPP
	}
	switch d {
	case "wireguard":
		return TypeWireguard
	case "bridge":
		return TypeBridge
	case "bonding":
		return TypeBond
	case "veth":
		return TypeVeth
	}
	return TypeOther
}

// SortIfaces returns deterministic ordering by iface.
func SortIfaces(rs []Iface) {
	sort.Slice(rs, func(i, j int) bool { return rs[i].Iface < rs[j].Iface })
}

// hashMAC SHA-256 hashes a normalized MAC string.
func hashMAC(mac string) string {
	t := strings.ToLower(strings.TrimSpace(mac))
	t = strings.ReplaceAll(t, "-", ":")
	if t == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(t))
	return hex.EncodeToString(sum[:])
}

// extractOUI returns the first 3 bytes (vendor OUI) of a MAC as
// 6 lowercase hex chars without separators.
func extractOUI(mac string) string {
	t := strings.ToLower(strings.TrimSpace(mac))
	t = strings.ReplaceAll(t, ":", "")
	t = strings.ReplaceAll(t, "-", "")
	if len(t) < 6 {
		return ""
	}
	return t[:6]
}
