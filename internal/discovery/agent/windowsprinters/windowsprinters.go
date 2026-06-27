// Package windowsprinters inventories Windows printers + their
// TCP/IP ports via a PowerShell shim. Twelfth table-set of the MID
// Server-aligned Windows track.
//
// Returns an Inventory bundle (Printers + Ports) so the store layer
// fans out into two table writes via asset_id from one PowerShell
// round-trip.
//
// MITRE T1210 (Exploitation of Remote Services — defender side):
// network-attached printers run firmware with a long CVE history
// (Lexmark, HP, Xerox, Brother). The audit pipeline joins ports
// against the CVE feed by host_address; share state surfaces SMB
// adjacency.
package windowsprinters

import (
	"context"
	"sort"
	"strings"
)

// Source identifies which probe produced the rows.
type Source string

const (
	SourcePowerShellCIM Source = "powershell-cim"
	SourcePowerShellWMI Source = "powershell-wmi"
	SourceUnknown       Source = "unknown"
)

// Win32_TCPIPPrinterPort.Protocol enum values.
const (
	PortProtocolRAW = 1 // port 9100
	PortProtocolLPR = 2
)

// Win32_Printer.PrinterStatus enum values.
const (
	PrinterStatusOther    = 1
	PrinterStatusUnknown  = 2
	PrinterStatusIdle     = 3
	PrinterStatusPrinting = 4
	PrinterStatusWarmup   = 5
	PrinterStatusStopped  = 6
	PrinterStatusOffline  = 7
)

// Printer mirrors host_windows_printers' column shape.
type Printer struct {
	Source             Source `json:"source"`
	Name               string `json:"name"`
	DriverName         string `json:"driver_name,omitempty"`
	PortName           string `json:"port_name,omitempty"`
	Location           string `json:"location,omitempty"`
	Comment            string `json:"comment,omitempty"`
	ServerName         string `json:"server_name,omitempty"`
	ShareName          string `json:"share_name,omitempty"`
	IsLocal            bool   `json:"is_local"`
	IsNetworkPrinter   bool   `json:"is_network_printer"`
	IsShared           bool   `json:"is_shared"`
	IsDefault          bool   `json:"is_default"`
	IsPublished        bool   `json:"is_published"`
	PrinterStatus      int    `json:"printer_status"`
	PrinterState       int    `json:"printer_state,omitempty"`
	DetectedErrorState int    `json:"detected_error_state,omitempty"`
}

// Port mirrors host_windows_printer_ports' column shape.
type Port struct {
	Source             Source `json:"source"`
	Name               string `json:"name"`
	HostAddress        string `json:"host_address,omitempty"`
	Description        string `json:"description,omitempty"`
	SNMPCommunity      string `json:"snmp_community,omitempty"`
	QueueName          string `json:"queue_name,omitempty"`
	PortNumber         int    `json:"port_number"`
	PortProtocol       int    `json:"port_protocol"`
	SNMPEnabled        bool   `json:"snmp_enabled"`
	IsDefaultCommunity bool   `json:"is_default_community"`
}

// Inventory bundles both entity slices.
type Inventory struct {
	Printers []Printer `json:"printers"`
	Ports    []Port    `json:"ports"`
}

// Collector is the read-only contract every per-OS implementation
// satisfies. Windows: PowerShell shim. Other OSes: empty Inventory.
type Collector interface {
	Name() string
	Collect(ctx context.Context) (Inventory, error)
}

// DefaultSNMPCommunities is the curated set of SNMP community
// strings every printer ships with. Their presence on a port =
// CWE-1188 (Insecure Default Initialization) — the audit pipeline
// surfaces them as findings.
func DefaultSNMPCommunities() []string {
	return []string{"public", "private", "manager", "administrator"}
}

// IsDefaultSNMPCommunity reports whether the community string matches
// one of the well-known vendor defaults.
func IsDefaultSNMPCommunity(community string) bool {
	v := strings.ToLower(strings.TrimSpace(community))
	if v == "" {
		return false
	}
	for _, c := range DefaultSNMPCommunities() {
		if c == v {
			return true
		}
	}
	return false
}

// AnnotatePrinter derives IsLocal/IsNetworkPrinter from the raw
// Win32_Printer.Local boolean. We always populate both so the audit
// pipeline's SQL never has to negate.
func AnnotatePrinter(p *Printer, rawLocal bool) {
	p.IsLocal = rawLocal
	p.IsNetworkPrinter = !rawLocal
}

// AnnotatePort derives IsDefaultCommunity from the community string.
func AnnotatePort(p *Port) {
	p.IsDefaultCommunity = p.SNMPEnabled && IsDefaultSNMPCommunity(p.SNMPCommunity)
}

// SortPrinters returns a deterministic ordering: name.
func SortPrinters(ps []Printer) {
	sort.Slice(ps, func(i, j int) bool {
		return ps[i].Name < ps[j].Name
	})
}

// SortPorts returns a deterministic ordering: name.
func SortPorts(ps []Port) {
	sort.Slice(ps, func(i, j int) bool {
		return ps[i].Name < ps[j].Name
	})
}

// SortInventory normalises both slices in place.
func SortInventory(inv *Inventory) {
	if inv == nil {
		return
	}
	SortPrinters(inv.Printers)
	SortPorts(inv.Ports)
}
