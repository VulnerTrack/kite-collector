package windowsprinters

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// PowerShellScript pulls Win32_Printer + Win32_TCPIPPrinterPort in
// one round-trip. We `[string]`-cast every value so PowerShell
// version drift doesn't change the wire format.
const PowerShellScript = `
$ErrorActionPreference = 'Stop'
$printers = @(Get-CimInstance -ClassName Win32_Printer -ErrorAction SilentlyContinue)
$ports    = @(Get-CimInstance -ClassName Win32_TCPIPPrinterPort -ErrorAction SilentlyContinue)

$printerRows = @($printers | ForEach-Object {
    [pscustomobject]@{
        name                  = [string]$_.Name
        driver_name           = [string]$_.DriverName
        port_name             = [string]$_.PortName
        location              = [string]$_.Location
        comment               = [string]$_.Comment
        server_name           = [string]$_.ServerName
        share_name            = [string]$_.ShareName
        is_local              = [bool]$_.Local
        is_shared             = [bool]$_.Shared
        is_default            = [bool]$_.Default
        is_published          = [bool]$_.Published
        printer_status        = if ($_.PrinterStatus -ne $null) { [int]$_.PrinterStatus } else { 0 }
        printer_state         = if ($_.PrinterState -ne $null) { [int]$_.PrinterState } else { 0 }
        detected_error_state  = if ($_.DetectedErrorState -ne $null) { [int]$_.DetectedErrorState } else { 0 }
    }
})

$portRows = @($ports | ForEach-Object {
    [pscustomobject]@{
        name             = [string]$_.Name
        host_address     = [string]$_.HostAddress
        port_number      = if ($_.PortNumber -ne $null) { [int]$_.PortNumber } else { 0 }
        port_protocol    = if ($_.Protocol -ne $null) { [int]$_.Protocol } else { 0 }
        description      = [string]$_.Description
        snmp_enabled     = [bool]$_.SNMPEnabled
        snmp_community   = [string]$_.SNMPCommunity
        queue_name       = [string]$_.Queue
    }
})

[pscustomobject]@{
    printers = @($printerRows)
    ports    = @($portRows)
} | ConvertTo-Json -Depth 4 -Compress
`

// rawPayload mirrors the wire JSON shape.
type rawPayload struct {
	Printers []rawPrinter `json:"printers"`
	Ports    []rawPort    `json:"ports"`
}

type rawPrinter struct {
	ShareName          string      `json:"share_name"`
	PrinterState       json.Number `json:"printer_state"`
	PortName           string      `json:"port_name"`
	Location           string      `json:"location"`
	Comment            string      `json:"comment"`
	ServerName         string      `json:"server_name"`
	DetectedErrorState json.Number `json:"detected_error_state"`
	Name               string      `json:"name"`
	DriverName         string      `json:"driver_name"`
	PrinterStatus      json.Number `json:"printer_status"`
	IsPublished        bool        `json:"is_published"`
	IsDefault          bool        `json:"is_default"`
	IsLocal            bool        `json:"is_local"`
	IsShared           bool        `json:"is_shared"`
}

type rawPort struct {
	Name          string      `json:"name"`
	HostAddress   string      `json:"host_address"`
	PortNumber    json.Number `json:"port_number"`
	PortProtocol  json.Number `json:"port_protocol"`
	Description   string      `json:"description"`
	SNMPCommunity string      `json:"snmp_community"`
	QueueName     string      `json:"queue_name"`
	SNMPEnabled   bool        `json:"snmp_enabled"`
}

// ParsePowerShellOutput converts the JSON payload into an Inventory.
// Singleton-object unwrap handles single-printer hosts.
func ParsePowerShellOutput(data []byte) (Inventory, error) {
	trimmed := trimUTF8BOM(data)
	trimmed = []byte(strings.TrimSpace(string(trimmed)))
	if len(trimmed) == 0 {
		return Inventory{}, fmt.Errorf("empty PowerShell output")
	}
	normalised := unwrapSingletonArrays(trimmed)
	var raw rawPayload
	dec := json.NewDecoder(strings.NewReader(string(normalised)))
	dec.UseNumber()
	if err := dec.Decode(&raw); err != nil {
		return Inventory{}, fmt.Errorf("decode windows-printers json: %w", err)
	}
	inv := Inventory{
		Printers: make([]Printer, 0, len(raw.Printers)),
		Ports:    make([]Port, 0, len(raw.Ports)),
	}
	for _, r := range raw.Printers {
		name := strings.TrimSpace(r.Name)
		if name == "" {
			continue
		}
		p := Printer{
			Source:             SourcePowerShellCIM,
			Name:               name,
			DriverName:         strings.TrimSpace(r.DriverName),
			PortName:           strings.TrimSpace(r.PortName),
			Location:           strings.TrimSpace(r.Location),
			Comment:            strings.TrimSpace(r.Comment),
			ServerName:         strings.TrimSpace(r.ServerName),
			ShareName:          strings.TrimSpace(r.ShareName),
			IsShared:           r.IsShared,
			IsDefault:          r.IsDefault,
			IsPublished:        r.IsPublished,
			PrinterStatus:      atoi(r.PrinterStatus),
			PrinterState:       atoi(r.PrinterState),
			DetectedErrorState: atoi(r.DetectedErrorState),
		}
		AnnotatePrinter(&p, r.IsLocal)
		inv.Printers = append(inv.Printers, p)
	}
	for _, r := range raw.Ports {
		name := strings.TrimSpace(r.Name)
		if name == "" {
			continue
		}
		p := Port{
			Source:        SourcePowerShellCIM,
			Name:          name,
			HostAddress:   strings.TrimSpace(r.HostAddress),
			PortNumber:    atoi(r.PortNumber),
			PortProtocol:  atoi(r.PortProtocol),
			Description:   strings.TrimSpace(r.Description),
			SNMPEnabled:   r.SNMPEnabled,
			SNMPCommunity: strings.TrimSpace(r.SNMPCommunity),
			QueueName:     strings.TrimSpace(r.QueueName),
		}
		AnnotatePort(&p)
		inv.Ports = append(inv.Ports, p)
	}
	return inv, nil
}

func atoi(n json.Number) int {
	if n == "" {
		return 0
	}
	if v, err := n.Int64(); err == nil {
		return int(v)
	}
	if i, err := strconv.Atoi(n.String()); err == nil {
		return i
	}
	return 0
}

func unwrapSingletonArrays(in []byte) []byte {
	s := string(in)
	for _, key := range []string{`"printers":`, `"ports":`} {
		s = wrapSingletonValue(s, key)
	}
	return []byte(s)
}

func wrapSingletonValue(s, key string) string {
	idx := strings.Index(s, key)
	if idx < 0 {
		return s
	}
	rest := s[idx+len(key):]
	i := 0
	for i < len(rest) && (rest[i] == ' ' || rest[i] == '\t') {
		i++
	}
	if i >= len(rest) || rest[i] != '{' {
		return s
	}
	depth, inStr, escaped := 0, false, false
	end := -1
	for j := i; j < len(rest); j++ {
		c := rest[j]
		switch {
		case escaped:
			escaped = false
		case c == '\\' && inStr:
			escaped = true
		case c == '"':
			inStr = !inStr
		case c == '{' && !inStr:
			depth++
		case c == '}' && !inStr:
			depth--
			if depth == 0 {
				end = j + 1
			}
		}
		if end >= 0 {
			break
		}
	}
	if end <= i {
		return s
	}
	wrapped := "[" + rest[i:end] + "]" + rest[end:]
	return s[:idx+len(key)] + wrapped
}

func trimUTF8BOM(data []byte) []byte {
	if len(data) >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
		return data[3:]
	}
	return data
}
