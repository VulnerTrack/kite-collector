package windowsprinters

import (
	"strings"
	"testing"
)

func TestPinnedSourceStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(SourcePowerShellCIM), "powershell-cim"},
		{string(SourcePowerShellWMI), "powershell-wmi"},
		{string(SourceUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("source drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestPortProtocolConstants(t *testing.T) {
	if PortProtocolRAW != 1 || PortProtocolLPR != 2 {
		t.Fatalf("port-protocol drift: RAW=%d LPR=%d", PortProtocolRAW, PortProtocolLPR)
	}
}

func TestPrinterStatusConstants(t *testing.T) {
	pairs := []struct{ got, want int }{
		{PrinterStatusOther, 1},
		{PrinterStatusUnknown, 2},
		{PrinterStatusIdle, 3},
		{PrinterStatusPrinting, 4},
		{PrinterStatusWarmup, 5},
		{PrinterStatusStopped, 6},
		{PrinterStatusOffline, 7},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("printer-status drift: got %d want %d", p.got, p.want)
		}
	}
}

func TestIsDefaultSNMPCommunity(t *testing.T) {
	for _, c := range []string{"public", "PUBLIC", "private", "manager", "administrator"} {
		if !IsDefaultSNMPCommunity(c) {
			t.Fatalf("%q must flag", c)
		}
	}
	for _, c := range []string{"corp-snmp-12345", "", "custom"} {
		if IsDefaultSNMPCommunity(c) {
			t.Fatalf("%q must NOT flag", c)
		}
	}
}

func TestAnnotatePrinter(t *testing.T) {
	p := Printer{}
	AnnotatePrinter(&p, true)
	if !p.IsLocal || p.IsNetworkPrinter {
		t.Fatalf("local: %+v", p)
	}
	AnnotatePrinter(&p, false)
	if p.IsLocal || !p.IsNetworkPrinter {
		t.Fatalf("network: %+v", p)
	}
}

func TestAnnotatePortDefaultCommunityFlag(t *testing.T) {
	p := Port{SNMPEnabled: true, SNMPCommunity: "public"}
	AnnotatePort(&p)
	if !p.IsDefaultCommunity {
		t.Fatal("public on enabled SNMP must flag default")
	}
	p = Port{SNMPEnabled: false, SNMPCommunity: "public"}
	AnnotatePort(&p)
	if p.IsDefaultCommunity {
		t.Fatal("SNMP disabled → not default even with 'public' community string")
	}
	p = Port{SNMPEnabled: true, SNMPCommunity: "corp-12345"}
	AnnotatePort(&p)
	if p.IsDefaultCommunity {
		t.Fatal("custom community must NOT flag")
	}
}

// -- ParsePowerShellOutput typical fixture --------------------------

func TestParsePowerShellOutputTypicalFleet(t *testing.T) {
	body := []byte(`{
        "printers": [
            {
                "name": "Microsoft Print to PDF",
                "driver_name": "Microsoft Print To PDF",
                "port_name": "PORTPROMPT:",
                "location": "",
                "comment": "",
                "share_name": "",
                "is_local": true,
                "is_shared": false,
                "is_default": false,
                "is_published": false,
                "printer_status": 3,
                "printer_state": 0,
                "detected_error_state": 0
            },
            {
                "name": "HP-LaserJet-2nd-Floor",
                "driver_name": "HP Universal Printing PCL 6",
                "port_name": "IP_10.0.5.42",
                "location": "Floor 2, Room 204",
                "comment": "Color, duplex",
                "server_name": "",
                "share_name": "HPLJ2F",
                "is_local": false,
                "is_shared": true,
                "is_default": true,
                "is_published": true,
                "printer_status": 3,
                "printer_state": 0,
                "detected_error_state": 0
            }
        ],
        "ports": [
            {
                "name": "IP_10.0.5.42",
                "host_address": "10.0.5.42",
                "port_number": 9100,
                "port_protocol": 1,
                "description": "Standard TCP/IP Port",
                "snmp_enabled": true,
                "snmp_community": "public",
                "queue_name": ""
            },
            {
                "name": "IP_10.0.5.43",
                "host_address": "10.0.5.43",
                "port_number": 515,
                "port_protocol": 2,
                "description": "LPR Port",
                "snmp_enabled": true,
                "snmp_community": "corp-snmp-7890",
                "queue_name": "lp"
            }
        ]
    }`)
	got, err := ParsePowerShellOutput(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got.Printers) != 2 {
		t.Fatalf("printers=%d", len(got.Printers))
	}
	if len(got.Ports) != 2 {
		t.Fatalf("ports=%d", len(got.Ports))
	}

	// PDF printer is purely local.
	pdf := got.Printers[0]
	if !pdf.IsLocal || pdf.IsNetworkPrinter {
		t.Fatalf("PDF flags: %+v", pdf)
	}
	if pdf.Source != SourcePowerShellCIM {
		t.Fatalf("source=%q", pdf.Source)
	}

	// HP is network, shared, default, published.
	hp := got.Printers[1]
	if hp.IsLocal || !hp.IsNetworkPrinter {
		t.Fatalf("HP flags: %+v", hp)
	}
	if !hp.IsShared || hp.ShareName != "HPLJ2F" {
		t.Fatalf("share state wrong: %+v", hp)
	}
	if !hp.IsDefault {
		t.Fatal("HP must flag default")
	}

	// First port has default SNMP community.
	rawPort := got.Ports[0]
	if rawPort.PortProtocol != PortProtocolRAW {
		t.Fatalf("protocol=%d", rawPort.PortProtocol)
	}
	if rawPort.PortNumber != 9100 {
		t.Fatalf("port_number=%d", rawPort.PortNumber)
	}
	if !rawPort.IsDefaultCommunity {
		t.Fatal("public community must flag default")
	}

	// Second port (LPR + custom community) is clean.
	lprPort := got.Ports[1]
	if lprPort.PortProtocol != PortProtocolLPR {
		t.Fatalf("protocol=%d", lprPort.PortProtocol)
	}
	if lprPort.IsDefaultCommunity {
		t.Fatal("custom community must NOT flag default")
	}
}

// -- ParsePowerShellOutput singleton unwrap -------------------------

func TestParsePowerShellOutputSingletonUnwrap(t *testing.T) {
	body := []byte(`{
        "printers": {
            "name": "Solo",
            "driver_name": "Generic",
            "port_name": "LPT1:",
            "is_local": true,
            "printer_status": 3
        },
        "ports": {
            "name": "IP_10.0.0.1",
            "host_address": "10.0.0.1",
            "port_number": 9100,
            "port_protocol": 1,
            "snmp_enabled": false
        }
    }`)
	got, err := ParsePowerShellOutput(body)
	if err != nil {
		t.Fatalf("singleton: %v", err)
	}
	if len(got.Printers) != 1 || len(got.Ports) != 1 {
		t.Fatalf("singleton unwrap broken: %+v", got)
	}
}

// -- ParsePowerShellOutput skip empty names -------------------------

func TestParsePowerShellOutputSkipEmpty(t *testing.T) {
	body := []byte(`{
        "printers": [
            {"name":"","is_local":true},
            {"name":"real","is_local":true,"printer_status":3}
        ],
        "ports": [
            {"name":"","host_address":"X"},
            {"name":"real-port","host_address":"10.0.0.1","port_number":9100,"port_protocol":1}
        ]
    }`)
	got, err := ParsePowerShellOutput(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Printers) != 1 || got.Printers[0].Name != "real" {
		t.Fatalf("printers: %+v", got.Printers)
	}
	if len(got.Ports) != 1 || got.Ports[0].Name != "real-port" {
		t.Fatalf("ports: %+v", got.Ports)
	}
}

// -- error paths ---------------------------------------------------

func TestParsePowerShellOutputEmptyError(t *testing.T) {
	if _, err := ParsePowerShellOutput(nil); err == nil {
		t.Fatal("empty must error")
	}
}

func TestParsePowerShellOutputMalformedError(t *testing.T) {
	if _, err := ParsePowerShellOutput([]byte("not json")); err == nil {
		t.Fatal("malformed must error")
	}
}

// -- script shape spot-check --------------------------------------

func TestPowerShellScriptShape(t *testing.T) {
	for _, must := range []string{
		"Win32_Printer",
		"Win32_TCPIPPrinterPort",
		"snmp_community",
		"ConvertTo-Json",
	} {
		if !strings.Contains(PowerShellScript, must) {
			t.Fatalf("PowerShellScript missing %q", must)
		}
	}
}

func TestSortPrintersDeterministic(t *testing.T) {
	in := []Printer{{Name: "z"}, {Name: "a"}, {Name: "m"}}
	SortPrinters(in)
	if in[0].Name != "a" || in[2].Name != "z" {
		t.Fatalf("sort: %+v", in)
	}
}

func TestSortPortsDeterministic(t *testing.T) {
	in := []Port{{Name: "z"}, {Name: "a"}, {Name: "m"}}
	SortPorts(in)
	if in[0].Name != "a" || in[2].Name != "z" {
		t.Fatalf("sort: %+v", in)
	}
}
