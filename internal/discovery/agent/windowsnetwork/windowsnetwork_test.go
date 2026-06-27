package windowsnetwork

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

func TestEncodeStringList(t *testing.T) {
	if EncodeStringList(nil) != "[]" {
		t.Fatal("nil")
	}
	if got := EncodeStringList([]string{"10.0.0.1", "10.0.0.2"}); got != `["10.0.0.1","10.0.0.2"]` {
		t.Fatalf("got %q", got)
	}
}

func TestNormalizeMAC(t *testing.T) {
	cases := map[string]string{
		"AA:BB:CC:DD:EE:FF": "AA:BB:CC:DD:EE:FF",
		"aa:bb:cc:dd:ee:ff": "AA:BB:CC:DD:EE:FF",
		"AA-BB-CC-DD-EE-FF": "AA:BB:CC:DD:EE:FF",
		"aa-bb-cc-dd-ee-ff": "AA:BB:CC:DD:EE:FF",
		"":                  "",
		"garbage":           "GARBAGE",
	}
	for in, want := range cases {
		if got := NormalizeMAC(in); got != want {
			t.Fatalf("NormalizeMAC(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIsDefaultRouteDestination(t *testing.T) {
	if !IsDefaultRouteDestination("0.0.0.0", "0.0.0.0") {
		t.Fatal("0.0.0.0/0 must flag default")
	}
	if IsDefaultRouteDestination("10.0.0.0", "255.0.0.0") {
		t.Fatal("RFC1918 must NOT flag default")
	}
	if IsDefaultRouteDestination("0.0.0.0", "255.0.0.0") {
		t.Fatal("only when both dest+mask are 0.0.0.0")
	}
}

func TestAnnotateAdapterDerivesGateway(t *testing.T) {
	a := Adapter{
		MACAddress: "aa-bb-cc-dd-ee-ff",
		Gateways:   []string{"192.168.1.1"},
	}
	AnnotateAdapter(&a)
	if a.MACAddress != "AA:BB:CC:DD:EE:FF" {
		t.Fatalf("mac=%q", a.MACAddress)
	}
	if !a.HasDefaultGateway {
		t.Fatal("must flag default gateway")
	}
}

func TestAnnotateAdapterNoGateway(t *testing.T) {
	a := Adapter{
		MACAddress: "AA:BB:CC:DD:EE:FF",
		Gateways:   []string{},
	}
	AnnotateAdapter(&a)
	if a.HasDefaultGateway {
		t.Fatal("empty gateways must NOT flag")
	}
}

func TestAnnotateRoute(t *testing.T) {
	r := Route{Destination: "0.0.0.0", Mask: "0.0.0.0"}
	AnnotateRoute(&r)
	if !r.IsDefaultRoute {
		t.Fatal("must flag default route")
	}
}

// -- ParsePowerShellOutput typical workstation --------------------------

func TestParsePowerShellOutputTypicalWorkstation(t *testing.T) {
	body := []byte(`{
        "adapters": [
            {
                "interface_index": 12,
                "device_id": "12",
                "name": "Intel(R) Wi-Fi 6E AX211 160MHz",
                "description": "Intel(R) Wi-Fi 6E AX211 160MHz",
                "net_connection_id": "Wi-Fi",
                "manufacturer": "Intel Corporation",
                "adapter_type": "Ethernet 802.3",
                "mac_address": "aa-bb-cc-dd-ee-ff",
                "speed_bps": 1200000000,
                "net_enabled": true,
                "net_connection_status": 2,
                "physical_adapter": true,
                "guid": "{12345678-ABCD-1234-ABCD-1234567890AB}",
                "pnp_device_id": "PCI\\VEN_8086",
                "dhcp_enabled": true,
                "dhcp_server": "192.168.1.1",
                "dhcp_lease_obtained": "2026-06-20T08:00:00Z",
                "ip_addresses": ["192.168.1.42", "fe80::1234:5678:9abc:def0"],
                "ip_subnets": ["255.255.255.0", "64"],
                "gateways": ["192.168.1.1"],
                "dns_servers": ["192.168.1.1", "1.1.1.1"],
                "dns_domain": "corp.local",
                "dns_suffix_search_order": ["corp.local"],
                "wins_servers": []
            }
        ],
        "routes": [
            {
                "destination": "0.0.0.0", "mask": "0.0.0.0",
                "next_hop": "192.168.1.1", "interface_index": 12,
                "metric1": 25, "protocol": 3, "type": 4
            },
            {
                "destination": "192.168.1.0", "mask": "255.255.255.0",
                "next_hop": "192.168.1.42", "interface_index": 12,
                "metric1": 281, "protocol": 3, "type": 3
            }
        ]
    }`)
	got, err := ParsePowerShellOutput(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got.Adapters) != 1 {
		t.Fatalf("adapters=%d", len(got.Adapters))
	}
	a := got.Adapters[0]
	if a.MACAddress != "AA:BB:CC:DD:EE:FF" {
		t.Fatalf("mac canonicalisation failed: %q", a.MACAddress)
	}
	if !a.DHCPEnabled || a.DHCPServer != "192.168.1.1" {
		t.Fatalf("dhcp wrong: %+v", a)
	}
	if !a.HasDefaultGateway {
		t.Fatal("must flag default gateway")
	}
	if len(a.IPAddresses) != 2 {
		t.Fatalf("ip count=%d", len(a.IPAddresses))
	}
	if len(a.DNSServers) != 2 || a.DNSServers[1] != "1.1.1.1" {
		t.Fatalf("dns=%v", a.DNSServers)
	}

	if len(got.Routes) != 2 {
		t.Fatalf("routes=%d", len(got.Routes))
	}
	var defaultFound bool
	for _, r := range got.Routes {
		if r.IsDefaultRoute && r.NextHop == "192.168.1.1" {
			defaultFound = true
		}
	}
	if !defaultFound {
		t.Fatal("default route flag did not propagate")
	}
}

// -- ParsePowerShellOutput multi-adapter laptop (Wi-Fi + Ethernet + VPN) --

func TestParsePowerShellOutputMultiAdapterWithSplitTunnel(t *testing.T) {
	body := []byte(`{
        "adapters": [
            {
                "interface_index": 11, "device_id": "11",
                "name": "Ethernet", "net_connection_id": "Ethernet",
                "mac_address": "aa:bb:cc:dd:ee:01",
                "physical_adapter": true, "net_enabled": true,
                "dhcp_enabled": true, "dhcp_server": "10.0.0.1",
                "ip_addresses": ["10.0.0.42"],
                "gateways": ["10.0.0.1"],
                "dns_servers": ["10.0.0.53"]
            },
            {
                "interface_index": 13, "device_id": "13",
                "name": "Cisco AnyConnect VPN Adapter",
                "net_connection_id": "VPN",
                "mac_address": "aa:bb:cc:dd:ee:99",
                "physical_adapter": false, "net_enabled": true,
                "dhcp_enabled": false,
                "ip_addresses": ["10.100.1.42"],
                "gateways": ["10.100.0.1"],
                "dns_servers": ["10.100.0.53"]
            }
        ],
        "routes": [
            {"destination": "0.0.0.0", "mask": "0.0.0.0",
             "next_hop": "10.0.0.1", "interface_index": 11, "metric1": 25},
            {"destination": "0.0.0.0", "mask": "0.0.0.0",
             "next_hop": "10.100.0.1", "interface_index": 13, "metric1": 1}
        ]
    }`)
	got, err := ParsePowerShellOutput(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got.Adapters) != 2 {
		t.Fatalf("adapters=%d", len(got.Adapters))
	}
	defaultRoutes := 0
	for _, r := range got.Routes {
		if r.IsDefaultRoute {
			defaultRoutes++
		}
	}
	if defaultRoutes != 2 {
		t.Fatalf("expected 2 default routes (split-tunnel), got %d", defaultRoutes)
	}
}

// -- ParsePowerShellOutput singleton-object unwrap ----------------------

func TestParsePowerShellOutputSingletonAdapter(t *testing.T) {
	body := []byte(`{
        "adapters": {
            "interface_index": 1, "device_id": "1",
            "name": "loopback", "mac_address": "00:00:00:00:00:00",
            "physical_adapter": false, "net_enabled": true,
            "dhcp_enabled": false,
            "ip_addresses": ["127.0.0.1"],
            "gateways": []
        },
        "routes": {
            "destination": "127.0.0.0", "mask": "255.0.0.0",
            "next_hop": "127.0.0.1", "interface_index": 1
        }
    }`)
	got, err := ParsePowerShellOutput(body)
	if err != nil {
		t.Fatalf("singleton parse: %v", err)
	}
	if len(got.Adapters) != 1 || len(got.Routes) != 1 {
		t.Fatalf("singleton unwrap broken: %+v", got)
	}
	if got.Adapters[0].HasDefaultGateway {
		t.Fatal("loopback has no gateway")
	}
}

// -- ParsePowerShellOutput sparse adapter config ------------------------

func TestParsePowerShellOutputSparseConfig(t *testing.T) {
	// Disconnected adapter — no config join, all addresses empty.
	body := []byte(`{
        "adapters": [{
            "interface_index": 99, "device_id": "99",
            "name": "Bluetooth PAN", "mac_address": "00:11:22:33:44:55",
            "physical_adapter": true, "net_enabled": false,
            "dhcp_enabled": false,
            "ip_addresses": [], "gateways": [], "dns_servers": []
        }],
        "routes": []
    }`)
	got, err := ParsePowerShellOutput(body)
	if err != nil {
		t.Fatal(err)
	}
	if got.Adapters[0].HasDefaultGateway {
		t.Fatal("empty gateway list must not flag")
	}
}

// -- cleanList strips empties ------------------------------------------

func TestCleanListStripsEmpty(t *testing.T) {
	in := []string{"", "10.0.0.1", "  ", "1.1.1.1"}
	got := cleanList(in)
	if len(got) != 2 || got[0] != "10.0.0.1" || got[1] != "1.1.1.1" {
		t.Fatalf("got %v", got)
	}
}

// -- error paths --------------------------------------------------------

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

// -- script shape spot-check --------------------------------------------

func TestPowerShellScriptShape(t *testing.T) {
	for _, must := range []string{
		"Win32_NetworkAdapter",
		"Win32_NetworkAdapterConfiguration",
		"Win32_IP4RouteTable",
		"DefaultIPGateway",
		"DNSServerSearchOrder",
		"ConvertTo-Json",
	} {
		if !strings.Contains(PowerShellScript, must) {
			t.Fatalf("PowerShellScript missing %q", must)
		}
	}
}

func TestSortAdaptersDeterministic(t *testing.T) {
	in := []Adapter{
		{InterfaceIndex: 13, MACAddress: "AA"},
		{InterfaceIndex: 11, MACAddress: "ZZ"},
		{InterfaceIndex: 11, MACAddress: "AA"},
	}
	SortAdapters(in)
	if in[0].InterfaceIndex != 11 || in[0].MACAddress != "AA" {
		t.Fatalf("first=%+v", in[0])
	}
	if in[2].InterfaceIndex != 13 {
		t.Fatalf("last=%+v", in[2])
	}
}

func TestSortRoutesDeterministic(t *testing.T) {
	in := []Route{
		{Destination: "192.168.1.0", Mask: "255.255.255.0", NextHop: "10.0.0.1"},
		{Destination: "0.0.0.0", Mask: "0.0.0.0", NextHop: "192.168.1.1"},
		{Destination: "0.0.0.0", Mask: "0.0.0.0", NextHop: "10.0.0.1"},
	}
	SortRoutes(in)
	if in[0].Destination != "0.0.0.0" || in[0].NextHop != "10.0.0.1" {
		t.Fatalf("first=%+v", in[0])
	}
	if in[2].Destination != "192.168.1.0" {
		t.Fatalf("last=%+v", in[2])
	}
}
