package btnames

import (
	"testing"
)

func TestIsValidMAC(t *testing.T) {
	cases := map[string]bool{
		"AA:BB:CC:DD:EE:FF": true,
		"00:11:22:33:44:55": true,
		"aa:bb:cc:dd:ee:ff": true,
		"AA:BB:CC:DD:EE":    false,
		"AA-BB-CC-DD-EE-FF": false,
		"":                  false,
		"random text":       false,
	}
	for in, want := range cases {
		if got := IsValidMAC(in); got != want {
			t.Fatalf("IsValidMAC(%q)=%v want %v", in, got, want)
		}
	}
}

func TestCoDMajorClass(t *testing.T) {
	cases := map[uint32]DeviceClass{
		0x000100: DeviceClassComputer,
		0x000200: DeviceClassPhone,
		0x000400: DeviceClassAudio,
		0x000500: DeviceClassPeripheral, // HID keyboard / mouse
		0x000704: DeviceClassWearable,
		0x000900: DeviceClassHealth,
		0x001F00: DeviceClassUncategorized,
		0x000000: DeviceClassMisc,
	}
	for cod, want := range cases {
		if got := CoDMajorClass(cod); got != want {
			t.Fatalf("CoDMajorClass(0x%06x)=%q want %q", cod, got, want)
		}
	}
}

func TestHashName(t *testing.T) {
	a := HashName("Alice's iPhone")
	b := HashName("Alice's iPhone")
	c := HashName("alice's iphone")
	if a != b {
		t.Fatal("hash drift")
	}
	if a != c {
		t.Fatal("hash must be case-insensitive")
	}
	if len(a) != 64 {
		t.Fatalf("hash len=%d", len(a))
	}
	if HashName("") != "" {
		t.Fatal("empty must yield empty")
	}
}

func TestParseBlueZInfo(t *testing.T) {
	body := []byte(`[General]
Name=Logitech MX Keys
Alias=Alice's Keyboard
Class=0x000540
AddressType=public
Trusted=true
Blocked=false
Connected=true

[DeviceID]
Source=2
Vendor=1133
Product=45923
Manufacturer=Logitech

[LinkKey]
Key=BEEFBEEFBEEFBEEFBEEFBEEFBEEFBEEF
Type=4
PINLength=0
`)
	info := ParseBlueZInfo(body)
	if info.Name != "Logitech MX Keys" {
		t.Fatalf("name=%q", info.Name)
	}
	if info.Alias != "Alice's Keyboard" {
		t.Fatalf("alias=%q", info.Alias)
	}
	if info.Class != 0x000540 {
		t.Fatalf("class=0x%06x", info.Class)
	}
	if info.DeviceClass != DeviceClassPeripheral {
		t.Fatalf("device class=%q want peripheral", info.DeviceClass)
	}
	if info.Manufacturer != "Logitech" {
		t.Fatalf("manuf=%q", info.Manufacturer)
	}
	if !info.IsTrusted {
		t.Fatal("trusted must flag")
	}
	if !info.IsConnected {
		t.Fatal("connected must flag")
	}
	if info.IsBlocked {
		t.Fatal("not blocked")
	}
}

func TestParseBlueZInfoBLE(t *testing.T) {
	body := []byte(`[General]
Name=Apple Watch
Alias=Alice's Apple Watch
AddressType=static
Trusted=true

[ConnectionParameters]
MinInterval=12
MaxInterval=24
`)
	info := ParseBlueZInfo(body)
	if !info.IsBLE {
		t.Fatal("static address-type must flag BLE")
	}
}

func TestParseBlueZInfoEmpty(t *testing.T) {
	info := ParseBlueZInfo(nil)
	if info.Name != "" || info.Class != 0 {
		t.Fatalf("empty must yield zero: %+v", info)
	}
}

func TestDeviceMACFromPath(t *testing.T) {
	a, d := DeviceMACFromPath(
		"/var/lib/bluetooth/AA:BB:CC:DD:EE:FF/11:22:33:44:55:66/info",
	)
	if a != "AA:BB:CC:DD:EE:FF" {
		t.Fatalf("adapter=%q", a)
	}
	if d != "11:22:33:44:55:66" {
		t.Fatalf("device=%q", d)
	}

	a, d = DeviceMACFromPath("/var/lib/bluetooth/AA:BB:CC:DD:EE:FF/")
	if a != "AA:BB:CC:DD:EE:FF" || d != "" {
		t.Fatalf("expected (adapter, empty), got (%q, %q)", a, d)
	}

	a, d = DeviceMACFromPath("/no/macs/here")
	if a != "" || d != "" {
		t.Fatalf("expected empty, got (%q, %q)", a, d)
	}
}

func TestSortRows(t *testing.T) {
	in := []Row{
		{Source: SourceLinuxBlueZ, AdapterMAC: "BB", DeviceMAC: "22"},
		{Source: SourceMacOSPlist, AdapterMAC: "AA", DeviceMAC: "11"},
		{Source: SourceLinuxBlueZ, AdapterMAC: "AA", DeviceMAC: "11"},
	}
	SortRows(in)
	if in[0].Source != SourceLinuxBlueZ || in[0].AdapterMAC != "AA" {
		t.Fatalf("first=%+v want bluez/AA", in[0])
	}
}
