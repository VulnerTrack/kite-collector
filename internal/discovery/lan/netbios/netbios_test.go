package netbios

import (
	"encoding/binary"
	"net"
	"strings"
	"testing"

	"github.com/vulnertrack/kite-collector/internal/model"
)

func TestEncodeDecodeNetBIOSNameRoundTrip(t *testing.T) {
	var raw [16]byte
	copy(raw[:], "KITE-DEV       \x00")
	enc := encodeNetBIOSName(raw[:])
	if len(enc) != 34 {
		t.Fatalf("encoded length = %d, want 34", len(enc))
	}
	if enc[0] != 0x20 {
		t.Fatalf("first byte must be 0x20, got 0x%02x", enc[0])
	}
	if enc[33] != 0x00 {
		t.Fatalf("last byte must be 0x00, got 0x%02x", enc[33])
	}
	dec, n, err := decodeNetBIOSName(enc, 0)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if n != 34 {
		t.Fatalf("consumed=%d, want 34", n)
	}
	if dec != raw {
		t.Fatalf("round trip mismatch:\n got %q\nwant %q", string(dec[:]), string(raw[:]))
	}
}

func TestBuildNBSTATQueryShape(t *testing.T) {
	q := buildNBSTATQuery(0xCAFE)
	if len(q) != 50 {
		t.Fatalf("len=%d, want 50", len(q))
	}
	if got := binary.BigEndian.Uint16(q[0:2]); got != 0xCAFE {
		t.Fatalf("xid=0x%04x, want 0xCAFE", got)
	}
	if got := binary.BigEndian.Uint16(q[4:6]); got != 1 {
		t.Fatalf("qdcount=%d, want 1", got)
	}
	if got := binary.BigEndian.Uint16(q[46:48]); got != qtypeNBSTAT {
		t.Fatalf("qtype=0x%04x, want 0x0021", got)
	}
	if got := binary.BigEndian.Uint16(q[48:50]); got != qclassIN {
		t.Fatalf("qclass=0x%04x, want 0x0001", got)
	}
	// Name section begins at offset 12 with the length byte.
	if q[12] != 0x20 {
		t.Fatalf("name length byte=0x%02x, want 0x20", q[12])
	}
	if q[12+33] != 0x00 {
		t.Fatalf("name terminator=0x%02x, want 0x00", q[12+33])
	}
	// First raw byte of the name should be '*' (0x2A), which encodes to 0x43 0x4B.
	if q[13] != 0x43 || q[14] != 0x4B {
		t.Fatalf("wildcard name not encoded: %02x %02x", q[13], q[14])
	}
}

func TestParseNBSTATResponse(t *testing.T) {
	// Hand-build a synthetic NBSTAT response.
	resp := buildSyntheticNBSTATResponse(t)
	r, err := parseNBSTAT(resp, net.ParseIP("192.168.1.50"))
	if err != nil {
		t.Fatalf("parseNBSTAT: %v", err)
	}
	if r.machine != "KITE-DEV" {
		t.Fatalf("machine=%q, want KITE-DEV", r.machine)
	}
	if r.workgroup != "WORKGROUP" {
		t.Fatalf("workgroup=%q, want WORKGROUP", r.workgroup)
	}
	if r.mac != "00:11:22:33:44:55" {
		t.Fatalf("mac=%q, want 00:11:22:33:44:55", r.mac)
	}
	if len(r.services) != 3 {
		t.Fatalf("services=%v, want 3 entries", r.services)
	}
}

func TestParseRejectsNonResponse(t *testing.T) {
	q := buildNBSTATQuery(0x4242)
	if _, err := parseNBSTAT(q, net.ParseIP("127.0.0.1")); err == nil {
		t.Fatalf("query must not parse as response")
	}
}

func TestSubnetBroadcast(t *testing.T) {
	cases := []struct {
		ip   string
		mask string
		want string
	}{
		{"192.168.1.10", "255.255.255.0", "192.168.1.255"},
		{"10.0.0.5", "255.255.0.0", "10.0.255.255"},
		{"172.16.0.1", "255.255.255.252", "172.16.0.3"},
	}
	for _, tc := range cases {
		ip := net.ParseIP(tc.ip).To4()
		mask := net.IPMask(net.ParseIP(tc.mask).To4())
		got := subnetBroadcast(ip, mask).String()
		if got != tc.want {
			t.Fatalf("subnetBroadcast(%s,%s)=%s, want %s", tc.ip, tc.mask, got, tc.want)
		}
	}
}

func TestClassifyPrecedence(t *testing.T) {
	cases := []struct {
		name     string
		want     model.AssetType
		services []string
	}{
		{"file server suffix 0x20 → server", model.AssetTypeServer, []string{"KITE<20>"}},
		{"domain master 0x1b → server", model.AssetTypeServer, []string{"KITE<00>", "WORKGROUP<1b>"}},
		{"domain group 0x1c → server", model.AssetTypeServer, []string{"WORKGROUP<1c>"}},
		{"plain workstation", model.AssetTypeWorkstation, []string{"KITE<00>", "WORKGROUP<00>"}},
		{"empty fallback", model.AssetTypeWorkstation, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classify(tc.services); got != tc.want {
				t.Fatalf("classify(%v)=%v, want %v", tc.services, got, tc.want)
			}
		})
	}
}

func TestAssetsFromRespondersDeterministicAndKeyed(t *testing.T) {
	in := map[string]*responder{
		"192.168.1.50": {
			addr:      net.ParseIP("192.168.1.50"),
			machine:   "KITE-DEV",
			workgroup: "WORKGROUP",
			mac:       "00:11:22:33:44:55",
			services:  []string{"KITE-DEV<00>", "WORKGROUP<00>", "KITE-DEV<20>"},
		},
		"192.168.1.10": {
			addr:      net.ParseIP("192.168.1.10"),
			machine:   "LAPTOP",
			workgroup: "WORKGROUP",
			services:  []string{"LAPTOP<00>", "WORKGROUP<00>"},
		},
	}
	out := assetsFromResponders(in)
	if len(out) != 2 {
		t.Fatalf("want 2 assets, got %d", len(out))
	}
	if out[0].Hostname != "LAPTOP" {
		t.Fatalf("first asset hostname=%q (sort by ip key)", out[0].Hostname)
	}
	if out[0].AssetType != model.AssetTypeWorkstation {
		t.Fatalf("laptop should be workstation, got %v", out[0].AssetType)
	}
	if out[1].AssetType != model.AssetTypeServer {
		t.Fatalf("file server (<20>) should be server, got %v", out[1].AssetType)
	}
	if out[1].DiscoverySource != "netbios" {
		t.Fatalf("source not stamped: %q", out[1].DiscoverySource)
	}
	if !strings.Contains(out[1].Tags, `"nbns_mac":"00:11:22:33:44:55"`) {
		t.Fatalf("mac missing from tags: %s", out[1].Tags)
	}
	if !strings.Contains(out[1].Tags, `"nbns_workgroup":"WORKGROUP"`) {
		t.Fatalf("workgroup missing: %s", out[1].Tags)
	}
	if out[1].NaturalKey == "" {
		t.Fatalf("natural key not computed")
	}
}

func TestParseConfigClampsWindow(t *testing.T) {
	c := parseConfig(map[string]any{"listen_window": "999s"})
	if c.ListenWindow != maxListenWin {
		t.Fatalf("listen_window not clamped: %v", c.ListenWindow)
	}
}

func TestBuildDestinationsExplicitOnly(t *testing.T) {
	dests, err := buildDestinations(Config{
		Targets:     []string{"10.0.0.5", "10.0.0.6", "::1", "bogus"},
		NoBroadcast: true,
	})
	if err != nil {
		t.Fatalf("buildDestinations: %v", err)
	}
	if len(dests) != 2 {
		t.Fatalf("want 2 ipv4 targets (v6 + bogus skipped), got %d: %v", len(dests), dests)
	}
}

// buildSyntheticNBSTATResponse fabricates a wire-format NBSTAT answer with
// three names (KITE-DEV<00> unique workstation, WORKGROUP<00> group,
// KITE-DEV<20> unique file server) and a known MAC.
func buildSyntheticNBSTATResponse(t *testing.T) []byte {
	t.Helper()

	// Build RDATA first so we know the full message size before allocating.
	rdata := make([]byte, 0, 1+3*18+6+40)
	rdata = append(rdata, 0x03) // num names

	mkEntry := func(label string, suffix byte, group bool) {
		var n [16]byte
		copy(n[:], strings.Repeat(" ", 15))
		copy(n[:], label)
		if len(label) > 15 {
			panic("label too long for test")
		}
		n[15] = suffix
		rdata = append(rdata, n[:]...)
		var flags uint16
		if group {
			flags |= 0x8000
		}
		f := make([]byte, 2)
		binary.BigEndian.PutUint16(f, flags)
		rdata = append(rdata, f...)
	}
	mkEntry("KITE-DEV", 0x00, false)
	mkEntry("WORKGROUP", 0x00, true)
	mkEntry("KITE-DEV", 0x20, false)

	rdata = append(rdata, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55)
	rdata = append(rdata, make([]byte, 40)...) // stats padding

	var nameRaw [16]byte
	copy(nameRaw[:], "*               ")
	encName := encodeNetBIOSName(nameRaw[:])

	// Answer: name + type + class + ttl + rdlength + rdata.
	ansTail := make([]byte, 10)
	binary.BigEndian.PutUint16(ansTail[0:], qtypeNBSTAT)
	binary.BigEndian.PutUint16(ansTail[2:], qclassIN)
	binary.BigEndian.PutUint32(ansTail[4:], 0) // ttl
	// rdata length fits in uint16 by construction (3*18 + 47 = 101 bytes).
	binary.BigEndian.PutUint16(ansTail[8:], uint16(len(rdata))) //#nosec G115 -- bounded test payload
	ans := make([]byte, 0, len(encName)+len(ansTail)+len(rdata))
	ans = append(ans, encName...)
	ans = append(ans, ansTail...)
	ans = append(ans, rdata...)

	// 12-byte NBNS header.
	out := make([]byte, 12, 12+len(ans))
	binary.BigEndian.PutUint16(out[0:], 0xCAFE) // xid
	binary.BigEndian.PutUint16(out[2:], 0x8400) // response, authoritative
	binary.BigEndian.PutUint16(out[4:], 0)      // qdcount
	binary.BigEndian.PutUint16(out[6:], 1)      // ancount
	binary.BigEndian.PutUint16(out[8:], 0)
	binary.BigEndian.PutUint16(out[10:], 0)
	return append(out, ans...)
}
