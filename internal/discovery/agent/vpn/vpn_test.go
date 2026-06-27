package vpn

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPinnedEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(TypeWireGuard), "wireguard"},
		{string(TypeOpenVPN), "openvpn"},
		{string(TypeIPSec), "ipsec"},
		{string(TypeStrongSwan), "strongswan"},
		{string(TypeLibreSwan), "libreswan"},
		{string(TypeTailscale), "tailscale"},
		{string(TypeZeroTier), "zerotier"},
		{string(TypeNebula), "nebula"},
		{string(TypeNetBird), "netbird"},
		{string(TypeWindowsBuiltin), "windows-builtin"},
		{string(TypeMacOSBuiltin), "macos-builtin"},
		{string(TypeCiscoAnyConnect), "cisco-anyconnect"},
		{string(TypeFortinet), "fortinet"},
		{string(TypePulse), "pulse"},
		{string(TypeUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q (breaks SQLite CHECK)",
				p.got, p.want)
		}
	}
}

func TestEncodeStringList(t *testing.T) {
	if got := EncodeStringList(nil); got != "[]" {
		t.Fatalf("nil = %q", got)
	}
	if got := EncodeStringList([]string{"10.0.0.0/8", "192.168.0.0/16"}); got != `["10.0.0.0/8","192.168.0.0/16"]` {
		t.Fatalf("got %q", got)
	}
}

func TestIsDefaultRoute(t *testing.T) {
	defaults := []string{"0.0.0.0/0", "::/0", "*", " 0.0.0.0/0 "}
	for _, s := range defaults {
		if !IsDefaultRoute(s) {
			t.Fatalf("%q must be default route", s)
		}
	}
	scoped := []string{
		"", "10.0.0.0/8", "192.168.1.0/24", "fd00::/8", "1.2.3.4/32",
	}
	for _, s := range scoped {
		if IsDefaultRoute(s) {
			t.Fatalf("%q must NOT be default route", s)
		}
	}
}

func TestHasFullTunnel(t *testing.T) {
	if !HasFullTunnel([]string{"10.0.0.0/8", "0.0.0.0/0"}) {
		t.Fatal("any default route must trigger")
	}
	if HasFullTunnel([]string{"10.0.0.0/8", "192.168.0.0/16"}) {
		t.Fatal("scoped routes must not trigger")
	}
	if HasFullTunnel(nil) {
		t.Fatal("nil must not trigger")
	}
}

func TestSortProfilesDeterministic(t *testing.T) {
	in := []Profile{
		{Type: TypeWireGuard, ConfigPath: "/z.conf", Name: "z"},
		{Type: TypeOpenVPN, ConfigPath: "/a.conf", Name: "a"},
		{Type: TypeWireGuard, ConfigPath: "/a.conf", Name: "a"},
	}
	SortProfiles(in)
	want := []struct {
		t Type
		p string
		n string
	}{
		{TypeOpenVPN, "/a.conf", "a"},
		{TypeWireGuard, "/a.conf", "a"},
		{TypeWireGuard, "/z.conf", "z"},
	}
	for i, p := range in {
		if p.Type != want[i].t || p.ConfigPath != want[i].p || p.Name != want[i].n {
			t.Fatalf("pos %d: got (%q,%q,%q)", i, p.Type, p.ConfigPath, p.Name)
		}
	}
}

// -- WireGuard parser ---------------------------------------------------

const wgFullTunnel = `# /etc/wireguard/wg0.conf
[Interface]
PrivateKey = aB3Z+xz1xxx=
Address    = 10.66.66.2/24
DNS        = 1.1.1.1, 1.0.0.1
MTU        = 1420
ListenPort = 51820

[Peer]
PublicKey           = PEER_PUBKEY_BASE64
PresharedKey        = PSK_BASE64
AllowedIPs          = 0.0.0.0/0, ::/0
Endpoint            = vpn.example.com:51820
PersistentKeepalive = 25
`

const wgSplitTunnel = `[Interface]
PrivateKey = key
Address    = 10.0.0.5/24

[Peer]
PublicKey  = peer
AllowedIPs = 10.0.0.0/8, 192.168.1.0/24
Endpoint   = peer.example:443
`

func TestParseWireGuardFullTunnel(t *testing.T) {
	p, ok := parseWireGuardConfig(wgFullTunnel)
	if !ok {
		t.Fatal("parse failed")
	}
	if !p.PrivateKeyPresent {
		t.Fatal("private key must be flagged")
	}
	if !p.PresharedKeyPresent {
		t.Fatal("preshared key must be flagged")
	}
	if !p.IsFullTunnel {
		t.Fatal("AllowedIPs contains 0.0.0.0/0 → must be full tunnel")
	}
	if p.MTU != 1420 {
		t.Fatalf("mtu=%d", p.MTU)
	}
	if p.Endpoint != "vpn.example.com:51820" {
		t.Fatalf("endpoint=%q", p.Endpoint)
	}
	if p.Port != 51820 {
		t.Fatalf("port=%d", p.Port)
	}
	if p.Protocol != "udp" {
		t.Fatalf("WG protocol must be udp")
	}
	if len(p.DNSServers) != 2 {
		t.Fatalf("dns servers=%v", p.DNSServers)
	}
}

func TestParseWireGuardSplitTunnel(t *testing.T) {
	p, ok := parseWireGuardConfig(wgSplitTunnel)
	if !ok {
		t.Fatal("parse failed")
	}
	if p.IsFullTunnel {
		t.Fatal("only scoped CIDRs → must NOT be full tunnel")
	}
	if len(p.RoutedSubnets) != 2 {
		t.Fatalf("subnets=%v", p.RoutedSubnets)
	}
}

func TestParseWireGuardRejectsNoInterface(t *testing.T) {
	_, ok := parseWireGuardConfig(`[Peer]
PublicKey = x
`)
	if ok {
		t.Fatal("config without [Interface] must be rejected")
	}
}

func TestSplitHostPort(t *testing.T) {
	cases := []struct {
		in       string
		wantHost string
		wantPort int
	}{
		{"vpn.example.com:51820", "vpn.example.com", 51820},
		{"1.2.3.4:443", "1.2.3.4", 443},
		{"[2001:db8::1]:1234", "2001:db8::1", 1234},
		{"bare-host", "", 0},
	}
	for _, tc := range cases {
		h, p := splitHostPort(tc.in)
		if h != tc.wantHost || p != tc.wantPort {
			t.Fatalf("splitHostPort(%q) = (%q, %d), want (%q, %d)",
				tc.in, h, p, tc.wantHost, tc.wantPort)
		}
	}
}

func TestWireGuardCollectorEndToEnd(t *testing.T) {
	tmp := t.TempDir()
	mustWrite(t, filepath.Join(tmp, "wg0.conf"), wgFullTunnel)
	mustWrite(t, filepath.Join(tmp, "wg1.conf"), wgSplitTunnel)
	mustWrite(t, filepath.Join(tmp, "README"), "skip me")
	mustWrite(t, filepath.Join(tmp, ".hidden.conf"), "[Interface]\nPrivateKey = k\n")

	c := &wireguardCollector{
		confDir:  tmp,
		readFile: os.ReadFile,
		readDir: func(p string) ([]os.DirEntry, error) {
			if p == tmp {
				return os.ReadDir(p)
			}
			return nil, errors.New("not found")
		},
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	// 3 .conf files (wg0, wg1, .hidden) — README is filtered out.
	if len(got) != 3 {
		t.Fatalf("want 3 profiles, got %d", len(got))
	}
	for _, p := range got {
		if p.Type != TypeWireGuard {
			t.Fatalf("type not stamped: %q", p.Type)
		}
		if p.Protocol != "udp" {
			t.Fatalf("WG must be udp, got %q", p.Protocol)
		}
	}
}

func TestWireGuardCollectorMissingDirReturnsEmpty(t *testing.T) {
	c := &wireguardCollector{
		confDir:  "/does/not/exist",
		readFile: os.ReadFile,
		readDir:  func(string) ([]os.DirEntry, error) { return nil, os.ErrNotExist },
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("missing dir must not error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want 0, got %d", len(got))
	}
}

// -- OpenVPN parser -----------------------------------------------------

const ovpnFullTunnel = `# Sample OpenVPN client config
client
dev tun
proto udp
remote vpn.example.com 1194
resolv-retry infinite
nobind
persist-key
persist-tun
redirect-gateway def1 bypass-dhcp
dhcp-option DNS 1.1.1.1
dhcp-option DNS 1.0.0.1
ca ca.crt
cert client.crt
key client.key
tls-auth ta.key 1
auth-user-pass /etc/openvpn/credentials.txt
tun-mtu 1500
`

const ovpnSplitTunnel = `client
dev tun
proto tcp
remote prod.example.com 443
route 10.0.0.0 255.0.0.0
route 192.168.1.0 255.255.255.0
ca ca.crt
cert client.crt
<key>
-----BEGIN PRIVATE KEY-----
inline-key-here
-----END PRIVATE KEY-----
</key>
`

func TestParseOpenVPNFullTunnel(t *testing.T) {
	p, ok := parseOpenVPNConfig(ovpnFullTunnel)
	if !ok {
		t.Fatal("parse failed")
	}
	if p.Protocol != "udp" {
		t.Fatalf("proto=%q", p.Protocol)
	}
	if p.Endpoint != "vpn.example.com:1194" {
		t.Fatalf("endpoint=%q", p.Endpoint)
	}
	if p.Port != 1194 {
		t.Fatalf("port=%d", p.Port)
	}
	if !p.IsFullTunnel {
		t.Fatal("redirect-gateway must flag full tunnel")
	}
	if !p.PrivateKeyPresent {
		t.Fatal("key directive must flag private key")
	}
	if !p.PresharedKeyPresent {
		t.Fatal("tls-auth must flag preshared key")
	}
	if len(p.DNSServers) != 2 {
		t.Fatalf("dns=%v", p.DNSServers)
	}
	if p.MTU != 1500 {
		t.Fatalf("mtu=%d", p.MTU)
	}
}

func TestParseOpenVPNSplitTunnelInlineKey(t *testing.T) {
	p, ok := parseOpenVPNConfig(ovpnSplitTunnel)
	if !ok {
		t.Fatal("parse failed")
	}
	if p.IsFullTunnel {
		t.Fatal("split tunnel: scoped routes only")
	}
	if !p.PrivateKeyPresent {
		t.Fatal("inline <key>...</key> must flag private key")
	}
	if p.Protocol != "tcp" {
		t.Fatalf("proto=%q", p.Protocol)
	}
	// Routes converted to CIDR by maskToPrefix:
	wantRoutes := []string{"10.0.0.0/8", "192.168.1.0/24"}
	if len(p.RoutedSubnets) != 2 {
		t.Fatalf("routes=%v", p.RoutedSubnets)
	}
	for i, r := range p.RoutedSubnets {
		if r != wantRoutes[i] {
			t.Fatalf("route[%d]=%q, want %q", i, r, wantRoutes[i])
		}
	}
}

func TestParseOpenVPNRejectsServerConfig(t *testing.T) {
	_, ok := parseOpenVPNConfig(`server
dev tun
remote whatever 443
`)
	if ok {
		t.Fatal("non-client config must be rejected")
	}
}

func TestMaskToPrefix(t *testing.T) {
	cases := map[string]string{
		"255.0.0.0":       "8",
		"255.255.0.0":     "16",
		"255.255.255.0":   "24",
		"255.255.255.255": "32",
		"0.0.0.0":         "0",
		"bogus":           "",
		"255.255.0":       "",
	}
	for mask, want := range cases {
		if got := maskToPrefix(mask); got != want {
			t.Fatalf("maskToPrefix(%q) = %q, want %q", mask, got, want)
		}
	}
}

// -- chain --------------------------------------------------------------

func TestChainCollectorSkipsErrors(t *testing.T) {
	good := stubCollector{out: []Profile{{Type: TypeWireGuard, Name: "wg0", ConfigPath: "/x"}}}
	bad := stubCollector{err: errors.New("boom")}
	chain := &chainCollector{collectors: []Collector{good, bad, good}}

	got, err := chain.Collect(context.Background())
	if err != nil {
		t.Fatalf("chain Collect: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 (good × 2), got %d", len(got))
	}
}

// -- helpers ------------------------------------------------------------

type stubCollector struct {
	err error
	out []Profile
}

func (s stubCollector) Name() string { return "stub" }
func (s stubCollector) Collect(_ context.Context) ([]Profile, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.out, nil
}

func mustWrite(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// Silence "imported and not used" if test set evolves.
var (
	_ = filepath.Join
	_ = time.Now
	_ fs.DirEntry
)
