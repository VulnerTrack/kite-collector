package wireguard

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPinnedSectionKindStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(SectionInterface), "interface"},
		{string(SectionPeer), "peer"},
		{string(SectionUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("section_kind drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestHashContentsDeterministic(t *testing.T) {
	a := HashContents([]byte("[Interface]\nAddress = 10.0.0.1/24\n"))
	b := HashContents([]byte("[Interface]\nAddress = 10.0.0.1/24\n"))
	if a != b || len(a) != 64 {
		t.Fatalf("a=%q b=%q", a, b)
	}
}

func TestPublicKeyFingerprintStableAndNonSecret(t *testing.T) {
	key := "abcdefABCDEFabcdefABCDEFabcdefABCDEFabcdefABC="
	a := PublicKeyFingerprint(key)
	b := PublicKeyFingerprint(key)
	if a != b {
		t.Fatalf("non-deterministic: %q vs %q", a, b)
	}
	if a == "" || strings.Contains(a, "=") {
		t.Fatalf("fingerprint should be hex prefix, not base64 key: %q", a)
	}
	if PublicKeyFingerprint("") != "" {
		t.Fatal("empty key must produce empty fingerprint")
	}
}

func TestIsFullTrafficRoute(t *testing.T) {
	hit := []string{
		"0.0.0.0/0",
		"::/0",
		"10.0.0.0/24, 0.0.0.0/0",
		"  ::/0  , 10.0.0.0/24",
	}
	for _, s := range hit {
		if !IsFullTrafficRoute(s) {
			t.Fatalf("%q must flag full-traffic", s)
		}
	}
	miss := []string{
		"10.0.0.0/24",
		"192.168.1.0/24, 172.16.0.0/12",
		"",
	}
	for _, s := range miss {
		if IsFullTrafficRoute(s) {
			t.Fatalf("%q must NOT flag full-traffic", s)
		}
	}
}

func TestEncodeStringList(t *testing.T) {
	if EncodeStringList(nil) != "[]" {
		t.Fatal("nil")
	}
	if got := EncodeStringList([]string{"postup: x"}); got != `["postup: x"]` {
		t.Fatalf("got %q", got)
	}
}

// -- AnnotateSecurity end-to-end -------------------------------------

func TestAnnotatePrivateKeyExposureViaMode(t *testing.T) {
	t1 := Tunnel{SectionKind: SectionInterface, HasPrivateKey: true, FileMode: 0o644}
	AnnotateSecurity(&t1)
	if !t1.IsFileWorldReadable {
		t.Fatal("0o644 must flag world-readable")
	}
	if !t1.HasPrivateKeyExposed {
		t.Fatal("private key + world-readable = exposed")
	}

	t2 := Tunnel{SectionKind: SectionInterface, HasPrivateKey: true, FileMode: 0o640}
	AnnotateSecurity(&t2)
	if !t2.IsFileGroupReadable || t2.IsFileWorldReadable {
		t.Fatalf("0o640 group-only flags wrong: %+v", t2)
	}
	if !t2.HasPrivateKeyExposed {
		t.Fatal("private key + group-readable = exposed")
	}

	t3 := Tunnel{SectionKind: SectionInterface, HasPrivateKey: true, FileMode: 0o600}
	AnnotateSecurity(&t3)
	if t3.IsFileWorldReadable || t3.IsFileGroupReadable {
		t.Fatalf("0o600 must be clean: %+v", t3)
	}
	if t3.HasPrivateKeyExposed {
		t.Fatal("0o600 must NOT flag exposed")
	}
}

func TestAnnotateMissingPresharedKeyOnPeerOnly(t *testing.T) {
	peer := Tunnel{SectionKind: SectionPeer, HasPresharedKey: false}
	AnnotateSecurity(&peer)
	if !peer.IsMissingPresharedKey {
		t.Fatal("peer without PSK must flag")
	}

	iface := Tunnel{SectionKind: SectionInterface, HasPresharedKey: false}
	AnnotateSecurity(&iface)
	if iface.IsMissingPresharedKey {
		t.Fatal("[Interface] never carries PSK; must NOT flag")
	}
}

func TestAnnotateFullTrafficRouteFlag(t *testing.T) {
	p := Tunnel{SectionKind: SectionPeer, AllowedIPs: "0.0.0.0/0, ::/0"}
	AnnotateSecurity(&p)
	if !p.IsFullTrafficRoute {
		t.Fatal("0.0.0.0/0 must flag full-traffic")
	}
}

func TestAnnotateShellHookFlag(t *testing.T) {
	iface := Tunnel{
		SectionKind: SectionInterface,
		ShellHooks:  []string{"postup: iptables -A FORWARD -i %i -j ACCEPT"},
	}
	AnnotateSecurity(&iface)
	if !iface.HasShellHook {
		t.Fatal("ShellHooks present must flag")
	}
}

// -- Parse end-to-end ----------------------------------------------

func TestParseTypicalTunnel(t *testing.T) {
	body := []byte(`# /etc/wireguard/wg0.conf
[Interface]
PrivateKey = abcdefABCDEFabcdefABCDEFabcdefABCDEFabcdefAB=
Address = 10.0.0.1/24
ListenPort = 51820
DNS = 10.0.0.53
PostUp = iptables -A FORWARD -i %i -j ACCEPT
PostDown = iptables -D FORWARD -i %i -j ACCEPT

[Peer]
# alice — laptop
PublicKey = AlicePubKeyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
PresharedKey = SharedSecretXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX=
AllowedIPs = 10.0.0.2/32
Endpoint = alice.corp:51820

[Peer]
# bob — site-to-site, full tunnel
PublicKey = BobPubKeyBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
`)
	got := Parse(body, "/etc/wireguard/wg0.conf")
	if len(got) != 3 {
		t.Fatalf("rows=%d, want 3: %+v", len(got), got)
	}

	iface := got[0]
	if iface.SectionKind != SectionInterface {
		t.Fatalf("first row kind=%q", iface.SectionKind)
	}
	if iface.TunnelName != "wg0" {
		t.Fatalf("tunnel_name=%q", iface.TunnelName)
	}
	if !iface.HasPrivateKey {
		t.Fatal("PrivateKey present must flag")
	}
	if iface.Address != "10.0.0.1/24" {
		t.Fatalf("address=%q", iface.Address)
	}
	if iface.ListenPort != 51820 {
		t.Fatalf("listen_port=%d", iface.ListenPort)
	}
	if !iface.HasShellHook || len(iface.ShellHooks) != 2 {
		t.Fatalf("shell hooks: %+v", iface.ShellHooks)
	}

	alice := got[1]
	if alice.SectionKind != SectionPeer || alice.SectionIndex != 1 {
		t.Fatalf("alice section: %+v", alice)
	}
	if !alice.HasPresharedKey || alice.IsMissingPresharedKey {
		t.Fatal("alice has PSK; must NOT flag missing")
	}
	if alice.IsFullTrafficRoute {
		t.Fatal("alice is 10.0.0.2/32; must NOT flag full-traffic")
	}
	if alice.PeerPublicKeyFingerprint == "" {
		t.Fatal("PublicKey fingerprint must be set")
	}

	bob := got[2]
	if bob.SectionIndex != 2 {
		t.Fatalf("bob index=%d", bob.SectionIndex)
	}
	if !bob.IsMissingPresharedKey {
		t.Fatal("bob has no PSK; must flag missing")
	}
	if !bob.IsFullTrafficRoute {
		t.Fatal("bob 0.0.0.0/0 must flag full-traffic")
	}
	if bob.PersistentKeepaliveSeconds != 25 || !bob.HasPersistentKeepalive {
		t.Fatalf("keepalive: %+v", bob)
	}
}

func TestParseSkipsHashCommentsAndBlanks(t *testing.T) {
	body := []byte(`# top comment

[Interface]
   # indented comment
Address = 10.0.0.1/24
`)
	got := Parse(body, "x.conf")
	if len(got) != 1 || got[0].Address != "10.0.0.1/24" {
		t.Fatalf("got: %+v", got)
	}
}

func TestParseFingerprintsIfaceAndPeerSeparately(t *testing.T) {
	body := []byte(`[Interface]
PrivateKey = privX=
PublicKey = ifacePubKeyXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX=

[Peer]
PublicKey = peerPubKeyXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX=
AllowedIPs = 10.0.0.2/32
`)
	got := Parse(body, "x.conf")
	if got[0].PublicKeyFingerprint == "" {
		t.Fatal("interface PublicKey must fingerprint")
	}
	if got[1].PeerPublicKeyFingerprint == "" {
		t.Fatal("peer PublicKey must fingerprint")
	}
	if got[0].PublicKeyFingerprint == got[1].PeerPublicKeyFingerprint {
		t.Fatal("distinct keys must produce distinct fingerprints")
	}
}

func TestParseHonoursMaxRows(t *testing.T) {
	var sb strings.Builder
	for i := 0; i < MaxRows+50; i++ {
		sb.WriteString("[Peer]\nAllowedIPs = 10.0.0.0/32\n")
	}
	got := Parse([]byte(sb.String()), "x.conf")
	if len(got) > MaxRows {
		t.Fatalf("got %d > MaxRows %d", len(got), MaxRows)
	}
}

// -- collector end-to-end -------------------------------------------

func TestFileCollectorWalksDirAndCarriesFileMode(t *testing.T) {
	tmp := t.TempDir()
	confPath := filepath.Join(tmp, "wg0.conf")
	must(t, os.WriteFile(confPath, []byte(`[Interface]
PrivateKey = privX=
Address = 10.0.0.1/24
`), 0o644))
	// Should be skipped — non-.conf extension.
	must(t, os.WriteFile(filepath.Join(tmp, "wg0.conf.bak"),
		[]byte(`[Interface]
PrivateKey = leaky=
`), 0o644))

	c := &fileCollector{
		dirs:     []string{tmp},
		readFile: os.ReadFile,
		readDir:  os.ReadDir,
		statFile: os.Stat,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 (only .conf), got %d: %+v", len(got), got)
	}
	row := got[0]
	if row.FileMode == 0 {
		t.Fatal("FileMode must propagate from stat")
	}
	if !row.IsFileWorldReadable {
		t.Fatal("0o644 must flag world-readable")
	}
	if !row.HasPrivateKeyExposed {
		t.Fatal("PrivateKey + 0o644 = exposed")
	}
}

func TestFileCollectorMissingDirsOK(t *testing.T) {
	c := &fileCollector{
		dirs:     []string{"/nope-a", "/nope-b"},
		readFile: os.ReadFile,
		readDir:  os.ReadDir,
		statFile: os.Stat,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("missing must not error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want empty, got %d", len(got))
	}
}

// -- SortTunnels -----------------------------------------------------

func TestSortTunnelsDeterministic(t *testing.T) {
	in := []Tunnel{
		{FilePath: "/etc/wireguard/wg1.conf", SectionIndex: 0},
		{FilePath: "/etc/wireguard/wg0.conf", SectionIndex: 2},
		{FilePath: "/etc/wireguard/wg0.conf", SectionIndex: 1},
		{FilePath: "/etc/wireguard/wg0.conf", SectionIndex: 0},
	}
	SortTunnels(in)
	if in[0].FilePath != "/etc/wireguard/wg0.conf" || in[0].SectionIndex != 0 {
		t.Fatalf("first=%+v", in[0])
	}
	if in[3].FilePath != "/etc/wireguard/wg1.conf" {
		t.Fatalf("last=%+v", in[3])
	}
}

// -- helpers --------------------------------------------------------

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
