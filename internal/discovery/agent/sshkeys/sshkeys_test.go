package sshkeys

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPinnedEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(RoleAuthorized), "authorized"},
		{string(RoleIdentityPublic), "identity-public"},
		{string(RoleIdentityPrivate), "identity-private"},
		{string(RoleKnownHost), "known-host"},
		{string(RoleHostKey), "host-key"},
		{string(RoleUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q (breaks SQLite CHECK)",
				p.got, p.want)
		}
	}
}

func TestFingerprintBlobIsOpenSSHCompatible(t *testing.T) {
	// Known fixture: trivial 4-byte blob "abcd".
	sha, md := FingerprintBlob([]byte("abcd"))
	// sha256("abcd") = 88d4266fd4e6338d13b845fcf289579d209c897823b9217da3e161936f031589
	// base64 unpadded = iNQmb9TmM40TuEX88olXnSCciXgjuSF9o+Fhk28DFYk
	if sha != "iNQmb9TmM40TuEX88olXnSCciXgjuSF9o+Fhk28DFYk" {
		t.Fatalf("sha256 fp = %q", sha)
	}
	// md5("abcd") = e2fc714c4727ee9395f324cd2e7f331f
	if md != "e2fc714c4727ee9395f324cd2e7f331f" {
		t.Fatalf("md5 fp = %q", md)
	}
}

func TestIsWeakKeyType(t *testing.T) {
	cases := []struct {
		kt   string
		bits int
		want bool
	}{
		{"ssh-dss", 1024, true},  // DSA always weak
		{"ssh-dss", 0, true},     // DSA always weak even without bit count
		{"ssh-rsa", 1024, true},  // RSA < 2048 weak
		{"ssh-rsa", 2048, false}, // boundary
		{"ssh-rsa", 4096, false},
		{"rsa-sha2-256", 1024, true},
		{"ssh-ed25519", 0, false}, // ed25519 strong; 0 bits is normal for fixed-size
		{"ecdsa-sha2-nistp256", 0, false},
		{"sk-ssh-ed25519@openssh.com", 0, false},
	}
	for _, tc := range cases {
		if got := IsWeakKeyType(tc.kt, tc.bits); got != tc.want {
			t.Fatalf("IsWeakKeyType(%q, %d) = %v, want %v",
				tc.kt, tc.bits, got, tc.want)
		}
	}
}

func TestSortKeysDeterministic(t *testing.T) {
	in := []Key{
		{Role: RoleKnownHost, SourcePath: "/x", LineNo: 2, FingerprintSHA256: "z"},
		{Role: RoleAuthorized, SourcePath: "/y", LineNo: 1, FingerprintSHA256: "a"},
		{Role: RoleAuthorized, SourcePath: "/y", LineNo: 1, FingerprintSHA256: "b"},
	}
	SortKeys(in)
	// authorized < known-host; within same path+line, sort by fingerprint.
	if in[0].Role != RoleAuthorized || in[0].FingerprintSHA256 != "a" {
		t.Fatalf("first: %+v", in[0])
	}
	if in[1].Role != RoleAuthorized || in[1].FingerprintSHA256 != "b" {
		t.Fatalf("second: %+v", in[1])
	}
	if in[2].Role != RoleKnownHost {
		t.Fatalf("third: %+v", in[2])
	}
}

// -- ParseAuthorizedKeysLine -------------------------------------------

func TestParseAuthorizedKeysLineED25519NoOptions(t *testing.T) {
	blob := buildPublicKeyBlobED25519(t)
	b64 := base64.StdEncoding.EncodeToString(blob)
	line := "ssh-ed25519 " + b64 + " alice@laptop"

	kt, b, comment, opts, decoded, ok := ParseAuthorizedKeysLine(line)
	if !ok {
		t.Fatal("parse failed")
	}
	if kt != "ssh-ed25519" {
		t.Fatalf("kt=%q", kt)
	}
	if comment != "alice@laptop" {
		t.Fatalf("comment=%q", comment)
	}
	if opts != "" {
		t.Fatalf("options should be empty, got %q", opts)
	}
	if b != b64 || len(decoded) == 0 {
		t.Fatal("blob/decoded lost")
	}
}

func TestParseAuthorizedKeysLineWithOptions(t *testing.T) {
	blob := buildPublicKeyBlobED25519(t)
	b64 := base64.StdEncoding.EncodeToString(blob)
	line := `restrict,from="10.0.0.0/8",command="/usr/bin/rrsync /backup" ssh-ed25519 ` +
		b64 + " backup-bot"
	kt, _, comment, opts, _, ok := ParseAuthorizedKeysLine(line)
	if !ok {
		t.Fatal("parse failed")
	}
	if kt != "ssh-ed25519" {
		t.Fatalf("kt=%q", kt)
	}
	if comment != "backup-bot" {
		t.Fatalf("comment=%q", comment)
	}
	if !strings.HasPrefix(opts, "restrict,from=") {
		t.Fatalf("options lost: %q", opts)
	}
	if !strings.Contains(opts, `command="/usr/bin/rrsync /backup"`) {
		t.Fatalf("quoted-space command option lost: %q", opts)
	}
}

func TestParseAuthorizedKeysLineRejectsCommentAndEmpty(t *testing.T) {
	for _, line := range []string{"", "   ", "# this is a comment", "#"} {
		if _, _, _, _, _, ok := ParseAuthorizedKeysLine(line); ok {
			t.Fatalf("line %q must not parse", line)
		}
	}
}

func TestParseAuthorizedKeysLineRejectsKeyTypeMismatch(t *testing.T) {
	blob := buildPublicKeyBlobED25519(t)
	b64 := base64.StdEncoding.EncodeToString(blob)
	// Claim ssh-rsa but blob says ssh-ed25519 → reject.
	line := "ssh-rsa " + b64
	if _, _, _, _, _, ok := ParseAuthorizedKeysLine(line); ok {
		t.Fatal("must reject key_type/blob mismatch (forgery defence)")
	}
}

// -- ParseKnownHostsLine -----------------------------------------------

func TestParseKnownHostsLinePlain(t *testing.T) {
	blob := buildPublicKeyBlobED25519(t)
	b64 := base64.StdEncoding.EncodeToString(blob)
	line := "github.com,140.82.114.4 ssh-ed25519 " + b64

	host, kt, _, _, _, ok := ParseKnownHostsLine(line)
	if !ok {
		t.Fatal("parse failed")
	}
	if host != "github.com,140.82.114.4" {
		t.Fatalf("host=%q", host)
	}
	if kt != "ssh-ed25519" {
		t.Fatalf("kt=%q", kt)
	}
}

func TestParseKnownHostsLineHashed(t *testing.T) {
	blob := buildPublicKeyBlobED25519(t)
	b64 := base64.StdEncoding.EncodeToString(blob)
	line := "|1|hashedhostnamebytes= ssh-ed25519 " + b64

	host, _, _, _, _, ok := ParseKnownHostsLine(line)
	if !ok {
		t.Fatal("parse failed")
	}
	if host != "HASHED" {
		t.Fatalf("hashed host should normalise to HASHED, got %q", host)
	}
}

// -- KeyBitsFromBlob ---------------------------------------------------

func TestKeyBitsRSA(t *testing.T) {
	rsaPub := buildPublicKeyBlobRSA(t, 2048)
	if bits := KeyBitsFromBlob(rsaPub); bits != 2048 {
		t.Fatalf("rsa-2048 bits=%d", bits)
	}
}

func TestKeyBitsED25519(t *testing.T) {
	blob := buildPublicKeyBlobED25519(t)
	if bits := KeyBitsFromBlob(blob); bits != 256 {
		t.Fatalf("ed25519 bits=%d, want 256", bits)
	}
}

func TestKeyBitsTruncatedBlob(t *testing.T) {
	if bits := KeyBitsFromBlob([]byte{0, 0, 0, 5}); bits != 0 {
		t.Fatalf("truncated must return 0, got %d", bits)
	}
}

// -- PrivateKeyHasPassphrase -------------------------------------------

func TestPrivateKeyHasPassphraseOpenSSHUnprotected(t *testing.T) {
	body := buildOpenSSHKey(t, "none")
	has, ok := PrivateKeyHasPassphrase([]byte(body))
	if !ok {
		t.Fatal("format detection failed")
	}
	if has {
		t.Fatal("cipher=none must be flagged as unprotected")
	}
}

func TestPrivateKeyHasPassphraseOpenSSHEncrypted(t *testing.T) {
	body := buildOpenSSHKey(t, "aes256-ctr")
	has, ok := PrivateKeyHasPassphrase([]byte(body))
	if !ok {
		t.Fatal("format detection failed")
	}
	if !has {
		t.Fatal("cipher=aes256-ctr must be flagged as passphrase-protected")
	}
}

func TestPrivateKeyHasPassphrasePEMEncrypted(t *testing.T) {
	body := `-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,A0B1C2D3E4F500112233445566778899

abcdefBASE64BODYxxxxx==
-----END RSA PRIVATE KEY-----
`
	has, ok := PrivateKeyHasPassphrase([]byte(body))
	if !ok {
		t.Fatal("format detection failed")
	}
	if !has {
		t.Fatal("Proc-Type header must flag encrypted")
	}
}

func TestPrivateKeyHasPassphrasePEMUnencrypted(t *testing.T) {
	body := `-----BEGIN RSA PRIVATE KEY-----
abcdefBASE64BODYxxxxx==
-----END RSA PRIVATE KEY-----
`
	has, ok := PrivateKeyHasPassphrase([]byte(body))
	if !ok {
		t.Fatal("format detection failed")
	}
	if has {
		t.Fatal("no Proc-Type header → unencrypted")
	}
}

func TestPrivateKeyHasPassphraseUnknownFormat(t *testing.T) {
	_, ok := PrivateKeyHasPassphrase([]byte("not a key"))
	if ok {
		t.Fatal("garbage must fail format detection")
	}
}

// -- end-to-end fileCollector ----------------------------------------

func TestFileCollectorEndToEnd(t *testing.T) {
	tmp := t.TempDir()
	// Two users: alice (with authorized_keys + id_ed25519 + .pub), bob (just known_hosts).
	mustMkdir(t, filepath.Join(tmp, "alice", ".ssh"))
	mustMkdir(t, filepath.Join(tmp, "bob", ".ssh"))

	pubBlob := buildPublicKeyBlobED25519(t)
	pubLine := "ssh-ed25519 " + base64.StdEncoding.EncodeToString(pubBlob) + " alice@laptop"
	rsaBlob := buildPublicKeyBlobRSA(t, 1024) // weak by design
	rsaLine := "ssh-rsa " + base64.StdEncoding.EncodeToString(rsaBlob) + " legacy"

	mustWrite(t, filepath.Join(tmp, "alice", ".ssh", "authorized_keys"),
		pubLine+"\n"+rsaLine+"\n# trailing comment\n")
	mustWrite(t, filepath.Join(tmp, "alice", ".ssh", "id_ed25519.pub"), pubLine+"\n")
	mustWrite(t, filepath.Join(tmp, "alice", ".ssh", "id_ed25519"),
		buildOpenSSHKey(t, "none"))

	mustWrite(t, filepath.Join(tmp, "bob", ".ssh", "known_hosts"),
		"github.com ssh-ed25519 "+base64.StdEncoding.EncodeToString(pubBlob)+"\n"+
			"|1|hashed= ssh-ed25519 "+base64.StdEncoding.EncodeToString(pubBlob)+"\n")

	c := &fileCollector{
		homeRoots: []string{tmp},
		etcSSH:    filepath.Join(tmp, "no-etc-ssh"),
		readFile:  os.ReadFile,
		readDir:   os.ReadDir,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	by := map[string]int{}
	for _, k := range got {
		by[string(k.Role)]++
	}
	// 2 authorized + 1 identity-public + 1 identity-private + 2 known-host = 6
	if by[string(RoleAuthorized)] != 2 {
		t.Fatalf("authorized count=%d, want 2", by[string(RoleAuthorized)])
	}
	if by[string(RoleIdentityPublic)] != 1 {
		t.Fatalf("identity-public count=%d, want 1", by[string(RoleIdentityPublic)])
	}
	if by[string(RoleIdentityPrivate)] != 1 {
		t.Fatalf("identity-private count=%d, want 1", by[string(RoleIdentityPrivate)])
	}
	if by[string(RoleKnownHost)] != 2 {
		t.Fatalf("known-host count=%d, want 2", by[string(RoleKnownHost)])
	}

	// Verify the weak RSA-1024 row got flagged.
	weakFound := false
	for _, k := range got {
		if k.IsWeak && k.KeyType == "ssh-rsa" && k.KeyBits == 1024 {
			weakFound = true
			break
		}
	}
	if !weakFound {
		t.Fatal("RSA-1024 row must be flagged as weak")
	}

	// Verify the passwordless private key got flagged.
	priv := findByRole(got, RoleIdentityPrivate)
	if priv.HasPassphrase {
		t.Fatal("cipher=none key must NOT have passphrase")
	}
	// And it should have lifted fingerprint from the companion .pub.
	if !strings.HasPrefix(priv.FingerprintSHA256, "no-companion-pub") &&
		priv.FingerprintSHA256 == "" {
		t.Fatalf("priv fp empty: %+v", priv)
	}

	// Verify owner_user attribution.
	for _, k := range got {
		if k.Role == RoleKnownHost && k.OwnerUser != "bob" {
			t.Fatalf("known-host owner=%q, want bob", k.OwnerUser)
		}
		if k.Role == RoleAuthorized && k.OwnerUser != "alice" {
			t.Fatalf("authorized owner=%q, want alice", k.OwnerUser)
		}
	}
}

func TestFileCollectorSkipsSystemUsers(t *testing.T) {
	tmp := t.TempDir()
	mustMkdir(t, filepath.Join(tmp, "Guest", ".ssh"))
	mustWrite(t, filepath.Join(tmp, "Guest", ".ssh", "authorized_keys"),
		"ssh-ed25519 "+base64.StdEncoding.EncodeToString(buildPublicKeyBlobED25519(t))+"\n")
	c := &fileCollector{
		homeRoots: []string{tmp},
		etcSSH:    filepath.Join(tmp, "no-etc"),
		readFile:  os.ReadFile,
		readDir:   os.ReadDir,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range got {
		if k.OwnerUser == "Guest" {
			t.Fatal("Guest user keys must be skipped")
		}
	}
}

// -- helpers ----------------------------------------------------------

// buildPublicKeyBlobED25519 returns the SSH wire-format blob of a fresh
// ed25519 public key.
func buildPublicKeyBlobED25519(t *testing.T) []byte {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen ed25519: %v", err)
	}
	return marshalSSHFields("ssh-ed25519", []byte(pub))
}

// buildPublicKeyBlobRSA returns the SSH wire-format blob of a fresh RSA
// public key at the requested bit size. Use small sizes in tests for
// speed (1024 bits ≈ a few ms).
func buildPublicKeyBlobRSA(t *testing.T, bits int) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("gen rsa: %v", err)
	}
	e := big.NewInt(int64(key.E)).Bytes()
	n := key.N.Bytes()
	// SSH integers are mpint: high bit clear, prepend 0x00 if set.
	if len(n) > 0 && n[0]&0x80 != 0 {
		n = append([]byte{0}, n...)
	}
	if len(e) > 0 && e[0]&0x80 != 0 {
		e = append([]byte{0}, e...)
	}
	return marshalSSHFields("ssh-rsa", e, n)
}

func marshalSSHFields(keyType string, fields ...[]byte) []byte {
	out := make([]byte, 0, 256)
	out = appendSSHString(out, []byte(keyType))
	for _, f := range fields {
		out = appendSSHString(out, f)
	}
	return out
}

func appendSSHString(b, s []byte) []byte {
	var lp [4]byte
	// Test fixtures bound s to a few hundred bytes — uint32 conversion is safe.
	binary.BigEndian.PutUint32(lp[:], uint32(len(s))) //#nosec G115 -- bounded test payload
	b = append(b, lp[:]...)
	b = append(b, s...)
	return b
}

// buildOpenSSHKey returns a minimal valid OpenSSH-v1 private key body
// with the given cipher name embedded after the magic header. We don't
// need the rest of the body to be valid — PrivateKeyHasPassphrase only
// inspects the cipher field.
func buildOpenSSHKey(t *testing.T, cipher string) string {
	t.Helper()
	const magic = "openssh-key-v1\x00"
	body := []byte(magic)
	body = appendSSHString(body, []byte(cipher))
	body = appendSSHString(body, []byte("none")) // kdfname
	body = appendSSHString(body, []byte(""))     // kdfoptions
	// Pad with junk to look like a real body.
	body = append(body, make([]byte, 64)...)
	b64 := base64.StdEncoding.EncodeToString(body)
	return "-----BEGIN OPENSSH PRIVATE KEY-----\n" + chunk64(b64) + "\n-----END OPENSSH PRIVATE KEY-----\n"
}

func chunk64(s string) string {
	const w = 70
	var b strings.Builder
	for i := 0; i < len(s); i += w {
		end := i + w
		if end > len(s) {
			end = len(s)
		}
		b.WriteString(s[i:end])
		if end < len(s) {
			b.WriteByte('\n')
		}
	}
	return b.String()
}

func mustMkdir(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatal(err)
	}
}

func mustWrite(t *testing.T, p, body string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func findByRole(ks []Key, r Role) Key {
	for _, k := range ks {
		if k.Role == r {
			return k
		}
	}
	return Key{}
}
