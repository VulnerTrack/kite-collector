package winauthkeys

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func TestPinnedKeyScopeStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(ScopeAdmin), "admin"},
		{string(ScopeRoot), "root"},
		{string(ScopeUser), "user"},
		{string(ScopeUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("scope drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestPinnedKeyTypeStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KeyTypeRSA), "rsa"},
		{string(KeyTypeEd25519), "ed25519"},
		{string(KeyTypeECDSA), "ecdsa"},
		{string(KeyTypeDSA), "dsa"},
		{string(KeyTypeRSASHA2), "rsa-sha2"},
		{string(KeyTypeSKEd25519), "sk-ed25519"},
		{string(KeyTypeSKECDSA), "sk-ecdsa"},
		{string(KeyTypeUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("key_type drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestNormalizeKeyType(t *testing.T) {
	cases := map[string]KeyType{
		"ssh-rsa":                            KeyTypeRSA,
		"SSH-RSA":                            KeyTypeRSA,
		"ssh-dss":                            KeyTypeDSA,
		"ssh-ed25519":                        KeyTypeEd25519,
		"sk-ssh-ed25519@openssh.com":         KeyTypeSKEd25519,
		"ecdsa-sha2-nistp256":                KeyTypeECDSA,
		"sk-ecdsa-sha2-nistp256@openssh.com": KeyTypeSKECDSA,
		"rsa-sha2-256":                       KeyTypeRSASHA2,
		"":                                   KeyTypeUnknown,
		"garbage":                            KeyTypeUnknown,
	}
	for in, want := range cases {
		if got := NormalizeKeyType(in); got != want {
			t.Fatalf("NormalizeKeyType(%q)=%q want %q", in, got, want)
		}
	}
}

func TestHashContentsDeterministic(t *testing.T) {
	a := HashContents([]byte("ssh-rsa AAA\n"))
	b := HashContents([]byte("ssh-rsa AAA\n"))
	if a != b || len(a) != 64 {
		t.Fatalf("a=%q b=%q", a, b)
	}
}

func TestFingerprintKey(t *testing.T) {
	// Two different bodies must produce different fingerprints;
	// the same body must produce the same fingerprint; invalid
	// base64 must return "".
	blob := base64.StdEncoding.EncodeToString([]byte("hello world"))
	a := FingerprintKey(blob)
	b := FingerprintKey(blob)
	if a != b {
		t.Fatalf("non-deterministic: %q vs %q", a, b)
	}
	if len(a) == 0 {
		t.Fatal("valid base64 must produce non-empty fingerprint")
	}
	other := FingerprintKey(base64.StdEncoding.EncodeToString([]byte("other")))
	if a == other {
		t.Fatal("different blobs must produce different fingerprints")
	}
	if FingerprintKey("not-valid-base64!!!") != "" {
		t.Fatal("invalid base64 must produce empty fingerprint")
	}
}

func TestExtractRSABits(t *testing.T) {
	// Build a minimal valid ssh-rsa wire-format blob:
	//   string "ssh-rsa", mpint e (3 bytes), mpint n (256 bytes for 2048-bit).
	body := buildRSABlob(256)
	bits := ExtractRSABits(base64.StdEncoding.EncodeToString(body))
	if bits != 2048 {
		t.Fatalf("expected 2048, got %d", bits)
	}

	// 1024-bit RSA = 128-byte modulus.
	weak := buildRSABlob(128)
	wbits := ExtractRSABits(base64.StdEncoding.EncodeToString(weak))
	if wbits != 1024 {
		t.Fatalf("expected 1024, got %d", wbits)
	}

	// Non-RSA algorithm — must return 0.
	if ExtractRSABits(base64.StdEncoding.EncodeToString([]byte("not a valid blob"))) != 0 {
		t.Fatal("invalid blob must return 0")
	}
}

// buildRSABlob constructs a minimal ssh-rsa wire-format body with a
// modulus of `modBytes` raw length (+ the SSH-prepended 0x00 byte).
// The bit-length recovered by ExtractRSABits is therefore
// 8 * modBytes.
func buildRSABlob(modBytes int) []byte {
	var b bytes.Buffer
	writeString := func(s []byte) {
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(s)&0xFFFFFFFF)) //nolint:gosec // test fixture, bounded
		b.Write(l[:])
		b.Write(s)
	}
	writeString([]byte("ssh-rsa"))
	writeString([]byte{0x01, 0x00, 0x01}) // e = 65537
	// mpint n: SSH prepends 0x00 to non-negative mpints; the
	// helper strips this byte when computing bits.
	mod := append([]byte{0x00}, bytes.Repeat([]byte{0xff}, modBytes)...)
	writeString(mod)
	return b.Bytes()
}

func TestHasDangerousOptions(t *testing.T) {
	hit := []string{
		`port-forwarding`,
		`pty,port-forwarding`,
		`X11-FORWARDING`,
		`agent-forwarding,permitlocalcommand`,
	}
	for _, s := range hit {
		if !HasDangerousOptions(s) {
			t.Fatalf("%q must flag dangerous", s)
		}
	}
	miss := []string{
		"",
		`no-port-forwarding,no-pty`,
		`command="ls -la"`,
		`no-agent-forwarding,no-x11-forwarding`,
	}
	for _, s := range miss {
		if HasDangerousOptions(s) {
			t.Fatalf("%q must NOT flag dangerous", s)
		}
	}
}

// -- AnnotateSecurity end-to-end -------------------------------------

func TestAnnotateAdminScopeFlagsHighPriv(t *testing.T) {
	k := Key{KeyScope: ScopeAdmin, KeyType: KeyTypeEd25519, Comment: "user@host"}
	AnnotateSecurity(&k)
	if !k.IsAdministratorsKey {
		t.Fatal("admin scope must flag administrators")
	}
	if !k.IsHighPrivilegeTarget {
		t.Fatal("admin scope must flag high-priv")
	}
	if k.IsWeakKeyType {
		t.Fatal("ed25519 must NOT flag weak")
	}
}

func TestAnnotateWeakRSA(t *testing.T) {
	k := Key{
		KeyScope:   ScopeUser,
		KeyType:    KeyTypeRSA,
		KeyTypeRaw: "ssh-rsa",
		KeyBits:    1024,
		Comment:    "legacy@host",
	}
	AnnotateSecurity(&k)
	if !k.IsWeakKeyType {
		t.Fatalf("1024-bit RSA must flag weak: %+v", k)
	}
}

func TestAnnotateDSAAlwaysWeak(t *testing.T) {
	k := Key{KeyType: KeyTypeDSA, KeyTypeRaw: "ssh-dss"}
	AnnotateSecurity(&k)
	if !k.IsWeakKeyType {
		t.Fatal("DSA must always flag weak")
	}
}

func TestAnnotateNistp192Weak(t *testing.T) {
	k := Key{KeyType: KeyTypeECDSA, KeyTypeRaw: "ecdsa-sha2-nistp192"}
	AnnotateSecurity(&k)
	if !k.IsWeakKeyType {
		t.Fatal("nistp192 ECDSA must flag weak")
	}
}

func TestAnnotateAnonymousKey(t *testing.T) {
	k := Key{KeyScope: ScopeUser, KeyType: KeyTypeEd25519}
	AnnotateSecurity(&k)
	if !k.IsNoComment {
		t.Fatal("empty comment must flag anonymous")
	}
}

func TestAnnotateDangerousOptionsFlag(t *testing.T) {
	k := Key{
		KeyScope: ScopeUser,
		KeyType:  KeyTypeEd25519,
		Comment:  "user@host",
		Options:  "port-forwarding,pty",
	}
	AnnotateSecurity(&k)
	if !k.HasDangerousOptions || !k.HasOptions {
		t.Fatalf("flags wrong: %+v", k)
	}
}

// -- ParseAuthorizedKeys end-to-end ---------------------------------

func TestParseAuthorizedKeysTypical(t *testing.T) {
	body := []byte(`# admin SSH access
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAA root@build
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIabc alice@laptop
no-port-forwarding,no-pty ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIxyz restricted@key
ssh-dss AAAAB3NzaC1kc3MAAAGB legacy@host
`)
	got := ParseAuthorizedKeys(body, "/x/authorized_keys", ScopeUser, "alice")
	if len(got) != 4 {
		t.Fatalf("rows=%d, want 4: %+v", len(got), got)
	}

	// Row 1: ssh-rsa root@build
	if got[0].KeyType != KeyTypeRSA || got[0].Comment != "root@build" {
		t.Fatalf("row 0 wrong: %+v", got[0])
	}
	// Row 2: ssh-ed25519, no options
	if got[1].KeyType != KeyTypeEd25519 || got[1].HasOptions {
		t.Fatalf("row 1 wrong: %+v", got[1])
	}
	// Row 3: with options (hardening, not dangerous)
	if !got[2].HasOptions || got[2].HasDangerousOptions {
		t.Fatalf("row 2 options wrong: %+v", got[2])
	}
	// Row 4: ssh-dss — weak
	if !got[3].IsWeakKeyType {
		t.Fatalf("row 3 must flag DSA weak: %+v", got[3])
	}
}

func TestParseAuthorizedKeysCommentsAndBlanksSkipped(t *testing.T) {
	body := []byte(`# all comments
#

# more
`)
	if got := ParseAuthorizedKeys(body, "x", ScopeUser, ""); len(got) != 0 {
		t.Fatalf("expected 0 rows, got %d", len(got))
	}
}

func TestParseAuthorizedKeysGarbageLineSkipped(t *testing.T) {
	body := []byte(`this is not a key
ssh-rsa AAA real-key
`)
	got := ParseAuthorizedKeys(body, "x", ScopeUser, "")
	if len(got) != 1 {
		t.Fatalf("expected 1 row, got %d: %+v", len(got), got)
	}
}

// -- collector end-to-end -------------------------------------------

func TestFileCollectorWalksAdminAndPerUser(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")
	adminFile := filepath.Join(tmp, "ProgramData", "ssh", "administrators_authorized_keys")
	rootFile := filepath.Join(tmp, "root", ".ssh", "authorized_keys")

	must(t, os.MkdirAll(filepath.Dir(adminFile), 0o755))
	must(t, os.MkdirAll(filepath.Dir(rootFile), 0o755))
	must(t, os.WriteFile(adminFile, []byte(`ssh-ed25519 AAAA admin@key`+"\n"), 0o644))
	must(t, os.WriteFile(rootFile, []byte(`ssh-rsa AAAB root@key`+"\n"), 0o644))

	// alice
	aliceDir := filepath.Join(usersBase, "alice", ".ssh")
	must(t, os.MkdirAll(aliceDir, 0o755))
	must(t, os.WriteFile(filepath.Join(aliceDir, "authorized_keys"),
		[]byte(`ssh-ed25519 AAAC alice@laptop`+"\n"), 0o644))

	// Public pseudo-profile — must be skipped.
	pubDir := filepath.Join(usersBase, "Public", ".ssh")
	must(t, os.MkdirAll(pubDir, 0o755))
	must(t, os.WriteFile(filepath.Join(pubDir, "authorized_keys"),
		[]byte(`ssh-ed25519 AAAD evil@key`+"\n"), 0o644))

	c := &fileCollector{
		usersBases: []string{usersBase},
		rootFiles: []seed{
			{path: adminFile, scope: ScopeAdmin},
			{path: rootFile, scope: ScopeRoot},
		},
		readFile: os.ReadFile,
		readDir:  os.ReadDir,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("want 3 rows (admin + root + alice), got %d: %+v", len(got), got)
	}

	byScope := map[KeyScope]Key{}
	for _, k := range got {
		byScope[k.KeyScope] = k
	}

	if !byScope[ScopeAdmin].IsAdministratorsKey ||
		!byScope[ScopeAdmin].IsHighPrivilegeTarget {
		t.Fatalf("admin row flags wrong: %+v", byScope[ScopeAdmin])
	}
	if !byScope[ScopeRoot].IsRootKey ||
		!byScope[ScopeRoot].IsHighPrivilegeTarget {
		t.Fatalf("root row flags wrong: %+v", byScope[ScopeRoot])
	}
	if byScope[ScopeUser].UserProfile != "alice" {
		t.Fatalf("user profile=%q", byScope[ScopeUser].UserProfile)
	}
	if byScope[ScopeUser].IsHighPrivilegeTarget {
		t.Fatal("user-scope must NOT flag high-priv")
	}
}

func TestFileCollectorMissingPathsOK(t *testing.T) {
	c := &fileCollector{
		usersBases: []string{"/nope-users"},
		rootFiles: []seed{
			{path: "/nope-admin", scope: ScopeAdmin},
		},
		readFile: os.ReadFile,
		readDir:  os.ReadDir,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("missing must not error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want empty, got %d", len(got))
	}
}

// -- SortKeys -------------------------------------------------------

func TestSortKeysDeterministic(t *testing.T) {
	in := []Key{
		{FilePath: "z", LineNo: 1},
		{FilePath: "a", LineNo: 5},
		{FilePath: "a", LineNo: 2},
	}
	SortKeys(in)
	if in[0].FilePath != "a" || in[0].LineNo != 2 {
		t.Fatalf("first=%+v", in[0])
	}
}

// -- helpers --------------------------------------------------------

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
