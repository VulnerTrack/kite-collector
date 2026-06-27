package sshdconfig

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPinnedScopeStrings(t *testing.T) {
	if string(ScopeGlobal) != "global" {
		t.Fatalf("scope drift: got %q want global", ScopeGlobal)
	}
	if string(ScopeMatch) != "match" {
		t.Fatalf("scope drift: got %q want match", ScopeMatch)
	}
}

func TestPinnedFindingCategoryStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(FindingRootLoginPermitted), "root-login-permitted"},
		{string(FindingPasswordAuthPermitted), "password-auth-permitted"},
		{string(FindingEmptyPasswordPermitted), "empty-password-permitted"},
		{string(FindingX11ForwardingEnabled), "x11-forwarding-enabled"},
		{string(FindingAgentForwardingEnabled), "agent-forwarding-enabled"},
		{string(FindingTCPForwardingEnabled), "tcp-forwarding-enabled"},
		{string(FindingHostBasedAuthEnabled), "host-based-auth-enabled"},
		{string(FindingRhostsNotIgnored), "rhosts-not-ignored"},
		{string(FindingExcessiveAuthAttempts), "excessive-auth-attempts"},
		{string(FindingLongLoginGrace), "long-login-grace"},
		{string(FindingWeakCipher), "weak-cipher"},
		{string(FindingWeakMAC), "weak-mac"},
		{string(FindingWeakKex), "weak-kex"},
		{string(FindingProtocolV1), "protocol-v1"},
		{string(FindingPermitUserEnvironment), "permit-user-environment"},
		{string(FindingNoBanner), "no-banner"},
		{string(FindingUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("category drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestHashContentsDeterministic(t *testing.T) {
	a := HashContents([]byte("PermitRootLogin no\n"))
	b := HashContents([]byte("PermitRootLogin no\n"))
	if a != b || len(a) != 64 {
		t.Fatalf("a=%q b=%q", a, b)
	}
}

func TestClassifyDirectivePermitRootLogin(t *testing.T) {
	for _, v := range []string{"yes", "without-password", "forced-commands-only"} {
		cat, _, viol := ClassifyDirective("PermitRootLogin", v)
		if !viol || cat != FindingRootLoginPermitted {
			t.Fatalf("PermitRootLogin=%q must flag: cat=%q viol=%v", v, cat, viol)
		}
	}
	for _, v := range []string{"no", "prohibit-password"} {
		cat, _, viol := ClassifyDirective("PermitRootLogin", v)
		if viol || cat != "" {
			t.Fatalf("PermitRootLogin=%q must NOT flag: cat=%q viol=%v", v, cat, viol)
		}
	}
}

func TestClassifyDirectivePasswordAndEmpty(t *testing.T) {
	cat, _, viol := ClassifyDirective("PasswordAuthentication", "yes")
	if !viol || cat != FindingPasswordAuthPermitted {
		t.Fatal("PasswordAuthentication=yes must flag")
	}
	cat, _, viol = ClassifyDirective("PasswordAuthentication", "no")
	if viol || cat != "" {
		t.Fatal("PasswordAuthentication=no must NOT flag")
	}
	cat, _, viol = ClassifyDirective("PermitEmptyPasswords", "yes")
	if !viol || cat != FindingEmptyPasswordPermitted {
		t.Fatal("PermitEmptyPasswords=yes must flag")
	}
}

func TestClassifyDirectiveForwardings(t *testing.T) {
	cases := []struct {
		key, val string
		wantCat  FindingCategory
	}{
		{"X11Forwarding", "yes", FindingX11ForwardingEnabled},
		{"AllowAgentForwarding", "yes", FindingAgentForwardingEnabled},
		{"AllowTcpForwarding", "yes", FindingTCPForwardingEnabled},
		{"AllowTcpForwarding", "all", FindingTCPForwardingEnabled},
		{"HostbasedAuthentication", "yes", FindingHostBasedAuthEnabled},
	}
	for _, c := range cases {
		cat, _, viol := ClassifyDirective(c.key, c.val)
		if !viol || cat != c.wantCat {
			t.Fatalf("%s=%q: cat=%q viol=%v, want %q+true", c.key, c.val, cat, viol, c.wantCat)
		}
	}
}

func TestClassifyDirectiveIgnoreRhosts(t *testing.T) {
	cat, _, viol := ClassifyDirective("IgnoreRhosts", "no")
	if !viol || cat != FindingRhostsNotIgnored {
		t.Fatal("IgnoreRhosts=no must flag")
	}
	cat, _, viol = ClassifyDirective("IgnoreRhosts", "yes")
	if viol || cat != "" {
		t.Fatal("IgnoreRhosts=yes must NOT flag")
	}
}

func TestClassifyDirectiveMaxAuthTries(t *testing.T) {
	for _, n := range []string{"5", "6", "10", "100"} {
		cat, _, viol := ClassifyDirective("MaxAuthTries", n)
		if !viol || cat != FindingExcessiveAuthAttempts {
			t.Fatalf("MaxAuthTries=%s must flag", n)
		}
	}
	for _, n := range []string{"4", "3", "1"} {
		cat, _, viol := ClassifyDirective("MaxAuthTries", n)
		if viol || cat != "" {
			t.Fatalf("MaxAuthTries=%s must NOT flag", n)
		}
	}
}

func TestClassifyDirectiveLoginGraceTime(t *testing.T) {
	for _, v := range []string{"120", "5m", "1h", "120s"} {
		cat, _, viol := ClassifyDirective("LoginGraceTime", v)
		if !viol || cat != FindingLongLoginGrace {
			t.Fatalf("LoginGraceTime=%s must flag", v)
		}
	}
	for _, v := range []string{"60", "30s", "60s", "1m"} {
		cat, _, viol := ClassifyDirective("LoginGraceTime", v)
		if viol || cat != "" {
			t.Fatalf("LoginGraceTime=%s must NOT flag: got %q", v, cat)
		}
	}
}

func TestClassifyDirectiveCiphers(t *testing.T) {
	cat, _, viol := ClassifyDirective("Ciphers",
		"aes256-gcm@openssh.com,chacha20-poly1305@openssh.com,aes256-cbc")
	if !viol || cat != FindingWeakCipher {
		t.Fatal("aes256-cbc in cipher list must flag")
	}
	cat, _, viol = ClassifyDirective("Ciphers",
		"aes256-gcm@openssh.com,chacha20-poly1305@openssh.com")
	if viol || cat != "" {
		t.Fatal("modern-only cipher list must NOT flag")
	}
}

func TestClassifyDirectiveMACs(t *testing.T) {
	cat, _, viol := ClassifyDirective("MACs", "hmac-sha2-256,hmac-md5")
	if !viol || cat != FindingWeakMAC {
		t.Fatal("hmac-md5 must flag")
	}
	cat, _, viol = ClassifyDirective("MACs", "hmac-sha2-256-etm@openssh.com")
	if viol || cat != "" {
		t.Fatal("modern MAC must NOT flag")
	}
}

func TestClassifyDirectiveKexAlgorithms(t *testing.T) {
	cat, _, viol := ClassifyDirective("KexAlgorithms",
		"curve25519-sha256,diffie-hellman-group1-sha1")
	if !viol || cat != FindingWeakKex {
		t.Fatal("dh-group1-sha1 must flag")
	}
	cat, _, viol = ClassifyDirective("KexAlgorithms", "curve25519-sha256")
	if viol || cat != "" {
		t.Fatal("modern KEX must NOT flag")
	}
}

func TestClassifyDirectiveProtocolV1(t *testing.T) {
	cat, _, viol := ClassifyDirective("Protocol", "1")
	if !viol || cat != FindingProtocolV1 {
		t.Fatal("Protocol=1 must flag")
	}
	cat, _, viol = ClassifyDirective("Protocol", "2,1")
	if !viol || cat != FindingProtocolV1 {
		t.Fatal("Protocol=2,1 must flag (downgrade allowed)")
	}
	cat, _, viol = ClassifyDirective("Protocol", "2")
	if viol || cat != "" {
		t.Fatal("Protocol=2 must NOT flag")
	}
}

func TestClassifyDirectiveCaseInsensitiveKey(t *testing.T) {
	cat1, _, viol1 := ClassifyDirective("permitrootlogin", "yes")
	cat2, _, viol2 := ClassifyDirective("PermitRootLogin", "yes")
	if cat1 != cat2 || viol1 != viol2 {
		t.Fatalf("case-insensitive failed: (%q,%v) vs (%q,%v)",
			cat1, viol1, cat2, viol2)
	}
}

func TestAnnotateSecurity(t *testing.T) {
	s := Setting{Key: "PermitRootLogin", Value: "yes"}
	AnnotateSecurity(&s)
	if !s.IsSecurityCritical || !s.IsBaselineViolation {
		t.Fatalf("flags: %+v", s)
	}
	if s.FindingCategory != FindingRootLoginPermitted {
		t.Fatalf("category=%q", s.FindingCategory)
	}
}

// -- Parse end-to-end ---------------------------------------------------

func TestParseTypicalSshdConfig(t *testing.T) {
	body := []byte(`# /etc/ssh/sshd_config
Port 22
Protocol 2
PermitRootLogin no
PasswordAuthentication no
PermitEmptyPasswords no
X11Forwarding no
MaxAuthTries 4
LoginGraceTime 60s
IgnoreRhosts yes
HostbasedAuthentication no
Ciphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com
MACs hmac-sha2-256-etm@openssh.com

Match User backup
    PermitRootLogin yes
    PasswordAuthentication yes
`)
	got := Parse(body, "/etc/ssh/sshd_config")
	if len(got) < 12 {
		t.Fatalf("len=%d, want >=12: %+v", len(got), got)
	}

	// The global block is all CIS-clean; the Match block has 2 violations.
	violations := 0
	matchScope := 0
	for _, s := range got {
		if s.IsBaselineViolation {
			violations++
		}
		if s.Scope == ScopeMatch {
			matchScope++
			if s.MatchCriteria != "User backup" {
				t.Fatalf("match_criteria=%q", s.MatchCriteria)
			}
		}
		if s.FileHash == "" {
			t.Fatalf("file_hash missing on %+v", s)
		}
	}
	if violations != 2 {
		t.Fatalf("violation count=%d, want 2 (Match block overrides)", violations)
	}
	if matchScope != 2 {
		t.Fatalf("match scope count=%d, want 2", matchScope)
	}
}

func TestParseHandlesEqualsSeparator(t *testing.T) {
	body := []byte("PermitRootLogin=yes\nPasswordAuthentication = yes\n")
	got := Parse(body, "x")
	if len(got) != 2 {
		t.Fatalf("len=%d", len(got))
	}
	for _, s := range got {
		if !s.IsBaselineViolation {
			t.Fatalf("must flag: %+v", s)
		}
	}
}

func TestParseSkipsCommentsAndBlanks(t *testing.T) {
	body := []byte("# comment\n\n# more\n")
	if got := Parse(body, "x"); len(got) != 0 {
		t.Fatalf("expected empty, got %d: %+v", len(got), got)
	}
}

func TestParseMaxSettingsCeiling(t *testing.T) {
	var sb strings.Builder
	for i := 0; i < MaxSettings+50; i++ {
		sb.WriteString("AllowUsers alice\n")
	}
	got := Parse([]byte(sb.String()), "x")
	if len(got) > MaxSettings {
		t.Fatalf("got %d > MaxSettings %d", len(got), MaxSettings)
	}
}

// -- collector end-to-end ---------------------------------------------

func TestFileCollectorWalksMainAndDropIns(t *testing.T) {
	tmp := t.TempDir()
	main := filepath.Join(tmp, "sshd_config")
	dropIn := filepath.Join(tmp, "sshd_config.d")
	must(t, os.MkdirAll(dropIn, 0o755))
	mustWrite(t, main, "PermitRootLogin no\n")
	mustWrite(t, filepath.Join(dropIn, "10-cis.conf"),
		"PasswordAuthentication no\nMaxAuthTries 4\n")
	mustWrite(t, filepath.Join(dropIn, "99-bad.conf"),
		"X11Forwarding yes\nCiphers aes256-cbc\n")
	mustWrite(t, filepath.Join(dropIn, "ignored.bak"),
		"PermitRootLogin yes\n")

	c := &fileCollector{
		mainFile:  main,
		dropInDir: dropIn,
		readFile:  os.ReadFile,
		readDir:   os.ReadDir,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	// 1 main + 2 cis + 2 bad = 5; .bak ignored.
	if len(got) != 5 {
		t.Fatalf("want 5, got %d: %+v", len(got), got)
	}
	violations := 0
	for _, s := range got {
		if s.IsBaselineViolation {
			violations++
		}
	}
	if violations != 2 {
		t.Fatalf("violations=%d, want 2 (X11Forwarding + weak cipher)", violations)
	}
}

func TestFileCollectorMissingPathsOK(t *testing.T) {
	c := &fileCollector{
		mainFile:  "/nope",
		dropInDir: "/nope-dir",
		readFile:  os.ReadFile,
		readDir:   os.ReadDir,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("missing must not error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want empty, got %d", len(got))
	}
}

func TestSortSettingsDeterministic(t *testing.T) {
	in := []Setting{
		{FilePath: "/etc/ssh/sshd_config.d/zzz.conf", LineNo: 1},
		{FilePath: "/etc/ssh/sshd_config", LineNo: 5},
		{FilePath: "/etc/ssh/sshd_config", LineNo: 2},
	}
	SortSettings(in)
	if in[0].FilePath != "/etc/ssh/sshd_config" || in[0].LineNo != 2 {
		t.Fatalf("first=%+v", in[0])
	}
	if in[2].FilePath != "/etc/ssh/sshd_config.d/zzz.conf" {
		t.Fatalf("last=%+v", in[2])
	}
}

// -- helpers -----------------------------------------------------------

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func mustWrite(t *testing.T, p, body string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}
