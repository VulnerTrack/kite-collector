package fail2ban

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestPinnedSectionKindStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(SectionDefault), "default"},
		{string(SectionJail), "jail"},
		{string(SectionUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("section_kind drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestHashContentsDeterministic(t *testing.T) {
	a := HashContents([]byte("[sshd]\nenabled = true\n"))
	b := HashContents([]byte("[sshd]\nenabled = true\n"))
	if a != b || len(a) != 64 {
		t.Fatalf("a=%q b=%q", a, b)
	}
}

func TestNormalizeSectionKind(t *testing.T) {
	cases := map[string]SectionKind{
		"DEFAULT":     SectionDefault,
		"Default":     SectionDefault,
		"INCLUDES":    SectionDefault,
		"sshd":        SectionJail,
		"apache-auth": SectionJail,
		"":            SectionUnknown,
	}
	for in, want := range cases {
		if got := NormalizeSectionKind(in); got != want {
			t.Fatalf("NormalizeSectionKind(%q)=%q want %q", in, got, want)
		}
	}
}

func TestIsCriticalJailName(t *testing.T) {
	for _, j := range []string{"sshd", "SSHD", "sshd-ddos", "postfix", "nginx-http-auth", "vsftpd"} {
		if !IsCriticalJailName(j) {
			t.Fatalf("%q must flag critical", j)
		}
	}
	for _, j := range []string{"my-custom-jail", "", "wordpress-hard"} {
		if IsCriticalJailName(j) {
			t.Fatalf("%q must NOT flag critical", j)
		}
	}
}

func TestParseDuration(t *testing.T) {
	cases := map[string]int{
		"120":     120,
		"10m":     600,
		"10M":     600, // case-insensitive
		"1h":      3600,
		"1d":      86400,
		"1w":      86400 * 7,
		"1y":      86400 * 365,
		"-1":      -1,
		"perm":    -1,
		"":        0,
		"garbage": 0,
	}
	for in, want := range cases {
		if got := ParseDuration(in); got != want {
			t.Fatalf("ParseDuration(%q)=%d want %d", in, got, want)
		}
	}
}

func TestIsIgnoreIPWorldExposed(t *testing.T) {
	hit := []string{
		"0.0.0.0/0",
		"127.0.0.1 0.0.0.0/0",
		"::/0",
		"  10.0.0.0/24 ::/0  ",
	}
	for _, s := range hit {
		if !IsIgnoreIPWorldExposed(s) {
			t.Fatalf("%q must flag world-exposed", s)
		}
	}
	miss := []string{
		"127.0.0.1/8 ::1",
		"10.0.0.0/24",
		"",
		"192.168.1.1",
	}
	for _, s := range miss {
		if IsIgnoreIPWorldExposed(s) {
			t.Fatalf("%q must NOT flag world-exposed", s)
		}
	}
}

func TestIsBoolTrue(t *testing.T) {
	for _, s := range []string{"true", "TRUE", "yes", "1", "on", " true "} {
		if !IsBoolTrue(s) {
			t.Fatalf("%q must flag true", s)
		}
	}
	for _, s := range []string{"false", "no", "0", "", "garbage"} {
		if IsBoolTrue(s) {
			t.Fatalf("%q must NOT flag true", s)
		}
	}
}

// -- AnnotateSecurity end-to-end -------------------------------------

func TestAnnotateCriticalJailDisabled(t *testing.T) {
	j := Jail{
		SectionKind: SectionJail,
		SectionName: "sshd",
		Enabled:     "false",
	}
	AnnotateSecurity(&j)
	if !j.IsCriticalJail {
		t.Fatal("sshd must flag critical")
	}
	if !j.IsCriticalJailDisabled {
		t.Fatalf("critical jail off must flag the headline: %+v", j)
	}
}

func TestAnnotateCriticalJailEnabledIsClean(t *testing.T) {
	j := Jail{
		SectionKind:     SectionJail,
		SectionName:     "sshd",
		Enabled:         "true",
		MaxRetry:        3,
		BanTimeSeconds:  3600,
		FindTimeSeconds: 600,
	}
	AnnotateSecurity(&j)
	if !j.IsEnabled {
		t.Fatal("enabled=true must propagate")
	}
	if j.IsCriticalJailDisabled || j.HasLooseThreshold || j.HasShortBantime {
		t.Fatalf("clean jail must clear all flags: %+v", j)
	}
}

func TestAnnotateLooseThreshold(t *testing.T) {
	j := Jail{
		SectionKind: SectionJail,
		SectionName: "sshd",
		Enabled:     "true",
		MaxRetry:    20,
	}
	AnnotateSecurity(&j)
	if !j.HasLooseThreshold {
		t.Fatal("maxretry=20 must flag loose")
	}
}

func TestAnnotateShortBantime(t *testing.T) {
	j := Jail{
		SectionKind:    SectionJail,
		SectionName:    "sshd",
		Enabled:        "true",
		BanTimeSeconds: 120,
	}
	AnnotateSecurity(&j)
	if !j.HasShortBantime {
		t.Fatalf("bantime=2m must flag short: %+v", j)
	}
}

func TestAnnotatePermanentBan(t *testing.T) {
	j := Jail{
		SectionKind:    SectionJail,
		SectionName:    "recidive",
		Enabled:        "true",
		BanTimeSeconds: -1,
	}
	AnnotateSecurity(&j)
	if !j.IsPermanentBan {
		t.Fatal("bantime=-1 must flag permanent")
	}
	if j.HasShortBantime {
		t.Fatal("permanent must NOT flag short")
	}
}

func TestAnnotateIgnoreIPWorld(t *testing.T) {
	j := Jail{
		SectionKind: SectionJail,
		SectionName: "sshd",
		Enabled:     "true",
		IgnoreIP:    "127.0.0.1/8 ::1 0.0.0.0/0",
	}
	AnnotateSecurity(&j)
	if !j.IsIgnoreIPWorldExposed {
		t.Fatal("0.0.0.0/0 in ignoreip must flag")
	}
}

// -- Parse end-to-end ----------------------------------------------

func TestParseTypicalJailLocal(t *testing.T) {
	body := []byte(`# /etc/fail2ban/jail.local
[DEFAULT]
bantime  = 1h
findtime = 10m
maxretry = 3
ignoreip = 127.0.0.1/8 ::1

[sshd]
enabled = true
port    = ssh
filter  = sshd
logpath = /var/log/auth.log

[postfix-sasl]
enabled = true
maxretry = 10

[apache-auth]
enabled = false
`)
	got := Parse(body, "/etc/fail2ban/jail.local")
	if len(got) != 4 {
		t.Fatalf("rows=%d, want 4 (DEFAULT + 3 jails): %+v", len(got), got)
	}

	byName := map[string]Jail{}
	for _, j := range got {
		byName[j.SectionName] = j
	}

	def := byName["DEFAULT"]
	if def.SectionKind != SectionDefault {
		t.Fatalf("DEFAULT section_kind=%q", def.SectionKind)
	}
	if def.BanTimeSeconds != 3600 {
		t.Fatalf("DEFAULT bantime=%d", def.BanTimeSeconds)
	}
	if def.MaxRetry != 3 {
		t.Fatalf("DEFAULT maxretry=%d", def.MaxRetry)
	}

	ssh := byName["sshd"]
	if !ssh.IsCriticalJail {
		t.Fatal("sshd must flag critical")
	}
	if !ssh.IsEnabled {
		t.Fatal("sshd enabled=true must propagate")
	}
	if ssh.IsCriticalJailDisabled {
		t.Fatal("enabled sshd must NOT flag headline finding")
	}
	// Inherited from DEFAULT:
	if ssh.MaxRetry != 3 || ssh.BanTimeSeconds != 3600 {
		t.Fatalf("sshd inheritance broken: %+v", ssh)
	}
	if ssh.IgnoreIP != "127.0.0.1/8 ::1" {
		t.Fatalf("sshd ignoreip inheritance broken: %q", ssh.IgnoreIP)
	}

	// postfix-sasl overrides maxretry.
	postfix := byName["postfix-sasl"]
	if postfix.MaxRetry != 10 {
		t.Fatalf("postfix override broken: %d", postfix.MaxRetry)
	}
	if !postfix.HasLooseThreshold {
		t.Fatal("maxretry=10 must flag loose")
	}

	// apache-auth is critical but disabled — headline finding.
	apache := byName["apache-auth"]
	if !apache.IsCriticalJailDisabled {
		t.Fatalf("apache-auth disabled must flag headline: %+v", apache)
	}
}

func TestParseContinuationLines(t *testing.T) {
	body := []byte(`[sshd]
enabled = true
action  = iptables-multiport[name=SSH, port="ssh", protocol=tcp]
          sendmail-whois[name=SSH, dest=admin@example.com]
`)
	got := Parse(body, "x")
	if len(got) != 1 {
		t.Fatalf("rows=%d", len(got))
	}
	if got[0].ActionCount < 2 {
		t.Fatalf("continuation merge broken; action_count=%d action=%q",
			got[0].ActionCount, got[0].Action)
	}
}

func TestParseCommentVariants(t *testing.T) {
	body := []byte(`# hash
; semi
[sshd]
   # indented hash
enabled = true
`)
	got := Parse(body, "x")
	if len(got) != 1 || got[0].SectionName != "sshd" {
		t.Fatalf("comments broken: %+v", got)
	}
}

func TestParseHonoursMaxRows(t *testing.T) {
	var sb []byte
	for i := 0; i < MaxRows+10; i++ {
		sb = append(sb, []byte("[sshd-")...)
		sb = append(sb, byte('a'+(i%26)))
		sb = append(sb, []byte("]\nenabled = true\n")...)
	}
	got := Parse(sb, "x")
	if len(got) > MaxRows {
		t.Fatalf("rows=%d > MaxRows=%d", len(got), MaxRows)
	}
}

// -- collector end-to-end -------------------------------------------

func TestFileCollectorWalksLocalsAndDropIns(t *testing.T) {
	tmp := t.TempDir()
	local := filepath.Join(tmp, "jail.local")
	dropIn := filepath.Join(tmp, "jail.d")
	must(t, os.MkdirAll(dropIn, 0o755))

	must(t, os.WriteFile(local, []byte(`[DEFAULT]
bantime = 1h
maxretry = 3

[sshd]
enabled = false
`), 0o644))
	must(t, os.WriteFile(filepath.Join(dropIn, "10-postfix.conf"), []byte(`[postfix]
enabled = true
`), 0o644))
	// .bak files must be skipped.
	must(t, os.WriteFile(filepath.Join(dropIn, "ignored.bak"), []byte(`[evil]
enabled = true
`), 0o644))

	c := &fileCollector{
		seeds:      []string{local},
		dropInDirs: []string{dropIn},
		readFile:   os.ReadFile,
		readDir:    os.ReadDir,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	// jail.local: DEFAULT + sshd = 2; drop-in postfix = 1; bak skipped.
	if len(got) != 3 {
		t.Fatalf("want 3, got %d: %+v", len(got), got)
	}
}

func TestFileCollectorMissingPathsOK(t *testing.T) {
	c := &fileCollector{
		seeds:      []string{"/nope"},
		dropInDirs: []string{"/nope-d"},
		readFile:   os.ReadFile,
		readDir:    os.ReadDir,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("missing must not error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want empty, got %d", len(got))
	}
}

// -- SortJails ---------------------------------------------------

func TestSortJailsDeterministic(t *testing.T) {
	in := []Jail{
		{FilePath: "/etc/fail2ban/jail.local", SectionName: "sshd"},
		{FilePath: "/etc/fail2ban/jail.local", SectionName: "DEFAULT"},
		{FilePath: "/etc/fail2ban/jail.conf", SectionName: "sshd"},
	}
	SortJails(in)
	if in[0].FilePath != "/etc/fail2ban/jail.conf" {
		t.Fatalf("first=%+v", in[0])
	}
	// Within jail.local, DEFAULT < sshd lexically.
	if in[1].SectionName != "DEFAULT" {
		t.Fatalf("second=%+v", in[1])
	}
}

// -- helpers --------------------------------------------------------

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
