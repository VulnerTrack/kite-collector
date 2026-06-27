package kerberos

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPinnedSectionStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(SectionLibdefaults), "libdefaults"},
		{string(SectionRealms), "realms"},
		{string(SectionDomainRealm), "domain_realm"},
		{string(SectionAppdefaults), "appdefaults"},
		{string(SectionCAPaths), "capaths"},
		{string(SectionPlugins), "plugins"},
		{string(SectionLogging), "logging"},
		{string(SectionLogin), "login"},
		{string(SectionUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("section drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestHashContentsDeterministic(t *testing.T) {
	a := HashContents([]byte("[libdefaults]\ndefault_realm = EXAMPLE.COM\n"))
	b := HashContents([]byte("[libdefaults]\ndefault_realm = EXAMPLE.COM\n"))
	if a != b || len(a) != 64 {
		t.Fatalf("a=%q b=%q", a, b)
	}
}

func TestIsWeakCryptoSetting(t *testing.T) {
	// allow_weak_crypto truthy.
	for _, v := range []string{"true", "yes", "1", "TRUE"} {
		if !IsWeakCryptoSetting("allow_weak_crypto", v) {
			t.Fatalf("allow_weak_crypto=%q must flag", v)
		}
	}
	if IsWeakCryptoSetting("allow_weak_crypto", "false") {
		t.Fatal("allow_weak_crypto=false must NOT flag")
	}

	// enctypes with weak family.
	if !IsWeakCryptoSetting("permitted_enctypes", "des-cbc-md5 aes256-cts") {
		t.Fatal("des-cbc must flag")
	}
	if !IsWeakCryptoSetting("default_tkt_enctypes", "arcfour-hmac aes256") {
		t.Fatal("arcfour must flag")
	}
	if !IsWeakCryptoSetting("default_tgs_enctypes", "rc4-hmac") {
		t.Fatal("rc4 must flag")
	}
	if IsWeakCryptoSetting("permitted_enctypes", "aes256-cts aes128-cts") {
		t.Fatal("aes-only enctype must NOT flag")
	}

	// Unrelated key.
	if IsWeakCryptoSetting("default_realm", "EXAMPLE.COM") {
		t.Fatal("default_realm is not a crypto switch")
	}
}

func TestParseTicketLifetime(t *testing.T) {
	cases := []struct {
		in   string
		want time.Duration
		ok   bool
	}{
		{"3600", 3600 * time.Second, true},
		{"30s", 30 * time.Second, true},
		{"5m", 5 * time.Minute, true},
		{"10h", 10 * time.Hour, true},
		{"1d", 24 * time.Hour, true},
		{"25h", 25 * time.Hour, true},
		{"24:00:00", 24 * time.Hour, true},
		{"01:30", 1*time.Hour + 30*time.Minute, true},
		{"", 0, false},
		{"garbage", 0, false},
	}
	for _, c := range cases {
		got, ok := ParseTicketLifetime(c.in)
		if ok != c.ok {
			t.Fatalf("ParseTicketLifetime(%q): ok=%v, want %v", c.in, ok, c.ok)
		}
		if got != c.want {
			t.Fatalf("ParseTicketLifetime(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestIsLongTicketLifetimeValue(t *testing.T) {
	for _, v := range []string{"25h", "2d", "48h"} {
		if !IsLongTicketLifetimeValue(v) {
			t.Fatalf("%q (>24h) must flag long", v)
		}
	}
	for _, v := range []string{"24h", "10h", "3600", "1d"} {
		if IsLongTicketLifetimeValue(v) {
			t.Fatalf("%q (<=24h) must NOT flag long", v)
		}
	}
}

func TestIsDNSLookupEnabledSetting(t *testing.T) {
	for _, k := range []string{
		"dns_lookup_realm", "dns_lookup_kdc",
		"dns_canonicalize_hostname",
	} {
		if !IsDNSLookupEnabledSetting(k, "true") {
			t.Fatalf("%s=true must flag", k)
		}
		if IsDNSLookupEnabledSetting(k, "false") {
			t.Fatalf("%s=false must NOT flag", k)
		}
	}
	if IsDNSLookupEnabledSetting("ticket_lifetime", "true") {
		t.Fatal("non-DNS key must not flag")
	}
}

func TestIsKDCOrAdminKey(t *testing.T) {
	for _, k := range []string{
		"kdc", "admin_server", "master_kdc",
		"kpasswd_server",
	} {
		if !IsKDCOrAdminKey(k) {
			t.Fatalf("%s must flag", k)
		}
	}
	for _, k := range []string{"default_realm", "ticket_lifetime", ""} {
		if IsKDCOrAdminKey(k) {
			t.Fatalf("%s must NOT flag", k)
		}
	}
}

func TestAnnotateSecurity(t *testing.T) {
	s := Setting{Key: "kdc", Value: "kdc1.example.com"}
	AnnotateSecurity(&s)
	if !s.IsKDCOrAdmin {
		t.Fatal("kdc must flag is_kdc_or_admin")
	}

	s = Setting{Key: "allow_weak_crypto", Value: "true"}
	AnnotateSecurity(&s)
	if !s.IsWeakCrypto {
		t.Fatal("allow_weak_crypto=true must flag is_weak_crypto")
	}

	s = Setting{Key: "ticket_lifetime", Value: "48h"}
	AnnotateSecurity(&s)
	if !s.IsLongTicketLifetime {
		t.Fatal("48h must flag is_long_ticket_lifetime")
	}

	s = Setting{Key: "default_realm", Value: "EXAMPLE.COM"}
	AnnotateSecurity(&s)
	if !s.IsDefaultRealm {
		t.Fatal("default_realm key must flag is_default_realm")
	}

	s = Setting{Key: "dns_lookup_realm", Value: "true"}
	AnnotateSecurity(&s)
	if !s.IsDNSLookupEnabled {
		t.Fatal("dns_lookup_realm=true must flag is_dns_lookup_enabled")
	}
}

// -- Parse end-to-end ---------------------------------------------------

func TestParseTypicalKrb5(t *testing.T) {
	body := []byte(`# Typical krb5.conf
[libdefaults]
    default_realm = EXAMPLE.COM
    dns_lookup_realm = false
    dns_lookup_kdc = true
    ticket_lifetime = 24h
    renew_lifetime = 7d
    forwardable = true

[realms]
    EXAMPLE.COM = {
        kdc = kdc1.example.com
        kdc = kdc2.example.com
        admin_server = admin.example.com
        default_domain = example.com
    }

    LEGACY.COM = {
        kdc = old-kdc.legacy.com
    }

[domain_realm]
    .example.com = EXAMPLE.COM
    example.com = EXAMPLE.COM
`)
	got := Parse(body, "/etc/krb5.conf")
	if len(got) < 10 {
		t.Fatalf("len=%d, want >=10: %+v", len(got), got)
	}

	var (
		kdcCount        int
		realmsSeen      map[string]int
		hadDefaultRealm bool
		hadLongLifetime bool
		hadDNSLookupKDC bool
	)
	realmsSeen = map[string]int{}
	for _, s := range got {
		if s.IsKDCOrAdmin && s.Key == "kdc" {
			kdcCount++
			realmsSeen[s.Realm]++
		}
		if s.IsDefaultRealm {
			hadDefaultRealm = true
		}
		if s.IsLongTicketLifetime {
			hadLongLifetime = true
		}
		if s.Key == "dns_lookup_kdc" && s.IsDNSLookupEnabled {
			hadDNSLookupKDC = true
		}
		if s.FileHash == "" {
			t.Fatalf("file_hash missing on %+v", s)
		}
	}
	if kdcCount != 3 {
		t.Fatalf("kdc count=%d, want 3 (2 example + 1 legacy)", kdcCount)
	}
	if realmsSeen["EXAMPLE.COM"] != 2 {
		t.Fatalf("EXAMPLE.COM kdcs=%d", realmsSeen["EXAMPLE.COM"])
	}
	if realmsSeen["LEGACY.COM"] != 1 {
		t.Fatalf("LEGACY.COM kdcs=%d", realmsSeen["LEGACY.COM"])
	}
	if !hadDefaultRealm {
		t.Fatal("default_realm must flag")
	}
	// ticket_lifetime is 24h (boundary, not long), renew_lifetime is 7d (long).
	if !hadLongLifetime {
		t.Fatal("renew_lifetime=7d must flag long lifetime")
	}
	if !hadDNSLookupKDC {
		t.Fatal("dns_lookup_kdc=true must flag dns_lookup_enabled")
	}
}

func TestParseRealmBraceOnNextLine(t *testing.T) {
	body := []byte(`[realms]
EXAMPLE.COM =
{
    kdc = kdc1.example.com
}
`)
	got := Parse(body, "x")
	var found bool
	for _, s := range got {
		if s.Key == "kdc" && s.Realm == "EXAMPLE.COM" {
			found = true
		}
	}
	if !found {
		t.Fatalf("brace-on-next-line form lost realm: %+v", got)
	}
}

func TestParseWeakCryptoFlagged(t *testing.T) {
	body := []byte(`[libdefaults]
    allow_weak_crypto = true
    permitted_enctypes = aes256-cts des-cbc-md5
`)
	got := Parse(body, "/etc/krb5.conf")
	var weakCount int
	for _, s := range got {
		if s.IsWeakCrypto {
			weakCount++
		}
	}
	if weakCount != 2 {
		t.Fatalf("weak count=%d, want 2: %+v", weakCount, got)
	}
}

func TestParseCommentVariants(t *testing.T) {
	body := []byte(`# hash comment
; semi comment
[libdefaults]
    default_realm = EXAMPLE.COM   # inline hash
    forwardable = true            ; inline semi
`)
	got := Parse(body, "x")
	if len(got) != 2 {
		t.Fatalf("len=%d", len(got))
	}
	for _, s := range got {
		if s.Value == "" {
			t.Fatalf("value lost to inline comment: %+v", s)
		}
	}
}

func TestParseMaxSettingsCeiling(t *testing.T) {
	body := make([]byte, 0, 256*40)
	body = append(body, []byte("[libdefaults]\n")...)
	for i := 0; i < MaxSettings+50; i++ {
		body = append(body, []byte("a = b\n")...)
	}
	got := Parse(body, "x")
	if len(got) > MaxSettings {
		t.Fatalf("got %d > MaxSettings %d", len(got), MaxSettings)
	}
}

// -- collector end-to-end ---------------------------------------------

func TestFileCollectorWalksMainAndDropIns(t *testing.T) {
	tmp := t.TempDir()
	main := filepath.Join(tmp, "krb5.conf")
	dropIn := filepath.Join(tmp, "krb5.conf.d")
	must(t, os.MkdirAll(dropIn, 0o755))
	mustWrite(t, main, `[libdefaults]
default_realm = EXAMPLE.COM
`)
	mustWrite(t, filepath.Join(dropIn, "10-corp.conf"), `[realms]
EXAMPLE.COM = {
    kdc = kdc1.example.com
}
`)
	mustWrite(t, filepath.Join(dropIn, "99-extra.conf"), `[domain_realm]
.example.com = EXAMPLE.COM
`)
	mustWrite(t, filepath.Join(dropIn, "ignored.bak"),
		"[realms]\nEVIL.COM = {\n  kdc = evil-kdc\n}\n")

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
	// 1 default_realm + 1 kdc + 1 domain_realm = 3.
	if len(got) != 3 {
		t.Fatalf("want 3, got %d: %+v", len(got), got)
	}
	// Ensure the .bak file was NOT parsed.
	for _, s := range got {
		if s.Realm == "EVIL.COM" {
			t.Fatal(".bak file must be ignored")
		}
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
		{FilePath: "/etc/krb5.conf.d/zzz.conf", LineNo: 1},
		{FilePath: "/etc/krb5.conf", LineNo: 5},
		{FilePath: "/etc/krb5.conf", LineNo: 2},
	}
	SortSettings(in)
	if in[0].FilePath != "/etc/krb5.conf" || in[0].LineNo != 2 {
		t.Fatalf("first=%+v", in[0])
	}
	if in[2].FilePath != "/etc/krb5.conf.d/zzz.conf" {
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
