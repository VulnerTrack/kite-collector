package dedup

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestCanonFQDN(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"Example.COM", "example.com"},
		{"example.com.", "example.com"},
		{"  example.com  ", "example.com"},
		{"EXAMPLE.com.", "example.com"},
		{"", ""},
		{".", ""},
		{"foo..bar", ""},
		{"foo.bar", "foo.bar"},
	}
	for _, c := range cases {
		if got := CanonFQDN(c.in); got != c.want {
			t.Errorf("CanonFQDN(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestCanonMAC_NormalizesVariants(t *testing.T) {
	want := "aabbccddeeff"
	for _, in := range []string{
		"AA:BB:CC:DD:EE:FF",
		"aa-bb-cc-dd-ee-ff",
		"AABB.CCDD.EEFF",
		"aa:bb:cc:dd:ee:ff",
	} {
		if got := CanonMAC(in); got != want {
			t.Errorf("CanonMAC(%q) = %q, want %q", in, got, want)
		}
	}
	for _, in := range []string{"", "not-a-mac", "aa:bb:cc"} {
		if got := CanonMAC(in); got != "" {
			t.Errorf("CanonMAC(%q) = %q, want \"\"", in, got)
		}
	}
}

func TestCanonSortedMACs_OrderIndependent(t *testing.T) {
	a := CanonSortedMACs([]string{"AA:BB:CC:DD:EE:01", "aa-bb-cc-dd-ee-02"})
	b := CanonSortedMACs([]string{"aa:bb:cc:dd:ee:02", "AABB.CCDD.EE01"})
	if string(a) != string(b) {
		t.Errorf("MAC set canon differs: %q vs %q", a, b)
	}
}

func TestCanonSortedMACs_DeduplicatesAndSkipsInvalid(t *testing.T) {
	got := CanonSortedMACs([]string{"aa:bb:cc:dd:ee:01", "AA:BB:CC:DD:EE:01", "garbage"})
	if string(got) != "aabbccddee01" {
		t.Errorf("CanonSortedMACs dedup = %q", got)
	}
	if got := CanonSortedMACs([]string{"garbage"}); got != nil {
		t.Errorf("CanonSortedMACs all-invalid = %v, want nil", got)
	}
}

func TestCanonUUID(t *testing.T) {
	want := "00000000-0000-0000-0000-000000000001"
	for _, in := range []string{
		"00000000-0000-0000-0000-000000000001",
		"00000000000000000000000000000001",
		"{00000000-0000-0000-0000-000000000001}",
		"00000000-0000-0000-0000-000000000001 ",
	} {
		if got := CanonUUID(in); got != want {
			t.Errorf("CanonUUID(%q) = %q, want %q", in, got, want)
		}
	}
	if CanonUUID("not-a-uuid") != "" {
		t.Error("CanonUUID non-uuid should be empty")
	}
}

func TestCanonLowerHex(t *testing.T) {
	if CanonLowerHex("DEADBEEF") != "deadbeef" {
		t.Error("CanonLowerHex case fold")
	}
	if CanonLowerHex("xyz") != "" {
		t.Error("CanonLowerHex non-hex should be empty")
	}
	if CanonLowerHex("ABC") != "" {
		t.Error("CanonLowerHex odd-length should be empty")
	}
}

func TestCanonProvider_Allowlist(t *testing.T) {
	if CanonProvider("AWS") != "aws" {
		t.Error("CanonProvider AWS")
	}
	if CanonProvider("aws ") != "aws" {
		t.Error("CanonProvider trailing space")
	}
	if CanonProvider("mystery-cloud") != "" {
		t.Error("CanonProvider unknown must reject")
	}
}

func TestCanonAccount_AWSZeroPad(t *testing.T) {
	if got := CanonAccount("aws", "42"); got != "000000000042" {
		t.Errorf("AWS zero-pad = %q", got)
	}
	if got := CanonAccount("aws", "123456789012"); got != "123456789012" {
		t.Errorf("AWS already padded = %q", got)
	}
	if CanonAccount("aws", "12345678901234") != "" {
		t.Error("AWS >12 digits must reject")
	}
	if CanonAccount("aws", "12a") != "" {
		t.Error("AWS non-numeric must reject")
	}
}

func TestCanonAccount_GCPProjectID(t *testing.T) {
	if got := CanonAccount("gcp", "My-Project-42"); got != "my-project-42" {
		t.Errorf("GCP lowercasing = %q", got)
	}
	if CanonAccount("gcp", "42project") != "" {
		t.Error("GCP starting digit must reject")
	}
	if CanonAccount("gcp", "no") != "" {
		t.Error("GCP <6 chars must reject")
	}
	if CanonAccount("gcp", "has_underscore") != "" {
		t.Error("GCP underscore must reject")
	}
}

func TestCanonAccount_AzureUUID(t *testing.T) {
	got := CanonAccount("azure", "DEADBEEF-1234-5678-9ABC-DEF012345678")
	if got != "deadbeef-1234-5678-9abc-def012345678" {
		t.Errorf("Azure UUID canon = %q", got)
	}
	if CanonAccount("azure", "not-a-uuid") != "" {
		t.Error("Azure non-UUID must reject")
	}
}

func TestCanonVCSURL_NormalizesForms(t *testing.T) {
	want := "https://github.com/org/repo"
	for _, in := range []string{
		"https://github.com/org/repo.git",
		"https://github.com/org/repo",
		"https://github.com/org/repo/",
		"https://USER:PASS@github.com/org/repo.git",
		"https://github.com:443/org/repo",
		"git@github.com:org/repo.git",
		"HTTPS://GitHub.com/org/repo",
	} {
		if got := CanonVCSURL(in); got != want {
			t.Errorf("CanonVCSURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCanonOCIDigest_RejectsTags(t *testing.T) {
	good := "sha256:" + strings.Repeat("a", 64)
	if CanonOCIDigest(good) != good {
		t.Error("CanonOCIDigest good")
	}
	if CanonOCIDigest("SHA256:"+strings.Repeat("A", 64)) != good {
		t.Error("CanonOCIDigest case fold")
	}
	if CanonOCIDigest("nginx:latest") != "" {
		t.Error("CanonOCIDigest must reject tag")
	}
	if CanonOCIDigest("sha256:xyz") != "" {
		t.Error("CanonOCIDigest must reject short")
	}
}

func TestCanonSSHHostKey_PEMvsRawAgnostic(t *testing.T) {
	// Construct a fake ssh-ed25519 line with deterministic key bytes.
	keyBytes := []byte("fake-wire-bytes-not-real-ed25519")
	encoded := stdB64Encode(keyBytes)
	one := CanonSSHHostKey("ssh-ed25519 " + encoded + " comment@host")
	two := CanonSSHHostKey("  ssh-ed25519  " + encoded + "  ")
	if one == "" || one != two {
		t.Errorf("CanonSSHHostKey not stable: %q vs %q", one, two)
	}
	// Direct SHA-256 of wire bytes for cross-check.
	if got := mustSHA256Hex(keyBytes); got != one {
		t.Errorf("CanonSSHHostKey digest = %q, want %q", one, got)
	}
}

func TestCanonStringSet_OrderIndependent(t *testing.T) {
	a := CanonStringSet([]string{"_ssh._tcp", "_http._tcp"})
	b := CanonStringSet([]string{"_HTTP._tcp", "_SSH._tcp"})
	if string(a) != string(b) {
		t.Errorf("CanonStringSet order-dependence: %q vs %q", a, b)
	}
}

func TestCanonStringSet_EmptyReturnsNil(t *testing.T) {
	if CanonStringSet(nil) != nil {
		t.Error("CanonStringSet(nil) should be nil")
	}
	if CanonStringSet([]string{"", "   "}) != nil {
		t.Error("CanonStringSet of empty strings should be nil")
	}
}

func mustSHA256Hex(b []byte) string {
	h := sha256Sum(b)
	return hex.EncodeToString(h[:])
}
