package macosposture

import (
	"testing"
)

func TestPinnedSourceStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(SourceDarwinCLI), "darwin-cli"},
		{string(SourceNoProbe), "no-probe"},
		{string(SourceUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("source drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestPinnedStatusStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(StatusEnabled), "enabled"},
		{string(StatusDisabled), "disabled"},
		{string(StatusOn), "on"},
		{string(StatusOff), "off"},
		{string(StatusDeferred), "deferred"},
		{string(StatusUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("status drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestHashContentsDeterministic(t *testing.T) {
	a := HashContents([]byte("ok"))
	b := HashContents([]byte("ok"))
	if a != b || len(a) != 64 {
		t.Fatalf("a=%q b=%q", a, b)
	}
}

// -- ParseCSRUtilStatus ---------------------------------------------

func TestParseCSRUtilStatusEnabled(t *testing.T) {
	cases := []string{
		"System Integrity Protection status: enabled.",
		"system integrity protection status: enabled.",
		"  System Integrity Protection status: enabled.  \n",
	}
	for _, s := range cases {
		if got := ParseCSRUtilStatus(s); got != StatusEnabled {
			t.Fatalf("ParseCSRUtilStatus(%q) = %q want enabled", s, got)
		}
	}
}

func TestParseCSRUtilStatusDisabled(t *testing.T) {
	cases := []string{
		"System Integrity Protection status: disabled.",
		"SYSTEM INTEGRITY PROTECTION STATUS: DISABLED.",
		"This is a custom configuration.\nSystem Integrity Protection status: disabled.",
	}
	for _, s := range cases {
		if got := ParseCSRUtilStatus(s); got != StatusDisabled {
			t.Fatalf("ParseCSRUtilStatus(%q) = %q want disabled", s, got)
		}
	}
}

func TestParseCSRUtilStatusCustomFlagsDisabled(t *testing.T) {
	// "Custom Configuration." with no headline word maps to disabled
	// — better to investigate than to false-negative.
	body := `Custom Configuration.

Apple Internal: disabled
Kext Signing: enabled
Filesystem Protections: enabled
Debugging Restrictions: disabled
DTrace Restrictions: enabled
NVRAM Protections: enabled`
	if got := ParseCSRUtilStatus(body); got != StatusDisabled {
		t.Fatalf("custom configuration must flag disabled: %q", got)
	}
}

func TestParseCSRUtilStatusUnknown(t *testing.T) {
	for _, s := range []string{"", "garbage", "csrutil: command not found"} {
		if got := ParseCSRUtilStatus(s); got != StatusUnknown {
			t.Fatalf("ParseCSRUtilStatus(%q) = %q want unknown", s, got)
		}
	}
}

// -- ParseSPCTLStatus -----------------------------------------------

func TestParseSPCTLStatus(t *testing.T) {
	cases := map[string]PostureStatus{
		"assessments enabled":  StatusEnabled,
		"assessments disabled": StatusDisabled,
		"ENABLED":              StatusEnabled,
		"  disabled\n":         StatusDisabled,
		"":                     StatusUnknown,
		"unrelated text":       StatusUnknown,
	}
	for in, want := range cases {
		if got := ParseSPCTLStatus(in); got != want {
			t.Fatalf("ParseSPCTLStatus(%q) = %q want %q", in, got, want)
		}
	}
}

// -- ParseFDESetupStatus --------------------------------------------

func TestParseFDESetupStatusOnOff(t *testing.T) {
	cases := map[string]PostureStatus{
		"FileVault is On.":  StatusOn,
		"FILEVAULT IS ON.":  StatusOn,
		"FileVault is Off.": StatusOff,
		"FileVault is Off, but will be enabled after the next restart.": StatusDeferred,
		"":             StatusUnknown,
		"unrecognised": StatusUnknown,
	}
	for in, want := range cases {
		if got := ParseFDESetupStatus(in); got != want {
			t.Fatalf("ParseFDESetupStatus(%q) = %q want %q", in, got, want)
		}
	}
}

// -- AnnotateSecurity end-to-end ------------------------------------

func TestAnnotateSecurityFullProtection(t *testing.T) {
	s := State{
		SIPStatusRaw:        StatusEnabled,
		GatekeeperStatusRaw: StatusEnabled,
		FileVaultStatusRaw:  StatusOn,
	}
	AnnotateSecurity(&s)
	if !s.IsSIPEnabled || !s.IsGatekeeperEnabled || !s.IsFileVaultEnabled {
		t.Fatalf("flags: %+v", s)
	}
	if !s.IsFullProtectionActive {
		t.Fatal("all-on must flag full protection")
	}
}

func TestAnnotateSecurityWorstCase(t *testing.T) {
	s := State{
		SIPStatusRaw:        StatusDisabled,
		GatekeeperStatusRaw: StatusDisabled,
		FileVaultStatusRaw:  StatusOff,
	}
	AnnotateSecurity(&s)
	if !s.IsSIPDisabled || !s.IsGatekeeperDisabled || !s.IsFileVaultDisabled {
		t.Fatalf("disabled flags: %+v", s)
	}
	if s.IsFullProtectionActive {
		t.Fatal("worst-case must NOT flag full protection")
	}
}

func TestAnnotateSecurityFileVaultDeferred(t *testing.T) {
	s := State{
		SIPStatusRaw:        StatusEnabled,
		GatekeeperStatusRaw: StatusEnabled,
		FileVaultStatusRaw:  StatusDeferred,
	}
	AnnotateSecurity(&s)
	if !s.IsFileVaultDeferred {
		t.Fatal("deferred must flag")
	}
	if s.IsFileVaultEnabled || s.IsFileVaultDisabled {
		t.Fatalf("deferred ≠ on/off: %+v", s)
	}
	if s.IsFullProtectionActive {
		t.Fatal("deferred FileVault must NOT count as full protection")
	}
}

func TestAnnotateSecurityUnknownStatusesClearBooleans(t *testing.T) {
	s := State{
		SIPStatusRaw:        StatusUnknown,
		GatekeeperStatusRaw: StatusUnknown,
		FileVaultStatusRaw:  StatusUnknown,
	}
	AnnotateSecurity(&s)
	if s.IsSIPEnabled || s.IsSIPDisabled ||
		s.IsGatekeeperEnabled || s.IsGatekeeperDisabled ||
		s.IsFileVaultEnabled || s.IsFileVaultDisabled {
		t.Fatalf("unknown must leave booleans cleared: %+v", s)
	}
	if s.IsFullProtectionActive {
		t.Fatal("unknown must NOT flag full protection")
	}
}
