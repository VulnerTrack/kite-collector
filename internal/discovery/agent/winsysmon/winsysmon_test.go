package winsysmon

import (
	"context"
	"errors"
	"io/fs"
	"testing"
)

func TestPinnedSourceStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(SourceConfigXML), "config-xml"},
		{string(SourceNoConfig), "no-config"},
		{string(SourceNoProbe), "no-probe"},
		{string(SourceUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("source drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestHashContentsDeterministic(t *testing.T) {
	a := HashContents([]byte("<Sysmon/>"))
	b := HashContents([]byte("<Sysmon/>"))
	if a != b || len(a) != 64 {
		t.Fatalf("a=%q b=%q", a, b)
	}
}

func TestIsSuspiciousExclusionPath(t *testing.T) {
	hit := []string{
		`C:\Users\Public\dropper.exe`,
		`"C:\Windows\Temp\implant.exe"`,
		`c:\temp\foo.bat`,
		`%TEMP%\stage.exe`,
		`%PUBLIC%\go.cmd`,
		`%UserProfile%\AppData\Local\Temp\x.exe`,
	}
	for _, p := range hit {
		if !IsSuspiciousExclusionPath(p) {
			t.Fatalf("%q must flag suspicious", p)
		}
	}
	miss := []string{
		`C:\Program Files\Vendor\helper.exe`,
		`C:\Windows\System32\svchost.exe`,
		``,
	}
	for _, p := range miss {
		if IsSuspiciousExclusionPath(p) {
			t.Fatalf("%q must NOT flag suspicious", p)
		}
	}
}

func TestHasStrongHashAlgorithmList(t *testing.T) {
	for _, s := range []string{
		"SHA256,IMPHASH",
		"sha256, imphash",
		"MD5,SHA256,IMPHASH,SHA1",
		"*,IMPHASH",
	} {
		if !HasStrongHashAlgorithmList(s) {
			t.Fatalf("%q must flag strong", s)
		}
	}
	for _, s := range []string{
		"SHA256",   // missing IMPHASH
		"IMPHASH",  // missing SHA256
		"MD5,SHA1", // neither
		"",
	} {
		if HasStrongHashAlgorithmList(s) {
			t.Fatalf("%q must NOT flag strong", s)
		}
	}
}

func TestIsSchemaOutdated(t *testing.T) {
	for _, v := range []string{"4.50", "4.83", "5.0"} {
		if IsSchemaOutdated(v) {
			t.Fatalf("%q must NOT flag outdated", v)
		}
	}
	for _, v := range []string{"4.00", "3.40", "", "garbage"} {
		if !IsSchemaOutdated(v) {
			t.Fatalf("%q must flag outdated", v)
		}
	}
}

func TestEncodeStringList(t *testing.T) {
	if EncodeStringList(nil) != "[]" {
		t.Fatal("nil")
	}
	if got := EncodeStringList([]string{"ProcessCreate"}); got != `["ProcessCreate"]` {
		t.Fatalf("got %q", got)
	}
}

// -- AnnotateSecurity end-to-end -------------------------------------

func TestAnnotateMinimalConfigFlagsCoverageGaps(t *testing.T) {
	s := State{}
	AnnotateSecurity(&s)
	if !s.IsSchemaOutdated {
		t.Fatal("missing schema must flag outdated")
	}
	if s.HasStrongHashAlgorithms {
		t.Fatal("empty hash list must NOT flag strong")
	}
	if !s.HasNoProcessCreateRules {
		t.Fatal("no rule groups must flag missing PC")
	}
	if !s.HasNoNetworkConnectRules {
		t.Fatal("no rule groups must flag missing NC")
	}
	if !s.HasNoDNSQueryRules {
		t.Fatal("no rule groups must flag missing DNS")
	}
	if s.IsHardened {
		t.Fatal("empty config must NOT be hardened")
	}
}

func TestAnnotateFullyHardenedConfig(t *testing.T) {
	s := State{
		SchemaVersion:          "4.83",
		HashAlgorithms:         "SHA256,IMPHASH",
		CheckRevocationEnabled: true,
		RuleGroups:             []string{"ProcessCreate", "NetworkConnect", "DnsQuery"},
	}
	AnnotateSecurity(&s)
	if s.IsSchemaOutdated {
		t.Fatal("4.83 must NOT flag outdated")
	}
	if !s.HasStrongHashAlgorithms {
		t.Fatal("SHA256+IMPHASH must flag strong")
	}
	if s.HasNoProcessCreateRules || s.HasNoNetworkConnectRules || s.HasNoDNSQueryRules {
		t.Fatalf("coverage gaps wrong: %+v", s)
	}
	if !s.IsHardened {
		t.Fatalf("baseline must hold: %+v", s)
	}
}

func TestAnnotateSuspiciousExclusionFlags(t *testing.T) {
	s := State{
		SchemaVersion:          "4.83",
		HashAlgorithms:         "SHA256,IMPHASH",
		CheckRevocationEnabled: true,
		RuleGroups:             []string{"ProcessCreate", "NetworkConnect", "DnsQuery"},
		ExclusionImagePaths: []string{
			`C:\Program Files\Vendor\helper.exe`,
			`C:\Users\Public\dropper.exe`,
		},
	}
	AnnotateSecurity(&s)
	if !s.HasSuspiciousExclusion {
		t.Fatalf("Public exclusion must flag suspicious: %+v", s)
	}
	if len(s.SuspiciousExclusionPaths) != 1 {
		t.Fatalf("filter wrong: %+v", s.SuspiciousExclusionPaths)
	}
	if s.IsHardened {
		t.Fatal("suspicious exclusion must un-harden")
	}
}

// -- ParseConfigXML typical hardened --------------------------------

func TestParseConfigXMLTypicalHardened(t *testing.T) {
	body := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<Sysmon schemaversion="4.83">
  <HashAlgorithms>SHA256,IMPHASH</HashAlgorithms>
  <CheckRevocation/>
  <DnsLookup>True</DnsLookup>
  <EventFiltering>
    <RuleGroup name="ProcessCreate" groupRelation="or">
      <ProcessCreate onmatch="include">
        <Image condition="end with">.exe</Image>
      </ProcessCreate>
    </RuleGroup>
    <RuleGroup name="NetworkConnect" groupRelation="or">
      <NetworkConnect onmatch="exclude">
        <Image condition="is">C:\Windows\System32\svchost.exe</Image>
      </NetworkConnect>
    </RuleGroup>
    <RuleGroup name="DnsQuery" groupRelation="or">
      <DnsQuery onmatch="include">
        <Image condition="end with">.exe</Image>
      </DnsQuery>
    </RuleGroup>
  </EventFiltering>
</Sysmon>`)
	got, err := ParseConfigXML(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.SchemaVersion != "4.83" {
		t.Fatalf("schema=%q", got.SchemaVersion)
	}
	if got.HashAlgorithms != "SHA256,IMPHASH" {
		t.Fatalf("hash=%q", got.HashAlgorithms)
	}
	if !got.CheckRevocationEnabled {
		t.Fatal("self-closing <CheckRevocation/> must flag enabled")
	}
	if !got.DNSLookupEnabled {
		t.Fatal("DnsLookup=True must propagate")
	}
	if got.HasNoProcessCreateRules || got.HasNoNetworkConnectRules || got.HasNoDNSQueryRules {
		t.Fatalf("RuleGroups not picked up: %+v", got)
	}
	if !got.IsHardened {
		t.Fatalf("typical hardened must flag: %+v", got)
	}
	// svchost.exe is NOT a world-writable path, so no suspicious flag.
	if got.HasSuspiciousExclusion {
		t.Fatal("svchost exclusion is NOT suspicious")
	}
}

// -- ParseConfigXML worst-case --------------------------------------

func TestParseConfigXMLWorstCase(t *testing.T) {
	// Pre-coverage config: old schema, weak hash, no rule groups,
	// suspicious exclusion buried inside.
	body := []byte(`<?xml version="1.0"?>
<Sysmon schemaversion="3.40">
  <HashAlgorithms>MD5</HashAlgorithms>
  <EventFiltering>
    <ProcessCreate onmatch="exclude">
      <Image condition="is">C:\Users\Public\dropper.exe</Image>
    </ProcessCreate>
  </EventFiltering>
</Sysmon>`)
	got, err := ParseConfigXML(body)
	if err != nil {
		t.Fatal(err)
	}
	if !got.IsSchemaOutdated {
		t.Fatal("3.40 must flag outdated")
	}
	if got.HasStrongHashAlgorithms {
		t.Fatal("MD5-only must NOT flag strong")
	}
	if !got.HasNoNetworkConnectRules {
		t.Fatal("no NC rule must flag")
	}
	// Bare ProcessCreate (not wrapped in RuleGroup) should still
	// register coverage.
	if got.HasNoProcessCreateRules {
		t.Fatalf("bare ProcessCreate must register: %+v", got.RuleGroups)
	}
	if !got.HasSuspiciousExclusion {
		t.Fatalf("Public exclusion must flag suspicious: %+v", got)
	}
}

// -- ParseConfigXML BOM tolerance -----------------------------------

func TestParseConfigXMLBOMTolerance(t *testing.T) {
	body := append([]byte{0xEF, 0xBB, 0xBF},
		[]byte(`<Sysmon schemaversion="4.83"><HashAlgorithms>SHA256,IMPHASH</HashAlgorithms></Sysmon>`)...)
	got, err := ParseConfigXML(body)
	if err != nil {
		t.Fatalf("BOM should be tolerated: %v", err)
	}
	if got.SchemaVersion != "4.83" {
		t.Fatalf("schema=%q", got.SchemaVersion)
	}
}

// -- error paths ----------------------------------------------------

func TestParseConfigXMLEmpty(t *testing.T) {
	if _, err := ParseConfigXML(nil); err == nil {
		t.Fatal("empty must error")
	}
}

func TestParseConfigXMLMalformed(t *testing.T) {
	// xml.Decoder with Strict=false is permissive; verify a totally
	// non-XML payload still parses to a valid (empty) State without
	// crashing — but a top-level garbage produces unmarshal failure.
	got, err := ParseConfigXML([]byte("not xml"))
	if err != nil {
		// Either outcome is acceptable; we just don't want a panic.
		return
	}
	if got.SchemaVersion != "" {
		t.Fatalf("non-XML should NOT have schema: %q", got.SchemaVersion)
	}
}

// -- collector end-to-end -------------------------------------------

func TestFileCollectorPicksFirstReadable(t *testing.T) {
	body := []byte(`<Sysmon schemaversion="4.83">
<HashAlgorithms>SHA256,IMPHASH</HashAlgorithms>
<CheckRevocation/>
<EventFiltering>
<RuleGroup name="ProcessCreate" groupRelation="or"/>
<RuleGroup name="NetworkConnect" groupRelation="or"/>
<RuleGroup name="DnsQuery" groupRelation="or"/>
</EventFiltering>
</Sysmon>`)
	c := &fileCollector{
		paths: []string{"/nope-a", `C:\ProgramData\Sysmon\sysmonconfig.xml`},
		readFile: func(p string) ([]byte, error) {
			if p == "/nope-a" {
				return nil, fs.ErrNotExist
			}
			return body, nil
		},
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if got.Source != SourceConfigXML {
		t.Fatalf("source=%q", got.Source)
	}
	if !got.IsHardened {
		t.Fatalf("hardened expected: %+v", got)
	}
	if got.FileHash == "" {
		t.Fatal("file_hash missing")
	}
}

func TestFileCollectorAllMissingReturnsNoConfig(t *testing.T) {
	c := &fileCollector{
		paths: []string{"/nope-a", "/nope-b"},
		readFile: func(string) ([]byte, error) {
			return nil, fs.ErrNotExist
		},
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("missing must not error: %v", err)
	}
	if got.Source != SourceNoConfig {
		t.Fatalf("source=%q want no-config", got.Source)
	}
}

func TestFileCollectorReadErrorPropagates(t *testing.T) {
	boom := errors.New("io boom")
	c := &fileCollector{
		paths: []string{"/x"},
		readFile: func(string) ([]byte, error) {
			return nil, boom
		},
	}
	got, err := c.Collect(context.Background())
	if err == nil {
		t.Fatal("read error must propagate")
	}
	if got.Source != SourceUnknown {
		t.Fatalf("source=%q want unknown", got.Source)
	}
}
