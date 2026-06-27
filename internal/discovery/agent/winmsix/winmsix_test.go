package winmsix

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPinnedInstallScopeStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(ScopeMachineWide), "machine-wide"},
		{string(ScopePerUser), "per-user"},
		{string(ScopeUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("scope drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestHashContentsDeterministic(t *testing.T) {
	a := HashContents([]byte("manifest-body"))
	b := HashContents([]byte("manifest-body"))
	if a != b || len(a) != 64 {
		t.Fatalf("a=%q b=%q", a, b)
	}
}

func TestExtractPublisherCN(t *testing.T) {
	cases := map[string]string{
		"CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US": "Microsoft Corporation",
		"cn=Vendor X, o=Vendor Inc.": "Vendor X",
		"O=Vendor Only":              "O=Vendor Only", // no CN= → return whole
		"":                           "",
	}
	for in, want := range cases {
		if got := ExtractPublisherCN(in); got != want {
			t.Fatalf("ExtractPublisherCN(%q)=%q want %q", in, got, want)
		}
	}
}

func TestIsMicrosoftPublisher(t *testing.T) {
	hit := []string{
		"CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US",
		"cn=microsoft windows, o=microsoft corporation",
		"O=Microsoft Corporation",
	}
	for _, s := range hit {
		if !IsMicrosoftPublisher(s) {
			t.Fatalf("%q must flag Microsoft", s)
		}
	}
	miss := []string{
		"CN=Vendor X",
		"",
		"O=Random Vendor Inc.",
	}
	for _, s := range miss {
		if IsMicrosoftPublisher(s) {
			t.Fatalf("%q must NOT flag Microsoft", s)
		}
	}
}

// -- AnnotateSecurity end-to-end -------------------------------------

func TestAnnotateMicrosoftStoreApp(t *testing.T) {
	p := Package{
		IdentityName:      "Microsoft.WindowsCalculator",
		IdentityVersion:   "11.2306.1.0",
		IdentityPublisher: "CN=Microsoft Corporation, O=Microsoft Corporation",
		Capabilities:      []string{"internetClient"},
	}
	AnnotateSecurity(&p)
	if !p.IsMicrosoftPublisher {
		t.Fatal("MS publisher must flag")
	}
	if p.IsSideloaded {
		t.Fatal("MS publisher must NOT flag sideloaded")
	}
	if p.HasRestrictedCapability {
		t.Fatal("internetClient is not restricted")
	}
	if p.HasRunFullTrust || p.HasBroadFileSystemAccess || p.HasAllowElevation {
		t.Fatal("safe capabilities must not flip dedicated flags")
	}
}

func TestAnnotateRunFullTrustSideload(t *testing.T) {
	p := Package{
		IdentityName:      "EvilCorp.Implant",
		IdentityVersion:   "1.0.0.0",
		IdentityPublisher: "CN=EvilCorp",
		Capabilities:      []string{"rescap:runFullTrust", "rescap:broadFileSystemAccess"},
	}
	AnnotateSecurity(&p)
	if !p.IsSideloaded {
		t.Fatal("non-MS publisher must flag sideloaded")
	}
	if !p.HasRunFullTrust {
		t.Fatal("rescap:runFullTrust must flag dedicated column")
	}
	if !p.HasBroadFileSystemAccess {
		t.Fatal("broadFileSystemAccess must flag dedicated column")
	}
	if !p.HasRestrictedCapability {
		t.Fatal("restricted capability rollup must flip")
	}
}

func TestAnnotateAllowElevationFlag(t *testing.T) {
	p := Package{Capabilities: []string{"rescap:allowElevation"}}
	AnnotateSecurity(&p)
	if !p.HasAllowElevation {
		t.Fatal("allowElevation must flag")
	}
}

// -- ParseAppxManifest typical Microsoft package ---------------------

func TestParseAppxManifestMicrosoftCalculator(t *testing.T) {
	body := []byte(`<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
         xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10"
         xmlns:rescap="http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities">
  <Identity Name="Microsoft.WindowsCalculator"
            Publisher="CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"
            Version="11.2306.1.0"
            ProcessorArchitecture="x64" />
  <Properties>
    <DisplayName>ms-resource:AppName</DisplayName>
    <PublisherDisplayName>Microsoft Corporation</PublisherDisplayName>
    <Logo>Assets\StoreLogo.png</Logo>
  </Properties>
  <Applications>
    <Application Id="App" Executable="Calculator.exe" EntryPoint="Calculator.App" />
  </Applications>
  <Capabilities>
    <Capability Name="internetClient" />
  </Capabilities>
</Package>`)
	got, err := ParseAppxManifest(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.IdentityName != "Microsoft.WindowsCalculator" {
		t.Fatalf("identity=%q", got.IdentityName)
	}
	if got.IdentityVersion != "11.2306.1.0" {
		t.Fatalf("version=%q", got.IdentityVersion)
	}
	if got.IdentityArchitecture != "x64" {
		t.Fatalf("arch=%q", got.IdentityArchitecture)
	}
	if got.IdentityPublisherCN != "Microsoft Corporation" {
		t.Fatalf("cn=%q", got.IdentityPublisherCN)
	}
	if !got.IsMicrosoftPublisher {
		t.Fatal("MS publisher must flag")
	}
	if got.IsSideloaded {
		t.Fatal("MS publisher must NOT flag sideloaded")
	}
	if got.ApplicationCount != 1 || got.PrimaryExecutable != "Calculator.exe" {
		t.Fatalf("apps: count=%d exec=%q", got.ApplicationCount, got.PrimaryExecutable)
	}
	if got.PublisherDisplayName != "Microsoft Corporation" {
		t.Fatalf("publisher display=%q", got.PublisherDisplayName)
	}
	if len(got.Capabilities) != 1 || got.Capabilities[0] != "internetClient" {
		t.Fatalf("capabilities=%v", got.Capabilities)
	}
	if got.HasRestrictedCapability {
		t.Fatal("internetClient must NOT flag restricted")
	}
}

// -- ParseAppxManifest sideloaded full-trust implant -----------------

func TestParseAppxManifestSideloadedFullTrust(t *testing.T) {
	body := []byte(`<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
         xmlns:rescap="http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities">
  <Identity Name="EvilCorp.Implant"
            Publisher="CN=EvilCorp, O=EvilCorp Ltd."
            Version="0.0.1.0"
            ProcessorArchitecture="x64" />
  <Applications>
    <Application Id="App" Executable="Implant.exe" EntryPoint="Windows.FullTrustApplication" />
  </Applications>
  <Capabilities>
    <rescap:Capability Name="runFullTrust" />
    <rescap:Capability Name="broadFileSystemAccess" />
  </Capabilities>
</Package>`)
	got, err := ParseAppxManifest(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.IdentityPublisherCN != "EvilCorp" {
		t.Fatalf("cn=%q", got.IdentityPublisherCN)
	}
	if !got.IsSideloaded {
		t.Fatal("EvilCorp publisher must flag sideloaded")
	}
	if !got.HasRunFullTrust || !got.HasBroadFileSystemAccess {
		t.Fatalf("restricted caps not picked up: %+v", got.Capabilities)
	}
	if !got.HasRestrictedCapability {
		t.Fatal("rollup must flip")
	}
}

// -- ParseAppxManifest BOM tolerance --------------------------------

func TestParseAppxManifestBOMTolerance(t *testing.T) {
	body := append([]byte{0xEF, 0xBB, 0xBF},
		[]byte(`<Package><Identity Name="X" Version="1.0.0.0" Publisher="CN=X"/></Package>`)...)
	got, err := ParseAppxManifest(body)
	if err != nil {
		t.Fatalf("BOM should be tolerated: %v", err)
	}
	if got.IdentityName != "X" {
		t.Fatalf("name=%q", got.IdentityName)
	}
}

// -- ParseAppxManifest error paths -----------------------------------

func TestParseAppxManifestEmpty(t *testing.T) {
	if _, err := ParseAppxManifest(nil); err == nil {
		t.Fatal("empty must error")
	}
}

func TestParseAppxManifestMalformed(t *testing.T) {
	// xml.Decoder Strict=false is permissive; non-XML payloads
	// either error or produce an empty Package. Verify no panic.
	got, err := ParseAppxManifest([]byte("not xml"))
	if err != nil {
		return
	}
	if got.IdentityName != "" {
		t.Fatalf("garbage must NOT populate identity: %q", got.IdentityName)
	}
}

// -- collector end-to-end -------------------------------------------

func TestFileCollectorWalksWindowsApps(t *testing.T) {
	tmp := t.TempDir()

	mscalc := filepath.Join(tmp, "Microsoft.WindowsCalculator_11.2306.1.0_x64__8wekyb3d8bbwe")
	must(t, os.MkdirAll(mscalc, 0o755))
	must(t, os.WriteFile(filepath.Join(mscalc, "AppxManifest.xml"), []byte(`<Package
  xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10">
<Identity Name="Microsoft.WindowsCalculator" Version="11.2306.1.0"
          Publisher="CN=Microsoft Corporation" ProcessorArchitecture="x64"/>
<Applications><Application Id="App" Executable="Calculator.exe"/></Applications>
<Capabilities><Capability Name="internetClient"/></Capabilities>
</Package>`), 0o644))

	evil := filepath.Join(tmp, "EvilCorp.Implant_0.0.1.0_x64__abcdef")
	must(t, os.MkdirAll(evil, 0o755))
	must(t, os.WriteFile(filepath.Join(evil, "AppxManifest.xml"), []byte(`<Package
  xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
  xmlns:rescap="http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities">
<Identity Name="EvilCorp.Implant" Version="0.0.1.0"
          Publisher="CN=EvilCorp" ProcessorArchitecture="x64"/>
<Applications><Application Id="App" Executable="Implant.exe"/></Applications>
<Capabilities><rescap:Capability Name="runFullTrust"/></Capabilities>
</Package>`), 0o644))

	// Missing AppxManifest dir — must be skipped silently.
	must(t, os.MkdirAll(filepath.Join(tmp, "BrokenPackage_0.0.0.0_x64__x"), 0o755))

	// Hidden dir must be skipped.
	must(t, os.MkdirAll(filepath.Join(tmp, ".hidden"), 0o755))

	c := &fileCollector{
		machineWideRoot: tmp,
		readFile:        os.ReadFile,
		readDir:         os.ReadDir,
		statFile:        os.Stat,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 packages, got %d: %+v", len(got), got)
	}

	byName := map[string]Package{}
	for _, p := range got {
		byName[p.IdentityName] = p
	}

	calc := byName["Microsoft.WindowsCalculator"]
	if !calc.IsMicrosoftPublisher || calc.IsSideloaded {
		t.Fatalf("calc flags wrong: %+v", calc)
	}
	if calc.HasRunFullTrust {
		t.Fatal("calc must not flag full-trust")
	}
	if !strings.HasSuffix(calc.PackageFullName, "8wekyb3d8bbwe") {
		t.Fatalf("package_full_name=%q", calc.PackageFullName)
	}
	if calc.InstallScope != ScopeMachineWide {
		t.Fatalf("scope=%q", calc.InstallScope)
	}
	if calc.FileHash == "" {
		t.Fatal("calc file_hash must be populated")
	}

	evilPkg := byName["EvilCorp.Implant"]
	if !evilPkg.IsSideloaded || !evilPkg.HasRunFullTrust {
		t.Fatalf("evil flags wrong: %+v", evilPkg)
	}
}

func TestFileCollectorMissingRootOK(t *testing.T) {
	c := &fileCollector{
		machineWideRoot: "/nope",
		readFile:        os.ReadFile,
		readDir:         os.ReadDir,
		statFile:        os.Stat,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("missing must not error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want empty, got %d", len(got))
	}
}

// -- SortPackages ---------------------------------------------------

func TestSortPackagesDeterministic(t *testing.T) {
	in := []Package{
		{IdentityName: "B", IdentityVersion: "2.0.0.0"},
		{IdentityName: "A", IdentityVersion: "1.0.0.0"},
		{IdentityName: "A", IdentityVersion: "2.0.0.0"},
	}
	SortPackages(in)
	if in[0].IdentityName != "A" || in[0].IdentityVersion != "1.0.0.0" {
		t.Fatalf("first=%+v", in[0])
	}
}

// -- EncodeStringList -----------------------------------------------

func TestEncodeStringList(t *testing.T) {
	if EncodeStringList(nil) != "[]" {
		t.Fatal("nil must emit []")
	}
	got := EncodeStringList([]string{"runFullTrust", "internetClient"})
	if !strings.Contains(got, "runFullTrust") {
		t.Fatalf("got %q", got)
	}
}

// -- helpers --------------------------------------------------------

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
