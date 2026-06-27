package winsbom

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindSPDXJSON), "spdx-json"},
		{string(KindSPDXTagValue), "spdx-tag-value"},
		{string(KindSPDXYAML), "spdx-yaml"},
		{string(KindCycloneDXJSON), "cyclonedx-json"},
		{string(KindCycloneDXXML), "cyclonedx-xml"},
		{string(KindSWIDTag), "swid-tag"},
		{string(KindOther), "other"},
		{string(KindUnknown), "unknown"},
		{string(FormatSPDX22), "spdx-2.2"},
		{string(FormatSPDX23), "spdx-2.3"},
		{string(FormatSPDX30), "spdx-3.0"},
		{string(FormatCycloneDX14), "cyclonedx-1.4"},
		{string(FormatCycloneDX15), "cyclonedx-1.5"},
		{string(FormatCycloneDX16), "cyclonedx-1.6"},
		{string(FormatSWID197702), "swid-iso-19770-2"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestIsCandidateName(t *testing.T) {
	yes := []string{
		"project.spdx",
		"project.spdx.json",
		"project.spdx.yaml",
		"project.cdx.json",
		"project.bom.xml",
		"project.bom.json",
		"project.cyclonedx.json",
		"cyclonedx-1.5.json",
		"sbom-2026-06-15.json",
		"sbom.json",
		"sbom.xml",
		"product.swidtag",
	}
	no := []string{"", "factura.xml", "random.txt"}
	for _, v := range yes {
		if !IsCandidateName(v) {
			t.Fatalf("expected candidate: %q", v)
		}
	}
	for _, v := range no {
		if IsCandidateName(v) {
			t.Fatalf("expected NOT candidate: %q", v)
		}
	}
}

func TestArtifactKindFromName(t *testing.T) {
	cases := map[string]ArtifactKind{
		"project.spdx":           KindSPDXTagValue,
		"project.spdx.json":      KindSPDXJSON,
		"project.spdx.yaml":      KindSPDXYAML,
		"project.spdx.yml":       KindSPDXYAML,
		"project.cdx.json":       KindCycloneDXJSON,
		"project.cyclonedx.json": KindCycloneDXJSON,
		"project.bom.json":       KindCycloneDXJSON,
		"project.cdx.xml":        KindCycloneDXXML,
		"project.cyclonedx.xml":  KindCycloneDXXML,
		"product.swidtag":        KindSWIDTag,
		"sbom-2026.json":         KindOther,
		"":                       KindUnknown,
	}
	for in, want := range cases {
		if got := ArtifactKindFromName(in); got != want {
			t.Fatalf("ArtifactKindFromName(%q)=%q want %q", in, got, want)
		}
	}
}

func TestDetectFormat(t *testing.T) {
	cases := []struct {
		want SBOMFormat
		body []byte
	}{
		{want: FormatSPDX23, body: []byte(`{"spdxVersion": "SPDX-2.3"}`)},
		{want: FormatSPDX22, body: []byte(`SPDXVersion: SPDX-2.2`)},
		{want: FormatSPDX30, body: []byte(`{"spdxVersion": "SPDX-3.0"}`)},
		{want: FormatCycloneDX15, body: []byte(`{"specVersion": "1.5"}`)},
		{want: FormatCycloneDX16, body: []byte(`{"specVersion": "1.6"}`)},
		{want: FormatSWID197702, body: []byte(`<SoftwareIdentity name="Office">`)},
		{want: FormatSPDX23, body: []byte(`{"foo": "spdx wrapper"}`)},
		{want: FormatCycloneDX15, body: []byte(`{"foo": "cyclonedx wrapper"}`)},
		{want: FormatOther, body: []byte(`random`)},
		{want: FormatUnknown, body: []byte(``)},
	}
	for _, c := range cases {
		if got := DetectFormat(c.body); got != c.want {
			t.Fatalf("DetectFormat(%q)=%q want %q",
				string(c.body), got, c.want)
		}
	}
}

func TestCountVulnerableComponents(t *testing.T) {
	body := []byte(`vulnerabilities:
- CVE-2024-1234
- CVE-2025-99999
- not a cve: ABC-2024-1234
- CVE-2026-001234
`)
	if got := CountVulnerableComponents(body); got != 3 {
		t.Fatalf("CountVulnerableComponents=%d want 3", got)
	}
}

func TestCountComponentsSPDX(t *testing.T) {
	body := []byte(`SPDXVersion: SPDX-2.3
DocumentName: my-project
PackageName: package-a
SPDXID: SPDXRef-Package-A
PackageName: package-b
SPDXID: SPDXRef-Package-B
PackageName: package-c
SPDXID: SPDXRef-Package-C
`)
	if got := CountComponentsSPDX(body); got != 3 {
		t.Fatalf("CountComponentsSPDX=%d want 3", got)
	}
}

func TestCountOSSComponents(t *testing.T) {
	body := []byte(`{
"components": [
  {"name": "a", "license": "MIT"},
  {"name": "b", "license": "Apache-2.0"},
  {"name": "c", "license": "Proprietary"},
  {"name": "d", "license": "GPL-3.0"}
]
}`)
	got := CountOSSComponents(body)
	if got < 3 {
		t.Fatalf("CountOSSComponents=%d want >=3 (MIT/Apache/GPL)", got)
	}
}

func TestCountPIIComponents(t *testing.T) {
	body := []byte(`{"name": "Microsoft Outlook"}
{"name": "Google Chrome"}
{"name": "QuickBooks Pro"}
{"name": "Visual Studio"}
{"name": "Adobe Photoshop"}
`)
	got := CountPIIComponents(body)
	if got != 3 {
		t.Fatalf("CountPIIComponents=%d want 3 (Outlook/Chrome/QuickBooks)", got)
	}
}

func TestDocumentNameFromBody(t *testing.T) {
	cases := map[string]string{
		"DocumentName: my-spdx-doc": "my-spdx-doc",
		`{"metadata": {"component": {"name": "my-cdx-doc", "type": "application"}}}`: "my-cdx-doc",
		"no doc name": "",
	}
	for in, want := range cases {
		if got := DocumentNameFromBody([]byte(in)); got != want {
			t.Fatalf("DocumentNameFromBody(%q)=%q want %q", in, got, want)
		}
	}
}

func TestCreatorOrgFromBody(t *testing.T) {
	cases := map[string]string{
		"Creator: Organization: ACME Corp":                 "ACME Corp",
		`{"metadata": {"tools": [{"vendor": "Anchore"}]}}`: "Anchore",
		`{"supplier": {"name": "MyOrg"}}`:                  "MyOrg",
		"no creator":                                       "",
	}
	for in, want := range cases {
		if got := CreatorOrgFromBody([]byte(in)); got != want {
			t.Fatalf("CreatorOrgFromBody(%q)=%q want %q", in, got, want)
		}
	}
}

func TestCreationDateFromBody(t *testing.T) {
	cases := map[string]string{
		"Created: 2026-06-15":                  "20260615",
		`{"created": "2026-05-01T12:00:00Z"}`:  "20260501",
		`{"timestamp": "2026-04-20T09:00:00"}`: "20260420",
		"no created":                           "",
	}
	for in, want := range cases {
		if got := CreationDateFromBody([]byte(in)); got != want {
			t.Fatalf("CreationDateFromBody(%q)=%q want %q", in, got, want)
		}
	}
}

// -- AnnotateSecurity ---------------------------------------------

func TestAnnotatePIIExposure(t *testing.T) {
	r := Row{
		ArtifactKind:      KindCycloneDXJSON,
		ComponentCount:    100,
		PIIComponentCount: 5,
		FileMode:          0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasPIIComponents {
		t.Fatal("PII count > 0 must flag")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("readable + components + PII = exposure")
	}
}

func TestAnnotateVulnerableExposure(t *testing.T) {
	r := Row{
		ArtifactKind:             KindSPDXJSON,
		ComponentCount:           100,
		VulnerableComponentCount: 3,
		FileMode:                 0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasVulnerableComponents {
		t.Fatal("vulnerable count > 0 must flag")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("readable + components + vulnerable = exposure")
	}
}

func TestAnnotateOSS(t *testing.T) {
	r := Row{
		ArtifactKind:      KindSPDXJSON,
		ComponentCount:    100,
		OSSComponentCount: 50,
		FileMode:          0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasOSSComponents {
		t.Fatal("OSS count > 0 must flag")
	}
}

func TestAnnotateLockedDownClean(t *testing.T) {
	r := Row{
		ArtifactKind:      KindCycloneDXJSON,
		ComponentCount:    100,
		PIIComponentCount: 5,
		FileMode:          0o600,
	}
	AnnotateSecurity(&r)
	if r.IsCredentialExposureRisk {
		t.Fatal("0o600 must NOT flag exposure")
	}
}

func TestAnnotateEmptyComponentsNoExposure(t *testing.T) {
	r := Row{
		ArtifactKind:      KindCycloneDXJSON,
		ComponentCount:    0,
		PIIComponentCount: 5,
		FileMode:          0o644,
	}
	AnnotateSecurity(&r)
	if r.IsCredentialExposureRisk {
		t.Fatal("0 components must NOT flag exposure")
	}
}

// -- collector end-to-end -----------------------------------------

func TestCollectorWalksTree(t *testing.T) {
	tmp := t.TempDir()
	root := filepath.Join(tmp, "ProgramData", "SBOM")
	must(t, os.MkdirAll(root, 0o755))

	// CycloneDX JSON with PII + vulnerable + OSS, readable.
	cdxPath := filepath.Join(root, "myapp.cdx.json")
	must(t, os.WriteFile(cdxPath, []byte(`{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "serialNumber": "urn:uuid:1234",
  "metadata": {
    "timestamp": "2026-06-15T12:00:00Z",
    "tools": [{"vendor": "Anchore", "name": "syft", "version": "1.0"}],
    "component": {"type": "application", "name": "my-app"}
  },
  "components": [
    {"name": "Microsoft Outlook", "version": "16.0", "license": "Proprietary"},
    {"name": "google-chrome", "version": "120", "license": "BSD-3-Clause"},
    {"name": "quickbooks-sdk", "version": "1.0", "license": "Proprietary"},
    {"name": "lodash", "version": "4.17", "license": "MIT"}
  ],
  "vulnerabilities": [
    {"id": "CVE-2024-1234"},
    {"id": "CVE-2025-99999"}
  ]
}`), 0o644))

	// SPDX tag-value, locked down.
	spdxPath := filepath.Join(root, "infra.spdx")
	must(t, os.WriteFile(spdxPath, []byte(`SPDXVersion: SPDX-2.3
DataLicense: CC0-1.0
DocumentName: infra-sbom
DocumentNamespace: https://example.com/infra-sbom
Creator: Organization: ACME Corp
Created: 2026-05-01
PackageName: nginx
LicenseConcluded: BSD-2-Clause
PackageName: postgres
LicenseConcluded: PostgreSQL
`), 0o600))

	// Random ignored.
	must(t, os.WriteFile(filepath.Join(root, "random.txt"),
		[]byte(`noise`), 0o644))

	c := &fileCollector{
		installRoots: []string{root},
		usersBases:   nil,
		getenv:       func(string) string { return "" },
		readFile:     os.ReadFile,
		readDir:      os.ReadDir,
		statFile:     os.Stat,
		now:          func() time.Time { return time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC) },
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 (cdx+spdx), got %d: %+v", len(got), got)
	}

	var cdx, spdx Row
	for _, r := range got {
		switch r.FilePath {
		case cdxPath:
			cdx = r
		case spdxPath:
			spdx = r
		}
	}
	if cdx.ArtifactKind != KindCycloneDXJSON {
		t.Fatalf("cdx kind=%q", cdx.ArtifactKind)
	}
	if cdx.SBOMFormat != FormatCycloneDX15 {
		t.Fatalf("cdx format=%q", cdx.SBOMFormat)
	}
	if cdx.DocumentName != "my-app" {
		t.Fatalf("cdx doc=%q", cdx.DocumentName)
	}
	if cdx.CreatorOrg != "Anchore" {
		t.Fatalf("cdx creator=%q", cdx.CreatorOrg)
	}
	if cdx.CreationDateYYYYMMDD != "20260615" {
		t.Fatalf("cdx date=%q", cdx.CreationDateYYYYMMDD)
	}
	if cdx.ComponentCount < 3 {
		t.Fatalf("cdx components=%d want >=3", cdx.ComponentCount)
	}
	if cdx.PIIComponentCount < 3 {
		t.Fatalf("cdx PII=%d want >=3", cdx.PIIComponentCount)
	}
	if cdx.VulnerableComponentCount != 2 {
		t.Fatalf("cdx vuln=%d want 2", cdx.VulnerableComponentCount)
	}
	if !cdx.HasOSSComponents {
		t.Fatalf("cdx OSS must flag (BSD+MIT): %+v", cdx)
	}
	if !cdx.HasPIIComponents {
		t.Fatal("cdx must flag PII")
	}
	if !cdx.HasVulnerableComponents {
		t.Fatal("cdx must flag vulnerable")
	}
	if !cdx.IsCredentialExposureRisk {
		t.Fatalf("cdx readable + components + PII = exposure: %+v", cdx)
	}

	if spdx.ArtifactKind != KindSPDXTagValue {
		t.Fatalf("spdx kind=%q", spdx.ArtifactKind)
	}
	if spdx.SBOMFormat != FormatSPDX23 {
		t.Fatalf("spdx format=%q", spdx.SBOMFormat)
	}
	if spdx.DocumentName != "infra-sbom" {
		t.Fatalf("spdx doc=%q", spdx.DocumentName)
	}
	if spdx.CreatorOrg != "ACME Corp" {
		t.Fatalf("spdx creator=%q", spdx.CreatorOrg)
	}
	if spdx.ComponentCount != 2 {
		t.Fatalf("spdx components=%d want 2", spdx.ComponentCount)
	}
	if spdx.IsCredentialExposureRisk {
		t.Fatalf("0o600 must NOT flag: %+v", spdx)
	}
}

func TestCollectorRespectsEnv(t *testing.T) {
	tmp := t.TempDir()
	envDir := filepath.Join(tmp, "custom-sbom")
	must(t, os.MkdirAll(envDir, 0o755))
	must(t, os.WriteFile(filepath.Join(envDir, "x.spdx.json"),
		[]byte(`{"spdxVersion": "SPDX-2.3", "name": "x"}`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "SBOM_DIR" {
				return envDir
			}
			return ""
		},
		readFile: os.ReadFile,
		readDir:  os.ReadDir,
		statFile: os.Stat,
		now:      func() time.Time { return time.Now() },
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 1 || got[0].ArtifactKind != KindSPDXJSON {
		t.Fatalf("env: %+v", got)
	}
}

func TestCollectorMissingPathsOK(t *testing.T) {
	c := &fileCollector{
		installRoots: []string{"/nope-sbom"},
		usersBases:   []string{"/nope-users"},
		getenv:       func(string) string { return "" },
		readFile:     os.ReadFile,
		readDir:      os.ReadDir,
		statFile:     os.Stat,
		now:          func() time.Time { return time.Now() },
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("missing must not error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want empty, got %d", len(got))
	}
}

func TestSortRowsDeterministic(t *testing.T) {
	in := []Row{
		{FilePath: "z", ArtifactKind: KindSPDXJSON},
		{FilePath: "a", ArtifactKind: KindCycloneDXJSON},
		{FilePath: "a", ArtifactKind: KindSPDXJSON},
	}
	SortRows(in)
	if in[0].FilePath != "a" || in[0].ArtifactKind != KindCycloneDXJSON {
		t.Fatalf("first=%+v", in[0])
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
