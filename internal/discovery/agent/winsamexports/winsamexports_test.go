package winsamexports

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(ToolSCCM), "sccm"},
		{string(ToolIntune), "intune"},
		{string(ToolLansweeper), "lansweeper"},
		{string(ToolSnowLM), "snow-lm"},
		{string(ToolFlexera), "flexera"},
		{string(ToolDesktopCentral), "desktop-central"},
		{string(ToolBigFix), "bigfix"},
		{string(ToolWingetExport), "winget-export"},
		{string(ToolChocolateyList), "chocolatey-list"},
		{string(ToolGLPI), "glpi"},
		{string(ToolOCSInventory), "ocs-inventory"},
		{string(ToolGenericCSV), "generic-csv"},
		{string(ToolOther), "other"},
		{string(ToolUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestIsCandidateName(t *testing.T) {
	yes := []string{
		"sccm_software_LAPTOP01_20260615.csv",
		"intune_software_202606.json",
		"lansweeper_software_20260615.csv",
		"snow_inventory_20260615.xml",
		"flexera_inventory_20260615.csv",
		"desktopcentral_software_20260615.csv",
		"bigfix_software_20260615.csv",
		"winget-export.json",
		"choco-list-20260615.csv",
		"glpi_software_20260615.csv",
		"ocs_software_20260615.csv",
		"software_inventory_20260615.csv",
		"installed_software_LAPTOP01.csv",
	}
	no := []string{"", "factura.xml", "random.csv", "cv.docx"}
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

func TestToolKindFromName(t *testing.T) {
	cases := map[string]ToolKind{
		"sccm_software_LAPTOP01.csv":           ToolSCCM,
		"intune_software_202606.json":          ToolIntune,
		"lansweeper_software_20260615.csv":     ToolLansweeper,
		"snow_inventory_20260615.xml":          ToolSnowLM,
		"snowlm-export.csv":                    ToolSnowLM,
		"flexera_inventory_20260615.csv":       ToolFlexera,
		"desktopcentral_software_20260615.csv": ToolDesktopCentral,
		"dc_software_20260615.csv":             ToolDesktopCentral,
		"bigfix_software_20260615.csv":         ToolBigFix,
		"winget-export.json":                   ToolWingetExport,
		"choco-list-20260615.csv":              ToolChocolateyList,
		"glpi_software_20260615.csv":           ToolGLPI,
		"ocs_software_20260615.csv":            ToolOCSInventory,
		"software_inventory_20260615.csv":      ToolGenericCSV,
		"asset_software_LAPTOP01.csv":          ToolOther,
		"":                                     ToolUnknown,
	}
	for in, want := range cases {
		if got := ToolKindFromName(in); got != want {
			t.Fatalf("ToolKindFromName(%q)=%q want %q", in, got, want)
		}
	}
}

func TestHashHostname(t *testing.T) {
	hash := HashHostname("LAPTOP-ALICE")
	if hash == "" {
		t.Fatal("hash must be non-empty")
	}
	if !strings.HasPrefix(hash, "sha256:") {
		t.Fatalf("hash must be sha256-prefixed, got %q", hash)
	}
	if strings.Contains(hash, "LAPTOP") {
		t.Fatal("must NEVER return the raw hostname")
	}
	// Case-insensitive normalisation.
	if HashHostname("laptop-alice") != hash {
		t.Fatal("hash must be lowercase-normalised")
	}
}

func TestHostnameFromText(t *testing.T) {
	cases := map[string]string{
		"Hostname,LAPTOP-ALICE\nDisplayName,...":    "LAPTOP-ALICE",
		"<computer_name>SRV-FIN-01</computer_name>": "SRV-FIN-01",
		"asset_name: WS-PYME-007":                   "WS-PYME-007",
		"no hostname here":                          "",
	}
	for in, want := range cases {
		if got := HostnameFromText(in); got != want {
			t.Fatalf("HostnameFromText(%q)=%q want %q", in, got, want)
		}
	}
}

func TestInventoryTimestampFromText(t *testing.T) {
	cases := map[string]string{
		"InventoryDate: 2026-06-15":                            "2026-06-15",
		"<scan_timestamp>2026-06-15T13:00:00</scan_timestamp>": "2026-06-15T13:00:00",
		"Generated at 2026-06-15 12:00:00":                     "2026-06-15 12:00:00",
		"Exported_at = 2026-06-15":                             "2026-06-15",
		"no inventory ts":                                      "",
	}
	for in, want := range cases {
		if got := InventoryTimestampFromText(in); got != want {
			t.Fatalf("InventoryTimestampFromText(%q)=%q want %q", in, got, want)
		}
	}
}

func TestCountPIIRows(t *testing.T) {
	body := []byte(`DisplayName,Publisher,Version
Microsoft Outlook,Microsoft,16.0
Google Chrome,Google,120
QuickBooks Pro,Intuit,2025
Visual Studio,Microsoft,2022
Adobe Photoshop,Adobe,25
`)
	got := CountPIIRows(body)
	// Outlook (PII), Chrome (PII), QuickBooks (financial).
	// Visual Studio is dev-tool, NOT in PII catalogue.
	// Adobe Photoshop is media tool, NOT in PII catalogue.
	if got != 3 {
		t.Fatalf("CountPIIRows=%d want 3", got)
	}
}

func TestCountUnlicensedRows(t *testing.T) {
	body := []byte(`DisplayName,Status
Microsoft Office,Licensed
Adobe Photoshop,Unlicensed
QuickBooks,License expired
Slack,Licensed
`)
	got := CountUnlicensedRows(body)
	if got != 2 {
		t.Fatalf("CountUnlicensedRows=%d want 2", got)
	}
}

func TestSoftwareRowCount(t *testing.T) {
	body := []byte(`DisplayName,Publisher,Version
Microsoft Outlook,Microsoft,16.0
Google Chrome,Google,120
QuickBooks Pro,Intuit,2025
`)
	if got := SoftwareRowCount(body); got != 3 {
		t.Fatalf("SoftwareRowCount=%d want 3", got)
	}
}

// -- AnnotateSecurity ---------------------------------------------

func TestAnnotatePIIExposure(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC) }
	r := Row{
		ToolKind:          ToolSCCM,
		AssetHostnameHash: "sha256:abc",
		PIISoftwareCount:  5,
		FileMode:          0o644,
	}
	AnnotateSecurityWithClock(&r, now)
	if !r.HasPIISoftware {
		t.Fatal("PII count > 0 must flag")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("hostname + PII + readable = exposure")
	}
}

func TestAnnotateUnlicensedExposure(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC) }
	r := Row{
		ToolKind:          ToolFlexera,
		AssetHostnameHash: "sha256:abc",
		UnlicensedCount:   3,
		FileMode:          0o644,
	}
	AnnotateSecurityWithClock(&r, now)
	if !r.HasUnlicensedSoftware {
		t.Fatal("unlicensed count > 0 must flag")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("hostname + unlicensed + readable = exposure")
	}
}

func TestAnnotateStaleInventory(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC) }
	r := Row{
		ToolKind:           ToolSCCM,
		InventoryTimestamp: "2025-01-01",
		FileMode:           0o600,
	}
	AnnotateSecurityWithClock(&r, now)
	if !r.IsStaleInventory {
		t.Fatalf("inventory > 90d old must flag stale: %+v", r)
	}
	if r.InventoryAgeDays < 90 {
		t.Fatalf("inventory_age_days=%d should be > 90", r.InventoryAgeDays)
	}
}

func TestAnnotateFreshInventory(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC) }
	r := Row{
		ToolKind:           ToolSCCM,
		InventoryTimestamp: "2026-06-01",
		FileMode:           0o600,
	}
	AnnotateSecurityWithClock(&r, now)
	if r.IsStaleInventory {
		t.Fatal("fresh inventory must NOT flag stale")
	}
}

func TestAnnotateLockedDownClean(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC) }
	r := Row{
		ToolKind:          ToolSCCM,
		AssetHostnameHash: "sha256:abc",
		PIISoftwareCount:  5,
		FileMode:          0o600,
	}
	AnnotateSecurityWithClock(&r, now)
	if r.IsCredentialExposureRisk {
		t.Fatal("0o600 must NOT flag exposure")
	}
}

func TestAnnotateNoHostnameNoExposure(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC) }
	r := Row{
		ToolKind:         ToolSCCM,
		PIISoftwareCount: 5,
		FileMode:         0o644,
	}
	AnnotateSecurityWithClock(&r, now)
	if r.IsCredentialExposureRisk {
		t.Fatal("no hostname must NOT flag exposure")
	}
}

// -- collector end-to-end -----------------------------------------

func TestCollectorWalksTree(t *testing.T) {
	tmp := t.TempDir()
	root := filepath.Join(tmp, "ProgramData", "Lansweeper")
	must(t, os.MkdirAll(root, 0o755))

	// SCCM-style export with hostname + PII software, readable.
	sccmPath := filepath.Join(root, "sccm_software_LAPTOP01_20260615.csv")
	must(t, os.WriteFile(sccmPath, []byte(`Hostname,LAPTOP01
ScanTimestamp,2026-06-15
DisplayName,Publisher,Version
Microsoft Outlook,Microsoft,16.0
Google Chrome,Google,120
QuickBooks Pro,Intuit,2025
Visual Studio Code,Microsoft,1.85
`), 0o644))

	// Flexera with unlicensed software, locked down.
	flexPath := filepath.Join(root, "flexera_inventory_20260615.csv")
	must(t, os.WriteFile(flexPath, []byte(`Hostname,SRV-FIN-01
DisplayName,Status
Microsoft Office,Licensed
Adobe Photoshop,Unlicensed
`), 0o600))

	// Random ignored.
	must(t, os.WriteFile(filepath.Join(root, "random.csv"),
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
		t.Fatalf("want 2 (sccm+flexera), got %d: %+v", len(got), got)
	}

	var sccm, flex Row
	for _, r := range got {
		switch r.FilePath {
		case sccmPath:
			sccm = r
		case flexPath:
			flex = r
		}
	}
	if sccm.ToolKind != ToolSCCM {
		t.Fatalf("sccm kind=%q", sccm.ToolKind)
	}
	if sccm.AssetHostnameHash == "" {
		t.Fatal("sccm hostname hash must be set")
	}
	if strings.Contains(sccm.AssetHostnameHash, "LAPTOP01") {
		t.Fatalf("sccm hostname must NEVER be raw: %q", sccm.AssetHostnameHash)
	}
	if sccm.PIISoftwareCount < 3 {
		t.Fatalf("sccm PII count=%d want >=3", sccm.PIISoftwareCount)
	}
	if !sccm.HasPIISoftware {
		t.Fatal("sccm must flag PII")
	}
	if !sccm.IsCredentialExposureRisk {
		t.Fatalf("sccm readable + hostname + PII = exposure: %+v", sccm)
	}
	if sccm.InventoryTimestamp != "2026-06-15" {
		t.Fatalf("sccm ts=%q", sccm.InventoryTimestamp)
	}

	if flex.ToolKind != ToolFlexera {
		t.Fatalf("flex kind=%q", flex.ToolKind)
	}
	if !flex.HasUnlicensedSoftware {
		t.Fatalf("flex must flag unlicensed: %+v", flex)
	}
	if flex.IsCredentialExposureRisk {
		t.Fatalf("0o600 must NOT flag: %+v", flex)
	}
}

func TestCollectorRespectsEnv(t *testing.T) {
	tmp := t.TempDir()
	envDir := filepath.Join(tmp, "custom-sam")
	must(t, os.MkdirAll(envDir, 0o755))
	must(t, os.WriteFile(filepath.Join(envDir, "sccm_software_LAPTOP.csv"),
		[]byte(`DisplayName,Publisher
Outlook,Microsoft
`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "SAM_EXPORTS_DIR" {
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
	if len(got) != 1 || got[0].ToolKind != ToolSCCM {
		t.Fatalf("env: %+v", got)
	}
}

func TestCollectorMissingPathsOK(t *testing.T) {
	c := &fileCollector{
		installRoots: []string{"/nope-sam"},
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
		{FilePath: "z", ToolKind: ToolSCCM},
		{FilePath: "a", ToolKind: ToolIntune},
		{FilePath: "a", ToolKind: ToolFlexera},
	}
	SortRows(in)
	if in[0].FilePath != "a" || in[0].ToolKind != ToolFlexera {
		t.Fatalf("first=%+v", in[0])
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
