package winofficec2r

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindC2RConfigurationXML), "c2r-configuration-xml"},
		{string(KindC2RInventoryXML), "c2r-inventory-xml"},
		{string(KindC2RLicenseXML), "c2r-license-xml"},
		{string(KindC2RAppvManifest), "c2r-appv-manifest"},
		{string(KindOSPPDstatusTxt), "ospp-dstatus-txt"},
		{string(KindUserLicenseBin), "user-license-bin"},
		{string(KindOther), "other"},
		{string(KindUnknown), "unknown"},
		{string(ChannelMonthlyEnterprise), "monthlyenterprise"},
		{string(ChannelSemiAnnualEnterprise), "semiannualenterprise"},
		{string(ChannelCurrent), "current"},
		{string(ChannelCurrentPreview), "currentpreview"},
		{string(ChannelBeta), "beta"},
		{string(ChannelPerpetualVL2021), "perpetualvl2021"},
		{string(ChannelPerpetualVL2024), "perpetualvl2024"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestIsCandidateName(t *testing.T) {
	yes := []string{
		"Configuration.xml",
		"configuration-prod.xml",
		"inventory.xml",
		"office-license.xml",
		"ospp_dstatus_LAPTOP01.txt",
		"AppvManifest.xml",
		"userlicense.bin",
	}
	no := []string{"", "factura.xml", "cv.docx", "random.bin"}
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

func TestArtifactKindFromPath(t *testing.T) {
	cases := map[string]ArtifactKind{
		`C:\ODT\Configuration.xml`:                                                                     KindC2RConfigurationXML,
		`C:\ProgramData\Microsoft\ClickToRun\Inventory\inventory.xml`:                                  KindC2RInventoryXML,
		`C:\Program Files\Microsoft Office\root\Office16\Licenses\ProPlusVL_KMS_Client-ppd.xrm-ms.xml`: KindC2RLicenseXML,
		`C:\Program Files\Common Files\Microsoft Shared\ClickToRun\AppvManifest.xml`:                   KindC2RAppvManifest,
		`C:\Admin\inventory\office\ospp_dstatus_LAPTOP01.txt`:                                          KindOSPPDstatusTxt,
		`C:\Users\alice\AppData\Local\Microsoft\Office\Licenses\license.bin`:                           KindUserLicenseBin,
		`C:\Program Files\Microsoft Office\root\Office16\Licenses\some.bin`:                            KindUserLicenseBin,
		`C:\random\path.xml`: KindOther,
		``:                   KindUnknown,
	}
	for in, want := range cases {
		if got := ArtifactKindFromPath(in); got != want {
			t.Fatalf("ArtifactKindFromPath(%q)=%q want %q", in, got, want)
		}
	}
}

func TestChannelFromText(t *testing.T) {
	cases := map[string]Channel{
		"MonthlyEnterprise":           ChannelMonthlyEnterprise,
		"MonthlyEnterpriseChannel":    ChannelMonthlyEnterprise,
		"SemiAnnualEnterprise":        ChannelSemiAnnualEnterprise,
		"SemiAnnualEnterpriseChannel": ChannelSemiAnnualEnterprise,
		"SemiAnnual":                  ChannelSemiAnnualEnterprise,
		"Current":                     ChannelCurrent,
		"CurrentPreview":              ChannelCurrentPreview,
		"MonthlyChannelPreview":       ChannelCurrentPreview,
		"Beta":                        ChannelBeta,
		"InsiderFast":                 ChannelBeta,
		"PerpetualVL2019":             ChannelPerpetualVL2019,
		"PerpetualVL2021":             ChannelPerpetualVL2021,
		"PerpetualVL2024":             ChannelPerpetualVL2024,
		"":                            ChannelEmpty,
		"SomeCustom":                  ChannelOther,
	}
	for in, want := range cases {
		if got := ChannelFromText(in); got != want {
			t.Fatalf("ChannelFromText(%q)=%q want %q", in, got, want)
		}
	}
}

func TestIsEnterpriseChannelValue(t *testing.T) {
	yes := []Channel{
		ChannelMonthlyEnterprise,
		ChannelSemiAnnualEnterprise,
		ChannelPerpetualVL2019,
		ChannelPerpetualVL2021,
		ChannelPerpetualVL2024,
	}
	no := []Channel{
		ChannelCurrent, ChannelCurrentPreview, ChannelBeta,
		ChannelOther, ChannelUnknown, ChannelEmpty,
	}
	for _, v := range yes {
		if !IsEnterpriseChannelValue(v) {
			t.Fatalf("expected enterprise: %q", v)
		}
	}
	for _, v := range no {
		if IsEnterpriseChannelValue(v) {
			t.Fatalf("expected NOT enterprise: %q", v)
		}
	}
}

func TestIsPerpetualChannelValue(t *testing.T) {
	yes := []Channel{
		ChannelPerpetualVL2019,
		ChannelPerpetualVL2021,
		ChannelPerpetualVL2024,
	}
	no := []Channel{
		ChannelMonthlyEnterprise, ChannelSemiAnnualEnterprise,
		ChannelCurrent, ChannelBeta, ChannelEmpty,
	}
	for _, v := range yes {
		if !IsPerpetualChannelValue(v) {
			t.Fatalf("expected perpetual: %q", v)
		}
	}
	for _, v := range no {
		if IsPerpetualChannelValue(v) {
			t.Fatalf("expected NOT perpetual: %q", v)
		}
	}
}

func TestIsBetaChannelValue(t *testing.T) {
	yes := []Channel{ChannelBeta, ChannelCurrentPreview}
	no := []Channel{
		ChannelMonthlyEnterprise, ChannelCurrent,
		ChannelPerpetualVL2021, ChannelEmpty,
	}
	for _, v := range yes {
		if !IsBetaChannelValue(v) {
			t.Fatalf("expected beta: %q", v)
		}
	}
	for _, v := range no {
		if IsBetaChannelValue(v) {
			t.Fatalf("expected NOT beta: %q", v)
		}
	}
}

func TestProductIDFlags(t *testing.T) {
	cases := []struct {
		check func(Row) bool
		pid   string
	}{
		{pid: "VisioPro2019Retail", check: func(r Row) bool { return r.HasVisio }},
		{pid: "VisioStdRetail", check: func(r Row) bool { return r.HasVisio }},
		{pid: "ProjectPro2024Volume", check: func(r Row) bool { return r.HasProject }},
		{pid: "AccessRuntimeRetail", check: func(r Row) bool { return r.HasAccess }},
		{pid: "PublisherRetail", check: func(r Row) bool { return r.HasPublisher }},
		{pid: "SkypeforBusinessEntryRetail", check: func(r Row) bool { return r.HasSkypeForBusiness }},
		{pid: "Skype2019Retail", check: func(r Row) bool { return r.HasSkypeForBusiness }},
	}
	for _, c := range cases {
		var r Row
		if !ProductIDFlags(&r, c.pid) {
			t.Fatalf("ProductIDFlags(%q) must succeed", c.pid)
		}
		if !c.check(r) {
			t.Fatalf("ProductIDFlags(%q) wrong field", c.pid)
		}
	}
	var r Row
	if ProductIDFlags(&r, "O365ProPlusRetail") {
		t.Fatal("base SKU O365ProPlusRetail should NOT match per-product flags")
	}
}

func TestExcludedAppToField(t *testing.T) {
	var r Row
	if !ExcludedAppToField(&r, "Groove") {
		t.Fatal("Groove must succeed")
	}
	if !r.HasGrooveExcluded {
		t.Fatal("Groove sets HasGrooveExcluded")
	}
	if !ExcludedAppToField(&r, "Lync") {
		t.Fatal("Lync must succeed")
	}
	if !r.HasLyncExcluded {
		t.Fatal("Lync sets HasLyncExcluded")
	}
	if ExcludedAppToField(&r, "UnknownApp") {
		t.Fatal("unknown app must return false")
	}
}

// -- ParseConfiguration -------------------------------------------

func TestParseConfigurationProPlus(t *testing.T) {
	body := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<Configuration ID="00000000-1234-5678-9abc-def012345678">
  <Add OfficeClientEdition="64" Channel="MonthlyEnterprise">
    <Product ID="O365ProPlusRetail">
      <Language ID="en-us"/>
      <Language ID="es-es"/>
      <ExcludeApp ID="Groove"/>
      <ExcludeApp ID="Lync"/>
    </Product>
    <Product ID="VisioPro2019Retail">
      <Language ID="en-us"/>
    </Product>
  </Add>
  <RemoveMSI/>
  <Display Level="None" AcceptEULA="TRUE"/>
  <Property Name="SharedComputerLicensing" Value="1"/>
  <Property Name="AUTOACTIVATE" Value="1"/>
</Configuration>`)
	cf, ok := ParseConfiguration(body)
	if !ok {
		t.Fatal("must parse")
	}
	if cf.Channel != "MonthlyEnterprise" {
		t.Fatalf("channel=%q", cf.Channel)
	}
	if cf.OfficeClientEdition != "64" {
		t.Fatalf("edition=%q", cf.OfficeClientEdition)
	}
	if len(cf.Products) != 2 {
		t.Fatalf("products=%d want 2", len(cf.Products))
	}
	if len(cf.Languages) != 2 {
		t.Fatalf("languages=%d want 2", len(cf.Languages))
	}
	if len(cf.ExcludedApps) != 2 {
		t.Fatalf("excluded=%d want 2", len(cf.ExcludedApps))
	}
	if !HasSharedComputerLicensingFromProps(cf.Properties) {
		t.Fatal("SharedComputerLicensing must be detected")
	}
}

func TestParseConfigurationEmpty(t *testing.T) {
	if _, ok := ParseConfiguration([]byte("")); ok {
		t.Fatal("empty must NOT parse")
	}
}

func TestParseConfigurationNonXML(t *testing.T) {
	if _, ok := ParseConfiguration([]byte(`{"foo":"bar"}`)); ok {
		t.Fatal("non-XML must NOT parse")
	}
}

// -- AnnotateSecurity ---------------------------------------------

func TestAnnotateAlwaysPII(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC) }
	r := Row{
		ArtifactKind: KindC2RConfigurationXML,
		ProductID:    "O365ProPlusRetail",
		Channel:      ChannelMonthlyEnterprise,
		FileMode:     0o644,
	}
	AnnotateSecurityWithClock(&r, now)
	if !r.IsPIIHandling {
		t.Fatal("Office always handles PII")
	}
	if !r.IsEnterpriseChannel {
		t.Fatal("MonthlyEnterprise must flag enterprise")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("readable + product_id + PII = exposure")
	}
}

func TestAnnotatePerpetualChannel(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC) }
	r := Row{
		ArtifactKind: KindC2RConfigurationXML,
		ProductID:    "ProPlus2021Volume",
		Channel:      ChannelPerpetualVL2021,
		FileMode:     0o600,
	}
	AnnotateSecurityWithClock(&r, now)
	if !r.IsPerpetualChannel {
		t.Fatal("PerpetualVL2021 must flag")
	}
	if !r.IsEnterpriseChannel {
		t.Fatal("Perpetual is also enterprise")
	}
	if r.IsCredentialExposureRisk {
		t.Fatal("0o600 must NOT flag exposure")
	}
}

func TestAnnotateBetaChannel(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC) }
	r := Row{
		ArtifactKind: KindC2RConfigurationXML,
		ProductID:    "O365ProPlusRetail",
		Channel:      ChannelBeta,
		FileMode:     0o644,
	}
	AnnotateSecurityWithClock(&r, now)
	if !r.IsBetaChannel {
		t.Fatal("Beta must flag")
	}
}

func TestAnnotateRecentInstall(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC) }
	r := Row{
		ArtifactKind:        KindC2RConfigurationXML,
		ProductID:           "O365ProPlusRetail",
		InstallDateYYYYMMDD: "20260601",
		FileMode:            0o644,
	}
	AnnotateSecurityWithClock(&r, now)
	if !r.HasRecentInstall {
		t.Fatalf("2026-06-01 within 30d: %+v", r)
	}
}

func TestAnnotateOldInstall(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC) }
	r := Row{
		ArtifactKind:        KindC2RConfigurationXML,
		ProductID:           "O365ProPlusRetail",
		InstallDateYYYYMMDD: "20240101",
		FileMode:            0o644,
	}
	AnnotateSecurityWithClock(&r, now)
	if r.HasRecentInstall {
		t.Fatal("> 30d old must NOT flag")
	}
}

func TestAnnotateNoProductIDNoExposure(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC) }
	r := Row{
		ArtifactKind: KindC2RConfigurationXML,
		FileMode:     0o644,
	}
	AnnotateSecurityWithClock(&r, now)
	if r.IsCredentialExposureRisk {
		t.Fatal("no product_id must NOT flag exposure")
	}
}

// -- collector end-to-end -----------------------------------------

func TestCollectorWalksOfficeTree(t *testing.T) {
	tmp := t.TempDir()
	odtDir := filepath.Join(tmp, "ODT")
	must(t, os.MkdirAll(odtDir, 0o755))

	// Configuration.xml with O365 + Visio + Shared-Computer
	// Licensing, world-readable.
	cfgPath := filepath.Join(odtDir, "Configuration.xml")
	must(t, os.WriteFile(cfgPath, []byte(`<?xml version="1.0"?>
<Configuration ID="00000000-1234-5678-9abc-def012345678">
  <Add OfficeClientEdition="64" Channel="MonthlyEnterprise">
    <Product ID="O365ProPlusRetail">
      <Language ID="en-us"/>
      <Language ID="es-es"/>
      <ExcludeApp ID="Groove"/>
      <ExcludeApp ID="Lync"/>
    </Product>
    <Product ID="VisioPro2019Retail">
      <Language ID="en-us"/>
    </Product>
    <Product ID="ProjectPro2024Volume">
      <Language ID="en-us"/>
    </Product>
  </Add>
  <RemoveMSI/>
  <Display Level="None" AcceptEULA="TRUE"/>
  <Property Name="SharedComputerLicensing" Value="1"/>
</Configuration>`), 0o644))

	// Random ignored.
	must(t, os.WriteFile(filepath.Join(odtDir, "random.bin"),
		[]byte(`noise`), 0o644))

	c := &fileCollector{
		installRoots: []string{tmp},
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
	if len(got) != 1 {
		t.Fatalf("want 1 (configuration), got %d: %+v", len(got), got)
	}
	row := got[0]
	if row.ArtifactKind != KindC2RConfigurationXML {
		t.Fatalf("kind=%q", row.ArtifactKind)
	}
	if row.Channel != ChannelMonthlyEnterprise {
		t.Fatalf("channel=%q", row.Channel)
	}
	if row.OfficeClientEdition != "64" {
		t.Fatalf("edition=%q", row.OfficeClientEdition)
	}
	if row.ProductsCount != 3 {
		t.Fatalf("products=%d want 3", row.ProductsCount)
	}
	if row.LanguagesCount != 2 {
		t.Fatalf("languages=%d want 2", row.LanguagesCount)
	}
	if row.ExcludedAppsCount != 2 {
		t.Fatalf("excluded=%d want 2", row.ExcludedAppsCount)
	}
	if !row.HasVisio {
		t.Fatal("Visio must flag")
	}
	if !row.HasProject {
		t.Fatal("Project must flag")
	}
	if !row.HasGrooveExcluded {
		t.Fatal("Groove excluded must flag")
	}
	if !row.HasLyncExcluded {
		t.Fatal("Lync excluded must flag")
	}
	if !row.HasSharedComputerLic {
		t.Fatal("SharedComputerLicensing must flag")
	}
	if !row.IsEnterpriseChannel {
		t.Fatal("MonthlyEnterprise must flag enterprise")
	}
	if !row.IsPIIHandling {
		t.Fatal("Office always handles PII")
	}
	if !row.IsCredentialExposureRisk {
		t.Fatalf("readable + product + PII = exposure: %+v", row)
	}
}

func TestCollectorRespectsEnv(t *testing.T) {
	tmp := t.TempDir()
	envDir := filepath.Join(tmp, "custom-office")
	must(t, os.MkdirAll(envDir, 0o755))
	must(t, os.WriteFile(filepath.Join(envDir, "Configuration.xml"),
		[]byte(`<?xml version="1.0"?>
<Configuration>
  <Add OfficeClientEdition="64" Channel="Current">
    <Product ID="O365ProPlusRetail">
      <Language ID="en-us"/>
    </Product>
  </Add>
</Configuration>`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "OFFICE_C2R_DIR" {
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
	if len(got) != 1 || got[0].ArtifactKind != KindC2RConfigurationXML {
		t.Fatalf("env: %+v", got)
	}
	if got[0].Channel != ChannelCurrent {
		t.Fatalf("env channel=%q", got[0].Channel)
	}
}

func TestCollectorMissingPathsOK(t *testing.T) {
	c := &fileCollector{
		installRoots: []string{"/nope-office"},
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
		{FilePath: "z", ArtifactKind: KindC2RConfigurationXML, ProductID: "z"},
		{FilePath: "a", ArtifactKind: KindC2RConfigurationXML, ProductID: "z"},
		{FilePath: "a", ArtifactKind: KindC2RConfigurationXML, ProductID: "a"},
	}
	SortRows(in)
	if in[0].FilePath != "a" || in[0].ProductID != "a" {
		t.Fatalf("first=%+v", in[0])
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
