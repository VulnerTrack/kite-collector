package winsoftwarelicences

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindLicKeyfile), "lic-keyfile"},
		{string(KindLicenseJSON), "license-json"},
		{string(KindLicenseXML), "license-xml"},
		{string(KindLicenseText), "license-text"},
		{string(KindEULAText), "eula-text"},
		{string(KindRegistrationDat), "registration-dat"},
		{string(KindPlistLicense), "plist-license"},
		{string(KindDpkgCopyright), "dpkg-copyright"},
		{string(KindOther), "other"},
		{string(KindUnknown), "unknown"},
		{string(LicensePerpetual), "perpetual"},
		{string(LicenseSubscription), "subscription"},
		{string(LicenseOSSMIT), "oss-mit"},
		{string(LicenseOSSApache), "oss-apache"},
		{string(LicenseOSSGPL), "oss-gpl"},
		{string(DPDSHandlesPII), "handles-pii"},
		{string(DPDSHandlesFinancial), "handles-financial"},
		{string(DPDSHandlesPHI), "handles-phi"},
		{string(DPDSHandlesPCI), "handles-pci"},
		{string(DPDSDevTool), "dev-tool"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestIsCandidateName(t *testing.T) {
	yes := []string{
		"product.lic",
		"license.dat",
		"LICENSE",
		"LICENSE.txt",
		"COPYING",
		"copyright",
		"EULA.txt",
		"license.json",
		"license.xml",
		"License.plist",
		"registration.dat",
		"activation.dat",
		"product.key",
	}
	no := []string{"", "factura.xml", "cv.docx", "random.dat"}
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
		"office.lic":       KindLicKeyfile,
		"product.key":      KindLicKeyfile,
		"license.json":     KindLicenseJSON,
		"license.xml":      KindLicenseXML,
		"License.plist":    KindPlistLicense,
		"registration.dat": KindRegistrationDat,
		"activation.dat":   KindRegistrationDat,
		"EULA.txt":         KindEULAText,
		"LICENSE":          KindLicenseText,
		"COPYING":          KindLicenseText,
		"random.txt":       KindOther,
		"":                 KindUnknown,
	}
	for in, want := range cases {
		if got := ArtifactKindFromName(in); got != want {
			t.Fatalf("ArtifactKindFromName(%q)=%q want %q", in, got, want)
		}
	}
}

func TestProductURLFromText(t *testing.T) {
	cases := map[string]string{
		"see https://www.adobe.com for details.": "https://www.adobe.com",
		"https://jetbrains.com/license":          "https://jetbrains.com/license",
		"no url":                                 "",
	}
	for in, want := range cases {
		if got := ProductURLFromText(in); got != want {
			t.Fatalf("ProductURLFromText(%q)=%q want %q", in, got, want)
		}
	}
}

func TestExtractLicenseKey(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"License key: AAAA-BBBB-CCCC-DDDD-EEEE", "AAAA-BBBB-CCCC-DDDD-EEEE"},
		{"Product Key = XXXX-YYYY-ZZZZ-1234", "XXXX-YYYY-ZZZZ-1234"},
		{"no key here", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := ExtractLicenseKey(c.in); got != c.want {
			t.Fatalf("ExtractLicenseKey(%q)=%q want %q", c.in, got, c.want)
		}
	}
}

func TestHashLicenseKey(t *testing.T) {
	hash := HashLicenseKey("AAAA-BBBB-CCCC")
	if hash == "" {
		t.Fatal("hash must be non-empty")
	}
	if hash == "AAAA-BBBB-CCCC" {
		t.Fatal("must NEVER return the raw key")
	}
	if !startsWith(hash, "sha256:") {
		t.Fatalf("hash must be sha256-prefixed, got %q", hash)
	}
}

func startsWith(s, prefix string) bool {
	if len(s) < len(prefix) {
		return false
	}
	return s[:len(prefix)] == prefix
}

func TestClassifyLicenseTypeFromText(t *testing.T) {
	cases := map[string]LicenseType{
		"MIT License\nPermission is hereby granted":     LicenseOSSMIT,
		"Apache License, Version 2.0":                   LicenseOSSApache,
		"BSD License\nRedistribution and use in source": LicenseOSSBSD,
		"GNU General Public License":                    LicenseOSSGPL,
		"GNU Lesser General Public License":             LicenseOSSLGPL,
		"Mozilla Public License":                        LicenseOSSMPL,
		"This is an evaluation copy of the product.":    LicenseEvaluation,
		"30-day trial version":                          LicenseTrial,
		"Subscription license — auto-renews":            LicenseSubscription,
		"":                                              LicenseUnknown,
	}
	for in, want := range cases {
		if got := ClassifyLicenseTypeFromText(in); got != want {
			t.Fatalf("ClassifyLicenseTypeFromText(%q)=%q want %q", in, got, want)
		}
	}
}

func TestIsOSSLicenseType(t *testing.T) {
	yes := []LicenseType{LicenseOSSMIT, LicenseOSSApache, LicenseOSSGPL}
	no := []LicenseType{LicensePerpetual, LicenseSubscription, LicenseUnknown}
	for _, v := range yes {
		if !IsOSSLicenseType(v) {
			t.Fatalf("expected OSS: %q", v)
		}
	}
	for _, v := range no {
		if IsOSSLicenseType(v) {
			t.Fatalf("expected NOT OSS: %q", v)
		}
	}
}

func TestClassifyDPDS(t *testing.T) {
	cases := []struct {
		product, publisher string
		want               DPDSClass
	}{
		{"Microsoft Outlook", "Microsoft", DPDSHandlesPII},
		{"Google Chrome", "Google", DPDSHandlesPII},
		{"QuickBooks Pro", "Intuit", DPDSHandlesFinancial},
		{"Tango/04 Monitor", "Tango/04", DPDSHandlesFinancial},
		{"Epic Systems EHR", "Epic", DPDSHandlesPHI},
		{"Stripe Connect", "Stripe", DPDSHandlesPCI},
		{"IntelliJ IDEA", "JetBrains", DPDSDevTool},
		{"Photoshop", "Adobe", DPDSMediaTool},
		{"random thing", "no one", DPDSUnknown},
	}
	for _, c := range cases {
		if got := ClassifyDPDS(c.product, c.publisher); got != c.want {
			t.Fatalf("ClassifyDPDS(%q,%q)=%q want %q",
				c.product, c.publisher, got, c.want)
		}
	}
}

func TestIsPIIHandlingClass(t *testing.T) {
	yes := []DPDSClass{
		DPDSHandlesPII, DPDSHandlesFinancial,
		DPDSHandlesPHI, DPDSHandlesPCI,
	}
	no := []DPDSClass{DPDSDevTool, DPDSMediaTool, DPDSUnknown}
	for _, v := range yes {
		if !IsPIIHandlingClass(v) {
			t.Fatalf("expected PII-handling: %q", v)
		}
	}
	for _, v := range no {
		if IsPIIHandlingClass(v) {
			t.Fatalf("expected NOT PII-handling: %q", v)
		}
	}
}

func TestExpiryDateFromText(t *testing.T) {
	cases := map[string]string{
		"License expires 2026-12-31": "2026-12-31",
		"Valid until 2027-01-01":     "2027-01-01",
		"Expiration: 2025-06-15":     "2025-06-15",
		"vence 2026-11-30":           "2026-11-30",
		"no expiry":                  "",
	}
	for in, want := range cases {
		if got := ExpiryDateFromText(in); got != want {
			t.Fatalf("ExpiryDateFromText(%q)=%q want %q", in, got, want)
		}
	}
}

func TestPublisherProductFromPath(t *testing.T) {
	cases := []struct {
		path              string
		wantPub, wantProd string
	}{
		{`C:\Program Files\Microsoft\Office\license.dat`, "Microsoft", "Office"},
		{`C:\Program Files (x86)\Adobe\Photoshop\license.json`, "Adobe", "Photoshop"},
		{`C:\ProgramData\JetBrains\IntelliJ IDEA\license.key`, "JetBrains", "IntelliJ IDEA"},
		{`/opt/microsoft/office/license.dat`, "microsoft", "office"},
		{`/Applications/Adobe/Photoshop/license.plist`, "Adobe", "Photoshop"},
		{`C:\Users\alice\nope.lic`, "", ""},
	}
	for _, c := range cases {
		gp, gprod := PublisherProductFromPath(c.path)
		if gp != c.wantPub || gprod != c.wantProd {
			t.Fatalf("PublisherProductFromPath(%q)=(%q,%q) want (%q,%q)",
				c.path, gp, gprod, c.wantPub, c.wantProd)
		}
	}
}

// -- AnnotateSecurity ---------------------------------------------

func TestAnnotateExpired(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC) }
	r := Row{
		ArtifactKind:       KindLicKeyfile,
		ExpiryDateYYYYMMDD: "20250101",
		FileMode:           0o600,
	}
	// Reformat YYYYMMDD → YYYY-MM-DD for AnnotateSecurity's parse.
	r.ExpiryDateYYYYMMDD = "2025-01-01"
	AnnotateSecurityWithClock(&r, now)
	if !r.IsExpired {
		t.Fatal("past expiry must flag")
	}
}

func TestAnnotateFutureExpiry(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC) }
	r := Row{
		ArtifactKind:       KindLicKeyfile,
		ExpiryDateYYYYMMDD: "2027-01-01",
		FileMode:           0o600,
	}
	AnnotateSecurityWithClock(&r, now)
	if r.IsExpired {
		t.Fatal("future expiry must NOT flag")
	}
}

func TestAnnotateHasLicenseKey(t *testing.T) {
	now := func() time.Time { return time.Now() }
	r := Row{
		ArtifactKind:   KindLicKeyfile,
		LicenseKeyHash: "sha256:abc",
		FileMode:       0o600,
	}
	AnnotateSecurityWithClock(&r, now)
	if !r.HasLicenseKey {
		t.Fatal("hash != empty must flag has_license_key")
	}
}

func TestAnnotateOSS(t *testing.T) {
	now := func() time.Time { return time.Now() }
	r := Row{
		ArtifactKind: KindLicenseText,
		LicenseType:  LicenseOSSMIT,
		FileMode:     0o644,
	}
	AnnotateSecurityWithClock(&r, now)
	if !r.IsOSSLicense {
		t.Fatal("MIT must flag OSS")
	}
}

func TestAnnotateExposure(t *testing.T) {
	now := func() time.Time { return time.Now() }
	r := Row{
		ArtifactKind:   KindLicKeyfile,
		ProductTitle:   "QuickBooks Pro",
		Publisher:      "Intuit",
		DPDSClass:      DPDSHandlesFinancial,
		LicenseKeyHash: "sha256:abc",
		FileMode:       0o644,
	}
	AnnotateSecurityWithClock(&r, now)
	if !r.IsPIIHandling {
		t.Fatal("financial-handling must flag PII")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("readable + key + PII-handling = exposure")
	}
}

func TestAnnotateLockedDownClean(t *testing.T) {
	now := func() time.Time { return time.Now() }
	r := Row{
		ArtifactKind:   KindLicKeyfile,
		Publisher:      "Microsoft",
		ProductTitle:   "Outlook",
		DPDSClass:      DPDSHandlesPII,
		LicenseKeyHash: "sha256:xxx",
		FileMode:       0o600,
	}
	AnnotateSecurityWithClock(&r, now)
	if r.IsCredentialExposureRisk {
		t.Fatal("0o600 must NOT flag exposure")
	}
}

// -- ParseLicence -------------------------------------------------

func TestParseLicenceJSON(t *testing.T) {
	body := []byte(`{
"product_title": "IntelliJ IDEA",
"publisher": "JetBrains",
"url": "https://jetbrains.com/idea",
"install_date": "2026-01-15",
"expiry": "2027-01-15",
"license_type": "subscription",
"license_key": "JETBRAINS-XXXX-YYYY-ZZZZ-1234",
"purpose": "IDE for Java/Kotlin development"
}`)
	f, ok := ParseLicence(body)
	if !ok {
		t.Fatal("must parse")
	}
	if f.ProductTitle != "IntelliJ IDEA" {
		t.Fatalf("product=%q", f.ProductTitle)
	}
	if f.Publisher != "JetBrains" {
		t.Fatalf("publisher=%q", f.Publisher)
	}
	if f.ProductURL != "https://jetbrains.com/idea" {
		t.Fatalf("url=%q", f.ProductURL)
	}
	if f.LicenseType != LicenseSubscription {
		t.Fatalf("type=%q", f.LicenseType)
	}
	if f.LicenseKeyRaw != "JETBRAINS-XXXX-YYYY-ZZZZ-1234" {
		t.Fatalf("key=%q", f.LicenseKeyRaw)
	}
	if f.ExpiryDate != "2027-01-15" {
		t.Fatalf("expiry=%q", f.ExpiryDate)
	}
}

func TestParseLicenceXML(t *testing.T) {
	body := []byte(`<?xml version="1.0"?>
<license>
  <product>Microsoft Office</product>
  <publisher>Microsoft Corporation</publisher>
  <url>https://office.com</url>
  <install_date>2025-09-01</install_date>
  <expiry>2026-09-01</expiry>
  <license_type>perpetual</license_type>
  <license_key>OFFICE-1111-2222-3333-4444</license_key>
</license>`)
	f, ok := ParseLicence(body)
	if !ok {
		t.Fatal("must parse")
	}
	if f.ProductTitle != "Microsoft Office" {
		t.Fatalf("product=%q", f.ProductTitle)
	}
	if f.LicenseType != LicensePerpetual {
		t.Fatalf("type=%q", f.LicenseType)
	}
}

func TestParseLicenceText(t *testing.T) {
	body := []byte(`MIT License

Copyright (c) 2025 ExampleCorp

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files...`)
	f, ok := ParseLicence(body)
	if !ok {
		t.Fatal("must parse")
	}
	if f.LicenseType != LicenseOSSMIT {
		t.Fatalf("type=%q", f.LicenseType)
	}
}

func TestParseLicenceEmpty(t *testing.T) {
	if _, ok := ParseLicence([]byte("")); ok {
		t.Fatal("empty must NOT parse")
	}
}

// -- collector end-to-end -----------------------------------------

func TestCollectorWalksInstallTree(t *testing.T) {
	tmp := t.TempDir()
	// Simulate `Program Files\Intuit\QuickBooks\license.json`.
	progFiles := filepath.Join(tmp, "Program Files")
	qbDir := filepath.Join(progFiles, "Intuit", "QuickBooks")
	must(t, os.MkdirAll(qbDir, 0o755))
	qbPath := filepath.Join(qbDir, "license.json")
	must(t, os.WriteFile(qbPath, []byte(`{
"product_title": "QuickBooks Pro",
"publisher": "Intuit",
"url": "https://quickbooks.intuit.com",
"license_type": "subscription",
"license_key": "QB-XXXX-YYYY-ZZZZ-1234",
"expiry": "2027-01-01"
}`), 0o644))

	// And a `Program Files\Adobe\Acrobat\LICENSE` OSS-looking
	// readme — locked down.
	acrDir := filepath.Join(progFiles, "Adobe", "Acrobat")
	must(t, os.MkdirAll(acrDir, 0o755))
	acrPath := filepath.Join(acrDir, "LICENSE")
	must(t, os.WriteFile(acrPath, []byte(`MIT License
Permission is hereby granted...
`), 0o600))

	// Random ignored.
	must(t, os.WriteFile(filepath.Join(qbDir, "random.dat"),
		[]byte(`noise`), 0o644))

	c := &fileCollector{
		installRoots: []string{progFiles},
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
		t.Fatalf("want 2 (qb+adobe), got %d: %+v", len(got), got)
	}

	var qb, adobe Row
	for _, r := range got {
		switch r.FilePath {
		case qbPath:
			qb = r
		case acrPath:
			adobe = r
		}
	}
	if qb.ArtifactKind != KindLicenseJSON {
		t.Fatalf("qb kind=%q", qb.ArtifactKind)
	}
	if qb.Publisher != "Intuit" {
		t.Fatalf("qb publisher=%q", qb.Publisher)
	}
	if qb.ProductTitle != "QuickBooks Pro" && qb.ProductTitle != "QuickBooks" {
		t.Fatalf("qb product=%q", qb.ProductTitle)
	}
	if qb.LicenseType != LicenseSubscription {
		t.Fatalf("qb type=%q", qb.LicenseType)
	}
	if qb.LicenseKeyHash == "" {
		t.Fatal("qb must hash license key")
	}
	if qb.LicenseKeyHash == "QB-XXXX-YYYY-ZZZZ-1234" {
		t.Fatal("qb must NEVER persist raw key")
	}
	if qb.DPDSClass != DPDSHandlesFinancial {
		t.Fatalf("qb dp_ds=%q", qb.DPDSClass)
	}
	if !qb.IsPIIHandling {
		t.Fatal("financial = PII-handling")
	}
	if !qb.IsCredentialExposureRisk {
		t.Fatalf("readable + key + PII = exposure: %+v", qb)
	}
	if qb.ProductURL != "https://quickbooks.intuit.com" {
		t.Fatalf("qb url=%q", qb.ProductURL)
	}

	if adobe.ArtifactKind != KindLicenseText {
		t.Fatalf("adobe kind=%q", adobe.ArtifactKind)
	}
	if adobe.LicenseType != LicenseOSSMIT {
		t.Fatalf("adobe type=%q", adobe.LicenseType)
	}
	if !adobe.IsOSSLicense {
		t.Fatal("adobe must flag OSS")
	}
	if adobe.IsCredentialExposureRisk {
		t.Fatalf("0o600 must NOT flag: %+v", adobe)
	}
}

func TestCollectorRespectsEnv(t *testing.T) {
	tmp := t.TempDir()
	envDir := filepath.Join(tmp, "custom-licences")
	must(t, os.MkdirAll(envDir, 0o755))
	must(t, os.WriteFile(filepath.Join(envDir, "license.json"),
		[]byte(`{"product_title":"X","publisher":"Y"}`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "SOFTWARE_LICENCES_DIR" {
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
	if len(got) != 1 || got[0].ArtifactKind != KindLicenseJSON {
		t.Fatalf("env: %+v", got)
	}
}

func TestCollectorMissingPathsOK(t *testing.T) {
	c := &fileCollector{
		installRoots: []string{"/nope-licences"},
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
		{FilePath: "z", ArtifactKind: KindLicenseJSON},
		{FilePath: "a", ArtifactKind: KindLicenseText},
		{FilePath: "a", ArtifactKind: KindLicenseJSON},
	}
	SortRows(in)
	if in[0].FilePath != "a" || in[0].ArtifactKind != KindLicenseJSON {
		t.Fatalf("first=%+v", in[0])
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
