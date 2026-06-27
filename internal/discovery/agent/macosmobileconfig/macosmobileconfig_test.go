package macosmobileconfig

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindMobileconfigPlist), "mobileconfig-plist"},
		{string(KindMDMEnrollmentXML), "mdm-enrollment-xml"},
		{string(KindManagedPreferencesPlist), "managed-preferences-plist"},
		{string(KindJamfPolicyXML), "jamf-policy-xml"},
		{string(KindIntuneConfigXML), "intune-config-xml"},
		{string(KindOther), "other"},
		{string(KindUnknown), "unknown"},
		{string(DPDSHandlesPII), "handles-pii"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestIsCandidateName(t *testing.T) {
	yes := []string{
		"CorpStandard.mobileconfig",
		"com.acme.profile.plist",
		"jamf-policy-001.xml",
		"intune-config-fileVault.xml",
		"mdm-enrollment.xml",
	}
	no := []string{"", "random.bin", "factura.xml", "cv.docx"}
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
		"/Library/Mobile Device Management/CorpStandard.mobileconfig":        KindMobileconfigPlist,
		"/Library/Managed Preferences/com.acme.profile.plist":                KindManagedPreferencesPlist,
		"/var/db/ConfigurationProfiles/Store/profile.plist":                  KindManagedPreferencesPlist,
		"/Library/Application Support/JAMF/policies/policy-001.xml":          KindJamfPolicyXML,
		"/Library/Application Support/Microsoft/Intune/config-fileVault.xml": KindIntuneConfigXML,
		"/Library/MDM/enrollment.xml":                                        KindMDMEnrollmentXML,
		"/random/path.xml":                                                   KindOther,
		"":                                                                   KindUnknown,
	}
	for in, want := range cases {
		if got := ArtifactKindFromPath(in); got != want {
			t.Fatalf("ArtifactKindFromPath(%q)=%q want %q", in, got, want)
		}
	}
}

func TestPayloadTypeToField(t *testing.T) {
	cases := []struct {
		check func(Row) bool
		ptype string
	}{
		{ptype: "com.apple.wifi.managed", check: func(r Row) bool { return r.HasWifiPayload }},
		{ptype: "com.apple.vpn.managed", check: func(r Row) bool { return r.HasVPNPayload }},
		{ptype: "com.apple.vpn.managed.applayer", check: func(r Row) bool { return r.HasVPNPayload }},
		{ptype: "com.apple.security.scep", check: func(r Row) bool { return r.HasCertificatePayload }},
		{ptype: "com.apple.security.root", check: func(r Row) bool { return r.HasCertificatePayload }},
		{ptype: "com.apple.security.pkcs12", check: func(r Row) bool { return r.HasCertificatePayload }},
		{ptype: "com.apple.mail.managed", check: func(r Row) bool { return r.HasMailPayload }},
		{ptype: "com.apple.eas.account", check: func(r Row) bool { return r.HasMailPayload }},
		{ptype: "com.apple.mcx.FileVault2", check: func(r Row) bool { return r.HasFileVaultPayload }},
		{ptype: "com.apple.mobiledevice.passwordpolicy", check: func(r Row) bool { return r.HasPasscodePayload }},
		{ptype: "com.apple.applicationaccess", check: func(r Row) bool { return r.HasAppRestrictions }},
		{ptype: "com.apple.app.manage", check: func(r Row) bool { return r.HasManagedApps }},
		{ptype: "com.apple.system-extension-policy", check: func(r Row) bool { return r.HasKernelExtensions }},
		{ptype: "com.apple.screensharing", check: func(r Row) bool { return r.HasScreenSharing }},
		{ptype: "com.apple.remotedesktop", check: func(r Row) bool { return r.HasScreenSharing }},
	}
	for _, c := range cases {
		var r Row
		if !PayloadTypeToField(&r, c.ptype) {
			t.Fatalf("PayloadTypeToField(%q) must succeed", c.ptype)
		}
		if !c.check(r) {
			t.Fatalf("PayloadTypeToField(%q) wrong field", c.ptype)
		}
	}
	var r Row
	if PayloadTypeToField(&r, "com.apple.unknownpayload") {
		t.Fatal("unknown payload type must return false")
	}
}

// -- ParseMobileconfig --------------------------------------------

func TestParseMobileconfigCorp(t *testing.T) {
	body := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadIdentifier</key>
    <string>com.acme.corp.profile.standard</string>
    <key>PayloadDisplayName</key>
    <string>Acme Corp Standard Profile</string>
    <key>PayloadOrganization</key>
    <string>Acme Corp IT</string>
    <key>PayloadDescription</key>
    <string>Standard configuration for all corp Macs.</string>
    <key>PayloadUUID</key>
    <string>12345678-1234-1234-1234-123456789abc</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
    <key>PayloadContent</key>
    <array>
        <dict>
            <key>PayloadType</key>
            <string>com.apple.wifi.managed</string>
            <key>PayloadUUID</key>
            <string>aaaaaaaa-1111-2222-3333-444444444444</string>
        </dict>
        <dict>
            <key>PayloadType</key>
            <string>com.apple.vpn.managed</string>
            <key>PayloadUUID</key>
            <string>bbbbbbbb-1111-2222-3333-444444444444</string>
        </dict>
        <dict>
            <key>PayloadType</key>
            <string>com.apple.security.scep</string>
        </dict>
        <dict>
            <key>PayloadType</key>
            <string>com.apple.mcx.FileVault2</string>
        </dict>
        <dict>
            <key>PayloadType</key>
            <string>com.apple.mobiledevice.passwordpolicy</string>
        </dict>
    </array>
</dict>
</plist>`)
	f, ok := ParseMobileconfig(body)
	if !ok {
		t.Fatal("must parse")
	}
	if f.PayloadIdentifier != "com.acme.corp.profile.standard" {
		t.Fatalf("identifier=%q", f.PayloadIdentifier)
	}
	if f.PayloadDisplayName != "Acme Corp Standard Profile" {
		t.Fatalf("display=%q", f.PayloadDisplayName)
	}
	if f.PayloadOrganization != "Acme Corp IT" {
		t.Fatalf("org=%q", f.PayloadOrganization)
	}
	if f.PayloadUUID != "12345678-1234-1234-1234-123456789abc" {
		t.Fatalf("uuid=%q", f.PayloadUUID)
	}
	if f.PayloadVersion != "1" {
		t.Fatalf("version=%q", f.PayloadVersion)
	}
	if len(f.SubPayloadTypes) != 5 {
		t.Fatalf("subpayloads=%d want 5: %v", len(f.SubPayloadTypes), f.SubPayloadTypes)
	}
	want := map[string]bool{
		"com.apple.wifi.managed":                true,
		"com.apple.vpn.managed":                 true,
		"com.apple.security.scep":               true,
		"com.apple.mcx.FileVault2":              true,
		"com.apple.mobiledevice.passwordpolicy": true,
	}
	for _, st := range f.SubPayloadTypes {
		if !want[st] {
			t.Fatalf("unexpected subpayload %q", st)
		}
	}
}

func TestParseMobileconfigEmpty(t *testing.T) {
	if _, ok := ParseMobileconfig([]byte("")); ok {
		t.Fatal("empty must NOT parse")
	}
}

func TestParseMobileconfigBinary(t *testing.T) {
	if _, ok := ParseMobileconfig([]byte("bplist00\x00\x00")); ok {
		t.Fatal("binary plist must NOT parse")
	}
}

func TestParseMobileconfigNonXML(t *testing.T) {
	if _, ok := ParseMobileconfig([]byte(`{"foo":"bar"}`)); ok {
		t.Fatal("JSON must NOT parse")
	}
}

// -- AnnotateSecurity ---------------------------------------------

func TestAnnotateMDMEnrolled(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC) }
	r := Row{
		ArtifactKind:        KindMobileconfigPlist,
		PayloadUUID:         "uuid-1",
		PayloadOrganization: "Acme Corp IT",
		FileMode:            0o644,
	}
	AnnotateSecurityWithClock(&r, now)
	if !r.IsMDMEnrolled {
		t.Fatal("PayloadOrganization must flag MDM-enrolled")
	}
	if !r.IsPIIHandling {
		t.Fatal("Always handles PII")
	}
}

func TestAnnotateWifiExposure(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC) }
	r := Row{
		ArtifactKind:   KindMobileconfigPlist,
		PayloadUUID:    "uuid-1",
		HasWifiPayload: true,
		FileMode:       0o644,
	}
	AnnotateSecurityWithClock(&r, now)
	if !r.IsCredentialExposureRisk {
		t.Fatal("readable + uuid + wifi = exposure (PSK at risk)")
	}
}

func TestAnnotateVPNExposure(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC) }
	r := Row{
		ArtifactKind:  KindMobileconfigPlist,
		PayloadUUID:   "uuid-1",
		HasVPNPayload: true,
		FileMode:      0o644,
	}
	AnnotateSecurityWithClock(&r, now)
	if !r.IsCredentialExposureRisk {
		t.Fatal("readable + uuid + vpn = exposure (shared secret at risk)")
	}
}

func TestAnnotateCertificateExposure(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC) }
	r := Row{
		ArtifactKind:          KindMobileconfigPlist,
		PayloadUUID:           "uuid-1",
		HasCertificatePayload: true,
		FileMode:              0o644,
	}
	AnnotateSecurityWithClock(&r, now)
	if !r.IsCredentialExposureRisk {
		t.Fatal("readable + uuid + cert = exposure (key material at risk)")
	}
}

func TestAnnotatePasscodeNoExposure(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC) }
	r := Row{
		ArtifactKind:       KindMobileconfigPlist,
		PayloadUUID:        "uuid-1",
		HasPasscodePayload: true,
		FileMode:           0o644,
	}
	AnnotateSecurityWithClock(&r, now)
	if r.IsCredentialExposureRisk {
		t.Fatal("passcode policy alone is not credential-bearing — no exposure")
	}
}

func TestAnnotateLockedDownClean(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC) }
	r := Row{
		ArtifactKind:   KindMobileconfigPlist,
		PayloadUUID:    "uuid-1",
		HasWifiPayload: true,
		FileMode:       0o600,
	}
	AnnotateSecurityWithClock(&r, now)
	if r.IsCredentialExposureRisk {
		t.Fatal("0o600 must NOT flag exposure")
	}
}

func TestAnnotateNoUUIDNoExposure(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC) }
	r := Row{
		ArtifactKind:   KindMobileconfigPlist,
		HasWifiPayload: true,
		FileMode:       0o644,
	}
	AnnotateSecurityWithClock(&r, now)
	if r.IsCredentialExposureRisk {
		t.Fatal("no payload_uuid must NOT flag exposure")
	}
}

func TestAnnotateRecentInstall(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC) }
	r := Row{
		ArtifactKind:        KindMobileconfigPlist,
		PayloadUUID:         "uuid-1",
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
		ArtifactKind:        KindMobileconfigPlist,
		PayloadUUID:         "uuid-1",
		InstallDateYYYYMMDD: "20240101",
		FileMode:            0o644,
	}
	AnnotateSecurityWithClock(&r, now)
	if r.HasRecentInstall {
		t.Fatal("> 30d old must NOT flag")
	}
}

// -- collector end-to-end -----------------------------------------

func TestCollectorWalksMDMTree(t *testing.T) {
	tmp := t.TempDir()
	mdmDir := filepath.Join(tmp, "Library", "Mobile Device Management")
	must(t, os.MkdirAll(mdmDir, 0o755))

	// Corp standard profile with wifi+vpn+scep+filevault+passcode,
	// world-readable.
	corpPath := filepath.Join(mdmDir, "CorpStandard.mobileconfig")
	must(t, os.WriteFile(corpPath, []byte(`<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
<key>PayloadType</key><string>Configuration</string>
<key>PayloadIdentifier</key><string>com.acme.corp.standard</string>
<key>PayloadDisplayName</key><string>Acme Corp Standard</string>
<key>PayloadOrganization</key><string>Acme Corp IT</string>
<key>PayloadUUID</key><string>11111111-2222-3333-4444-555555555555</string>
<key>PayloadVersion</key><integer>2</integer>
<key>PayloadContent</key>
<array>
<dict><key>PayloadType</key><string>com.apple.wifi.managed</string></dict>
<dict><key>PayloadType</key><string>com.apple.vpn.managed</string></dict>
<dict><key>PayloadType</key><string>com.apple.security.scep</string></dict>
<dict><key>PayloadType</key><string>com.apple.mcx.FileVault2</string></dict>
<dict><key>PayloadType</key><string>com.apple.mobiledevice.passwordpolicy</string></dict>
</array>
</dict>
</plist>`), 0o644))

	// Passcode-only profile, locked down.
	passDir := filepath.Join(tmp, "Library", "Managed Preferences")
	must(t, os.MkdirAll(passDir, 0o755))
	passPath := filepath.Join(passDir, "com.acme.passcode.plist")
	must(t, os.WriteFile(passPath, []byte(`<?xml version="1.0"?>
<plist version="1.0">
<dict>
<key>PayloadIdentifier</key><string>com.acme.passcode</string>
<key>PayloadDisplayName</key><string>Passcode Policy</string>
<key>PayloadOrganization</key><string>Acme Corp IT</string>
<key>PayloadUUID</key><string>99999999-1111-2222-3333-444444444444</string>
<key>PayloadContent</key>
<array>
<dict><key>PayloadType</key><string>com.apple.mobiledevice.passwordpolicy</string></dict>
</array>
</dict>
</plist>`), 0o600))

	// Random ignored.
	must(t, os.WriteFile(filepath.Join(mdmDir, "random.bin"),
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
	if len(got) != 2 {
		t.Fatalf("want 2 (corp+passcode), got %d: %+v", len(got), got)
	}

	var corp, pass Row
	for _, r := range got {
		switch r.FilePath {
		case corpPath:
			corp = r
		case passPath:
			pass = r
		}
	}
	if corp.ArtifactKind != KindMobileconfigPlist {
		t.Fatalf("corp kind=%q", corp.ArtifactKind)
	}
	if corp.PayloadDisplayName != "Acme Corp Standard" {
		t.Fatalf("corp display=%q", corp.PayloadDisplayName)
	}
	if corp.PayloadOrganization != "Acme Corp IT" {
		t.Fatalf("corp org=%q", corp.PayloadOrganization)
	}
	if corp.PayloadUUID != "11111111-2222-3333-4444-555555555555" {
		t.Fatalf("corp uuid=%q", corp.PayloadUUID)
	}
	if corp.PayloadVersion != "2" {
		t.Fatalf("corp version=%q", corp.PayloadVersion)
	}
	if corp.SubpayloadsCount != 5 {
		t.Fatalf("corp subpayloads=%d want 5", corp.SubpayloadsCount)
	}
	if !corp.HasWifiPayload || !corp.HasVPNPayload || !corp.HasCertificatePayload ||
		!corp.HasFileVaultPayload || !corp.HasPasscodePayload {
		t.Fatalf("corp payload flags: %+v", corp)
	}
	if !corp.IsMDMEnrolled {
		t.Fatal("corp must flag MDM-enrolled")
	}
	if !corp.IsPIIHandling {
		t.Fatal("MDM always handles PII")
	}
	if !corp.IsCredentialExposureRisk {
		t.Fatalf("corp readable + uuid + wifi/vpn/cert = exposure: %+v", corp)
	}

	if pass.ArtifactKind != KindManagedPreferencesPlist {
		t.Fatalf("pass kind=%q", pass.ArtifactKind)
	}
	if !pass.HasPasscodePayload {
		t.Fatal("pass must flag passcode payload")
	}
	if !pass.IsMDMEnrolled {
		t.Fatal("pass must flag MDM-enrolled")
	}
	if pass.HasWifiPayload || pass.HasVPNPayload {
		t.Fatal("pass must NOT flag wifi/vpn")
	}
	if pass.IsCredentialExposureRisk {
		t.Fatalf("pass 0o600 + passcode-only must NOT flag: %+v", pass)
	}
}

func TestCollectorRespectsEnv(t *testing.T) {
	tmp := t.TempDir()
	envDir := filepath.Join(tmp, "custom-mdm")
	must(t, os.MkdirAll(envDir, 0o755))
	must(t, os.WriteFile(filepath.Join(envDir, "test.mobileconfig"),
		[]byte(`<?xml version="1.0"?>
<plist version="1.0">
<dict>
<key>PayloadIdentifier</key><string>com.acme.test</string>
<key>PayloadOrganization</key><string>Acme</string>
<key>PayloadUUID</key><string>uuid-1</string>
</dict>
</plist>`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "MACOS_MDM_DIR" {
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
	if len(got) != 1 || got[0].ArtifactKind != KindMobileconfigPlist {
		t.Fatalf("env: %+v", got)
	}
	if got[0].PayloadOrganization != "Acme" {
		t.Fatalf("env org=%q", got[0].PayloadOrganization)
	}
}

func TestCollectorMissingPathsOK(t *testing.T) {
	c := &fileCollector{
		installRoots: []string{"/nope-mdm"},
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
		{FilePath: "z", ArtifactKind: KindMobileconfigPlist, PayloadUUID: "z"},
		{FilePath: "a", ArtifactKind: KindMobileconfigPlist, PayloadUUID: "z"},
		{FilePath: "a", ArtifactKind: KindMobileconfigPlist, PayloadUUID: "a"},
	}
	SortRows(in)
	if in[0].FilePath != "a" || in[0].PayloadUUID != "a" {
		t.Fatalf("first=%+v", in[0])
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
