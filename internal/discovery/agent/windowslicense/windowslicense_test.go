package windowslicense

import (
	"strings"
	"testing"
	"time"
)

// fixedClock pins "now" so grace/evaluation expiry findings are
// deterministic.
func fixedClock() time.Time {
	return time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
}

// TestPinnedSourceStrings prevents drift between the Go const values
// and the SQLite CHECK constraint on host_windows_license.source.
func TestPinnedSourceStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(SourcePowerShellCIM), "powershell-cim"},
		{string(SourceUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("source drift: got %q want %q", p.got, p.want)
		}
	}
}

// TestPinnedStatusStrings prevents drift between the Go const values
// and the SQLite CHECK constraint on host_windows_license.license_status.
func TestPinnedStatusStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(StatusUnlicensed), "unlicensed"},
		{string(StatusLicensed), "licensed"},
		{string(StatusOOBGrace), "oob-grace"},
		{string(StatusOOTGrace), "oot-grace"},
		{string(StatusNonGenuineGrace), "non-genuine-grace"},
		{string(StatusNotification), "notification"},
		{string(StatusExtendedGrace), "extended-grace"},
		{string(StatusUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("status drift: got %q want %q", p.got, p.want)
		}
	}
}

// TestPinnedChannelStrings prevents drift between the Go const values
// and the SQLite CHECK constraint on host_windows_license.channel.
func TestPinnedChannelStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(ChannelRetail), "retail"},
		{string(ChannelOEM), "oem"},
		{string(ChannelVolumeKMS), "volume-kms-client"},
		{string(ChannelVolumeMAK), "volume-mak"},
		{string(ChannelEvaluation), "evaluation"},
		{string(ChannelUnknownValue), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("channel drift: got %q want %q", p.got, p.want)
		}
	}
}

// TestStatusFromCodeFullRange pins the slmgr LicenseStatus decoding.
func TestStatusFromCodeFullRange(t *testing.T) {
	pairs := []struct {
		code int
		want Status
	}{
		{0, StatusUnlicensed},
		{1, StatusLicensed},
		{2, StatusOOBGrace},
		{3, StatusOOTGrace},
		{4, StatusNonGenuineGrace},
		{5, StatusNotification},
		{6, StatusExtendedGrace},
		{7, StatusUnknown},
		{-1, StatusUnknown},
	}
	for _, p := range pairs {
		if got := StatusFromCode(p.code); got != p.want {
			t.Fatalf("code %d: got %q want %q", p.code, got, p.want)
		}
	}
}

// TestParsePowerShellOutputActivatedOEMWindows11 covers the most
// common enterprise laptop shape: OEM-activated Windows 11 Pro with a
// firmware-embedded OA3 key.
func TestParsePowerShellOutputActivatedOEMWindows11(t *testing.T) {
	body := []byte(`{
        "product_name": "Windows(R), Professional edition",
        "description": "Windows(R) Operating System, OEM_DM channel",
        "license_status_code": 1,
        "license_status_reason": 0,
        "partial_product_key": "3V66T",
        "license_family": "Professional",
        "product_key_channel": "OEM:DM",
        "grace_period_remaining_minutes": 0,
        "evaluation_end_date": null,
        "remaining_sku_rearm_count": 1001,
        "remaining_windows_rearm_count": 1001,
        "kms_configured_server": null,
        "kms_configured_port": 0,
        "kms_discovered_server": null,
        "kms_discovered_port": 0,
        "is_kms_host": false,
        "has_firmware_embedded_key": true,
        "firmware_key_hash": "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        "firmware_key_description": "4.0 Professional OEM:DM"
    }`)
	got, err := ParsePowerShellOutputWithClock(body, fixedClock)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.Source != SourcePowerShellCIM {
		t.Fatalf("source=%q", got.Source)
	}
	if !got.HasData() {
		t.Fatal("populated payload must report HasData")
	}
	if got.LicenseStatus != StatusLicensed || !got.IsActivated {
		t.Fatalf("status=%q activated=%v", got.LicenseStatus, got.IsActivated)
	}
	if got.Channel != ChannelOEM {
		t.Fatalf("channel=%q", got.Channel)
	}
	if got.PartialProductKey != "3V66T" {
		t.Fatalf("partial_product_key=%q", got.PartialProductKey)
	}
	if !got.HasFirmwareEmbeddedKey {
		t.Fatal("must flag firmware-embedded key")
	}
	if !strings.HasPrefix(got.FirmwareKeyHash, "sha256:") {
		t.Fatalf("firmware key must arrive hashed: %q", got.FirmwareKeyHash)
	}
	if got.IsLicenseComplianceRisk {
		t.Fatal("activated OEM host must not flag compliance risk")
	}
	if got.LicenseStatusReason != "" {
		t.Fatalf("reason 0 must coerce to empty: %q", got.LicenseStatusReason)
	}
}

// TestParsePowerShellOutputKMSClientGraceExpiring covers a
// volume-licensed domain host that lost its KMS server: out-of-
// tolerance grace, under 7 days remaining.
func TestParsePowerShellOutputKMSClientGraceExpiring(t *testing.T) {
	body := []byte(`{
        "product_name": "Windows(R), Enterprise edition",
        "description": "Windows(R) Operating System, VOLUME_KMSCLIENT channel",
        "license_status_code": 3,
        "license_status_reason": 3221549065,
        "partial_product_key": "2YT43",
        "license_family": "Enterprise",
        "product_key_channel": "Volume:GVLK",
        "grace_period_remaining_minutes": 4320,
        "evaluation_end_date": null,
        "remaining_sku_rearm_count": 3,
        "remaining_windows_rearm_count": 2,
        "kms_configured_server": "kms.corp.local",
        "kms_configured_port": 1688,
        "kms_discovered_server": "kms01.corp.local",
        "kms_discovered_port": 1688,
        "is_kms_host": false,
        "has_firmware_embedded_key": false,
        "firmware_key_hash": null,
        "firmware_key_description": null
    }`)
	got, err := ParsePowerShellOutputWithClock(body, fixedClock)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.LicenseStatus != StatusOOTGrace || !got.IsGracePeriod {
		t.Fatalf("status=%q grace=%v", got.LicenseStatus, got.IsGracePeriod)
	}
	if got.Channel != ChannelVolumeKMS || !got.IsKMSClient {
		t.Fatalf("channel=%q kms_client=%v", got.Channel, got.IsKMSClient)
	}
	if got.KMSConfiguredServer != "kms.corp.local" || got.KMSConfiguredPort != 1688 {
		t.Fatalf("kms configured=%q:%d", got.KMSConfiguredServer, got.KMSConfiguredPort)
	}
	if got.KMSDiscoveredServer != "kms01.corp.local" {
		t.Fatalf("kms discovered=%q", got.KMSDiscoveredServer)
	}
	if !got.IsGraceExpiringSoon {
		t.Fatal("4320 minutes (3 days) must flag grace-expiring-soon")
	}
	// 0xC004F009: the grace period expired HRESULT family.
	if got.LicenseStatusReason != "0xC004F009" {
		t.Fatalf("reason=%q", got.LicenseStatusReason)
	}
	if got.IsLicenseComplianceRisk {
		t.Fatal("in-grace host is a warning, not yet a compliance risk")
	}
}

// TestParsePowerShellOutputExpiredEvaluation covers an evaluation
// Server build past its deadline — availability + compliance finding.
func TestParsePowerShellOutputExpiredEvaluation(t *testing.T) {
	body := []byte(`{
        "product_name": "Windows(R), ServerStandardEval edition",
        "description": "Windows(R) Operating System, TIMEBASED_EVAL channel",
        "license_status_code": 5,
        "license_status_reason": 3221549078,
        "partial_product_key": "6XBNX",
        "license_family": "ServerStandardEval",
        "product_key_channel": "Retail:TB:Eval",
        "grace_period_remaining_minutes": 0,
        "evaluation_end_date": "2026-06-01T00:00:00Z",
        "remaining_sku_rearm_count": 0,
        "remaining_windows_rearm_count": 0,
        "kms_configured_server": null,
        "kms_configured_port": 0,
        "kms_discovered_server": null,
        "kms_discovered_port": 0,
        "is_kms_host": false,
        "has_firmware_embedded_key": false,
        "firmware_key_hash": null,
        "firmware_key_description": null
    }`)
	got, err := ParsePowerShellOutputWithClock(body, fixedClock)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.Channel != ChannelEvaluation || !got.IsEvaluation {
		t.Fatalf("channel=%q eval=%v", got.Channel, got.IsEvaluation)
	}
	if !got.IsEvaluationExpired {
		t.Fatal("2026-06-01 deadline vs 2026-08-20 clock must flag expired")
	}
	if !got.IsNotificationMode {
		t.Fatal("status 5 must flag notification mode")
	}
	if !got.IsRearmExhausted {
		t.Fatal("rearm count 0 must flag exhausted")
	}
	if !got.IsLicenseComplianceRisk {
		t.Fatal("expired eval in notification mode must roll up to compliance risk")
	}
}

// TestParsePowerShellOutputNonGenuine covers LicenseStatus 4 — the
// cracked-activator / tampered-activation shape.
func TestParsePowerShellOutputNonGenuine(t *testing.T) {
	body := []byte(`{
        "product_name": "Windows(R), Professional edition",
        "description": "Windows(R) Operating System, RETAIL channel",
        "license_status_code": 4,
        "license_status_reason": 0,
        "partial_product_key": "8HVX7",
        "license_family": "Professional",
        "product_key_channel": "Retail",
        "grace_period_remaining_minutes": 20160,
        "evaluation_end_date": null,
        "remaining_sku_rearm_count": -1,
        "remaining_windows_rearm_count": -1,
        "kms_configured_server": null,
        "kms_configured_port": 0,
        "kms_discovered_server": null,
        "kms_discovered_port": 0,
        "is_kms_host": false,
        "has_firmware_embedded_key": false,
        "firmware_key_hash": null,
        "firmware_key_description": null
    }`)
	got, err := ParsePowerShellOutputWithClock(body, fixedClock)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.LicenseStatus != StatusNonGenuineGrace || !got.IsNonGenuine {
		t.Fatalf("status=%q non_genuine=%v", got.LicenseStatus, got.IsNonGenuine)
	}
	if got.Channel != ChannelRetail {
		t.Fatalf("channel=%q", got.Channel)
	}
	if !got.IsLicenseComplianceRisk {
		t.Fatal("non-genuine must roll up to compliance risk")
	}
	if got.IsRearmExhausted {
		t.Fatal("unknown rearm count (-1) must NOT flag exhausted")
	}
}

// TestParsePowerShellOutputDeniedWMISurface covers the fully-null
// payload a locked-down host emits when both CIM queries are denied:
// the probe must degrade to a skippable row, not an error.
func TestParsePowerShellOutputDeniedWMISurface(t *testing.T) {
	body := []byte(`{
        "product_name": null,
        "description": null,
        "license_status_code": -1,
        "license_status_reason": 0,
        "partial_product_key": null,
        "license_family": null,
        "product_key_channel": null,
        "grace_period_remaining_minutes": 0,
        "evaluation_end_date": null,
        "remaining_sku_rearm_count": -1,
        "remaining_windows_rearm_count": -1,
        "kms_configured_server": null,
        "kms_configured_port": 0,
        "kms_discovered_server": null,
        "kms_discovered_port": 0,
        "is_kms_host": false,
        "has_firmware_embedded_key": false,
        "firmware_key_hash": null,
        "firmware_key_description": null
    }`)
	got, err := ParsePowerShellOutputWithClock(body, fixedClock)
	if err != nil {
		t.Fatalf("denied surface must parse, not error: %v", err)
	}
	if got.LicenseStatus != StatusUnknown {
		t.Fatalf("status=%q", got.LicenseStatus)
	}
	if got.HasData() {
		t.Fatal("all-null payload must NOT report HasData")
	}
	if got.IsLicenseComplianceRisk || got.IsUnlicensed || got.IsRearmExhausted {
		t.Fatal("no probe data must not synthesise findings")
	}
}

// TestParsePowerShellOutputEmptyError exercises the error path.
func TestParsePowerShellOutputEmptyError(t *testing.T) {
	if _, err := ParsePowerShellOutput(nil); err == nil {
		t.Fatal("empty input must error")
	}
	if _, err := ParsePowerShellOutput([]byte("   \n   ")); err == nil {
		t.Fatal("whitespace-only input must error")
	}
}

// TestParsePowerShellOutputMalformedJSONError exercises the
// malformed-JSON guard.
func TestParsePowerShellOutputMalformedJSONError(t *testing.T) {
	if _, err := ParsePowerShellOutput([]byte("not json at all")); err == nil {
		t.Fatal("malformed json must error")
	}
}

// TestParsePowerShellOutputHandlesUTF8BOM covers PowerShell output
// starting with a UTF-8 BOM (custom transcripting).
func TestParsePowerShellOutputHandlesUTF8BOM(t *testing.T) {
	body := append([]byte{0xEF, 0xBB, 0xBF}, []byte(`{
        "product_name": "Windows(R), Professional edition",
        "license_status_code": 1,
        "is_kms_host": false,
        "has_firmware_embedded_key": false
    }`)...)
	got, err := ParsePowerShellOutputWithClock(body, fixedClock)
	if err != nil {
		t.Fatalf("BOM-prefixed output must parse: %v", err)
	}
	if got.LicenseStatus != StatusLicensed {
		t.Fatalf("status=%q", got.LicenseStatus)
	}
}

// TestClassifyChannelDescriptionFallback covers pre-Windows-8 hosts
// where ProductKeyChannel doesn't exist and only the Description
// markers identify the channel.
func TestClassifyChannelDescriptionFallback(t *testing.T) {
	pairs := []struct {
		pkc, desc string
		want      Channel
	}{
		{"", "Windows Operating System, VOLUME_KMSCLIENT channel", ChannelVolumeKMS},
		{"", "Windows Operating System, VOLUME_MAK channel", ChannelVolumeMAK},
		{"", "Windows Operating System, OEM_SLP channel", ChannelOEM},
		{"", "Windows Operating System, RETAIL channel", ChannelRetail},
		{"", "Windows Operating System, TIMEBASED_EVAL channel", ChannelEvaluation},
		{"", "", ChannelUnknownValue},
		{"Volume:MAK", "irrelevant", ChannelVolumeMAK},
		{"Retail:TB:Eval", "RETAIL channel", ChannelEvaluation},
	}
	for _, p := range pairs {
		if got := ClassifyChannel(p.pkc, p.desc); got != p.want {
			t.Fatalf("pkc=%q desc=%q: got %q want %q", p.pkc, p.desc, got, p.want)
		}
	}
}

// TestPowerShellScriptShape spot-checks the embedded script contains
// the probes and privacy guards we depend on. Catches accidental
// edits — in particular, the raw OA3x key must only ever flow through
// HashKey.
func TestPowerShellScriptShape(t *testing.T) {
	for _, must := range []string{
		"SoftwareLicensingProduct",
		"SoftwareLicensingService",
		"55c92734-d682-4d71-983e-d6ec3f16059f",
		"PartialProductKey IS NOT NULL",
		"ConvertTo-Json",
		"HashKey $oa3",
		"sha256:",
	} {
		if !strings.Contains(PowerShellScript, must) {
			t.Fatalf("PowerShellScript missing %q", must)
		}
	}
	if strings.Contains(PowerShellScript, "firmware_key_hash         = $oa3") {
		t.Fatal("raw OA3x key must never be emitted unhashed")
	}
}

// TestAnnotateGraceNotExpiringWhenLong verifies the 7-day window
// boundary: a 30-day grace must not flag.
func TestAnnotateGraceNotExpiringWhenLong(t *testing.T) {
	i := Info{
		LicenseStatus:               StatusOOBGrace,
		GracePeriodRemainingMinutes: 30 * 24 * 60,
	}
	AnnotateWithClock(&i, fixedClock)
	if !i.IsGracePeriod {
		t.Fatal("oob-grace must flag grace period")
	}
	if i.IsGraceExpiringSoon {
		t.Fatal("30-day grace must not flag expiring soon")
	}
}
