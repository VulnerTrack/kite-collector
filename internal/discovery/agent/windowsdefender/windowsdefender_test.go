package windowsdefender

import (
	"strings"
	"testing"
)

func TestPinnedSourceStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(SourcePowerShellDefender), "powershell-defender"},
		{string(SourceNoProbe), "no-probe"},
		{string(SourceUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("source drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestMaxStaleSignatureDays(t *testing.T) {
	if MaxStaleSignatureDays != 7 {
		t.Fatalf("ceiling drift: %d", MaxStaleSignatureDays)
	}
}

func TestEncodeStringList(t *testing.T) {
	if EncodeStringList(nil) != "[]" {
		t.Fatal("nil")
	}
	if got := EncodeStringList([]string{"a", "b"}); got != `["a","b"]` {
		t.Fatalf("got %q", got)
	}
}

func TestHashContentsDeterministic(t *testing.T) {
	a := HashContents([]byte("payload"))
	b := HashContents([]byte("payload"))
	if a != b || len(a) != 64 {
		t.Fatalf("a=%q b=%q", a, b)
	}
}

// -- suspicious exclusion classifier ----------------------------------

func TestIsSuspiciousExclusionPathHits(t *testing.T) {
	hits := []string{
		`C:\Windows\Temp\`,
		`C:\Windows\Temp\evil.exe`,
		`c:\users\public\stash`, // case-insensitive
		`%TEMP%`,
		`%TMP%`,
		`*`,
		`*.*`,
		`C:\`,
		`C:\*`,
	}
	for _, p := range hits {
		if !IsSuspiciousExclusionPath(p) {
			t.Fatalf("%q must flag suspicious", p)
		}
	}
}

func TestIsSuspiciousExclusionPathMisses(t *testing.T) {
	miss := []string{
		`C:\Program Files\Corp\bin`,
		`D:\data\app\*.dll`,
		``,
		`C:\Windows\System32\custom-svc.exe`,
	}
	for _, p := range miss {
		if IsSuspiciousExclusionPath(p) {
			t.Fatalf("%q must NOT flag suspicious", p)
		}
	}
}

func TestFilterSuspiciousExclusions(t *testing.T) {
	in := []string{
		`C:\Program Files\Corp\bin`,
		`C:\Windows\Temp\`,
		`D:\data`,
		`*`,
	}
	got := FilterSuspiciousExclusions(in)
	if len(got) != 2 {
		t.Fatalf("got %v", got)
	}
	if got[0] != `C:\Windows\Temp\` || got[1] != `*` {
		t.Fatalf("order/content wrong: %v", got)
	}
}

func TestFilterSuspiciousExclusionsEmpty(t *testing.T) {
	if got := FilterSuspiciousExclusions(nil); got != nil {
		t.Fatalf("nil must round-trip: %v", got)
	}
}

// -- IsFullProtectionActive ------------------------------------------

func TestIsFullProtectionActiveAllOn(t *testing.T) {
	s := State{
		DefenderRunning:           true,
		OnAccessProtectionEnabled: true,
		BehaviorMonitorEnabled:    true,
		AntispywareEnabled:        true,
		TamperProtectionEnabled:   true,
		AntivirusSignatureAgeDays: 3,
	}
	s.IsSignatureStale = s.AntivirusSignatureAgeDays > MaxStaleSignatureDays
	if !IsFullProtectionActive(s) {
		t.Fatal("all-on must flag full protection")
	}
}

func TestIsFullProtectionActiveStaleSigBreaks(t *testing.T) {
	s := State{
		DefenderRunning:           true,
		OnAccessProtectionEnabled: true,
		BehaviorMonitorEnabled:    true,
		AntispywareEnabled:        true,
		TamperProtectionEnabled:   true,
		AntivirusSignatureAgeDays: 30,
	}
	s.IsSignatureStale = s.AntivirusSignatureAgeDays > MaxStaleSignatureDays
	if IsFullProtectionActive(s) {
		t.Fatal("stale signatures must break full-protection")
	}
}

func TestIsFullProtectionActiveTamperOff(t *testing.T) {
	s := State{
		DefenderRunning:           true,
		OnAccessProtectionEnabled: true,
		BehaviorMonitorEnabled:    true,
		AntispywareEnabled:        true,
		TamperProtectionEnabled:   false,
	}
	if IsFullProtectionActive(s) {
		t.Fatal("tamper off must break full-protection")
	}
}

// -- AnnotateSecurity end-to-end --------------------------------------

func TestAnnotateSecurityHealthyHost(t *testing.T) {
	s := State{
		DefenderRunning:           true,
		OnAccessProtectionEnabled: true,
		BehaviorMonitorEnabled:    true,
		AntispywareEnabled:        true,
		TamperProtectionEnabled:   true,
		PUAProtectionEnabled:      true,
		CloudProtectionEnabled:    true,
		AntivirusSignatureAgeDays: 1,
		ExclusionPaths: []string{
			`C:\Program Files\Corp\app.exe`,
		},
	}
	AnnotateSecurity(&s)
	if !s.IsFullProtectionActive {
		t.Fatal("healthy host must flag full protection")
	}
	if s.HasSuspiciousExclusion {
		t.Fatal("benign exclusion must NOT flag suspicious")
	}
	if s.IsSignatureStale {
		t.Fatal("1-day signature must NOT be stale")
	}
}

func TestAnnotateSecurityCompromisedHost(t *testing.T) {
	s := State{
		DefenderRunning:           true,
		OnAccessProtectionEnabled: true,
		BehaviorMonitorEnabled:    true,
		AntispywareEnabled:        true,
		TamperProtectionEnabled:   false, // attacker disabled
		AntivirusSignatureAgeDays: 60,    // and stopped updates
		ExclusionPaths: []string{
			`C:\Program Files\Legit\app.exe`,
			`C:\Windows\Temp\`, // attacker stash
			`*`,                // wildcard kill-switch
		},
	}
	AnnotateSecurity(&s)
	if s.IsFullProtectionActive {
		t.Fatal("compromised host must NOT flag full protection")
	}
	if !s.IsSignatureStale {
		t.Fatal("60-day signatures must flag stale")
	}
	if !s.HasSuspiciousExclusion {
		t.Fatal("must flag suspicious exclusion")
	}
	if len(s.SuspiciousExclusionPaths) != 2 {
		t.Fatalf("suspicious=%v (want 2)", s.SuspiciousExclusionPaths)
	}
}

// -- ParsePowerShellOutput typical fixtures ---------------------------

func TestParsePowerShellOutputHealthyWorkstation(t *testing.T) {
	body := []byte(`{
        "defender_running": true,
        "am_running_mode": "Normal",
        "am_service_version": "4.18.24080.9",
        "am_engine_version": "1.1.24070.5",
        "antivirus_signature_version": "1.421.892.0",
        "antivirus_signature_last_updated": "2026-06-22T08:00:00Z",
        "antivirus_signature_age_days": 1,
        "behavior_monitor_enabled": true,
        "on_access_protection_enabled": true,
        "ioav_protection_enabled": true,
        "nis_enabled": true,
        "antispyware_enabled": true,
        "tamper_protection_enabled": true,
        "last_quick_scan_time": "2026-06-23T06:00:00Z",
        "last_full_scan_time": "2026-06-15T03:00:00Z",
        "pua_protection_enabled": true,
        "cloud_protection_enabled": true,
        "exclusion_paths": [
            "C:\\Program Files\\Corp\\agent.exe"
        ],
        "exclusion_extensions": [".tmp"],
        "exclusion_processes": []
    }`)
	got, err := ParsePowerShellOutput(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.Source != SourcePowerShellDefender {
		t.Fatalf("source=%q", got.Source)
	}
	if !got.DefenderRunning || !got.TamperProtectionEnabled {
		t.Fatalf("flags: %+v", got)
	}
	if !got.IsFullProtectionActive {
		t.Fatal("healthy host must flag full protection")
	}
	if got.IsSignatureStale {
		t.Fatal("1-day signatures fresh")
	}
	if got.HasSuspiciousExclusion {
		t.Fatal("Corp\\agent.exe is not suspicious")
	}
	if got.AntivirusSignatureLastUpdated != "2026-06-22T08:00:00Z" {
		t.Fatalf("ts=%q", got.AntivirusSignatureLastUpdated)
	}
}

func TestParsePowerShellOutputThirdPartyAVPassive(t *testing.T) {
	// Defender stands down when CrowdStrike/SentinelOne etc. is installed.
	body := []byte(`{
        "defender_running": false,
        "am_running_mode": "Passive",
        "antivirus_signature_age_days": 0,
        "behavior_monitor_enabled": false,
        "on_access_protection_enabled": false,
        "antispyware_enabled": false,
        "tamper_protection_enabled": false,
        "pua_protection_enabled": false,
        "cloud_protection_enabled": false
    }`)
	got, err := ParsePowerShellOutput(body)
	if err != nil {
		t.Fatal(err)
	}
	if got.DefenderRunning {
		t.Fatal("passive mode must NOT flag running")
	}
	if got.AMRunningMode != "Passive" {
		t.Fatalf("mode=%q", got.AMRunningMode)
	}
	if got.IsFullProtectionActive {
		t.Fatal("passive Defender must NOT flag full protection")
	}
}

func TestParsePowerShellOutputAttackerExclusion(t *testing.T) {
	body := []byte(`{
        "defender_running": true,
        "am_running_mode": "Normal",
        "antivirus_signature_age_days": 2,
        "behavior_monitor_enabled": true,
        "on_access_protection_enabled": true,
        "ioav_protection_enabled": true,
        "antispyware_enabled": true,
        "tamper_protection_enabled": false,
        "pua_protection_enabled": true,
        "cloud_protection_enabled": true,
        "exclusion_paths": [
            "C:\\Program Files\\Corp\\app.exe",
            "C:\\Users\\Public\\",
            "C:\\Windows\\Temp\\stage.bin"
        ]
    }`)
	got, err := ParsePowerShellOutput(body)
	if err != nil {
		t.Fatal(err)
	}
	if !got.HasSuspiciousExclusion {
		t.Fatal("must flag suspicious exclusion")
	}
	if len(got.SuspiciousExclusionPaths) != 2 {
		t.Fatalf("suspicious=%v", got.SuspiciousExclusionPaths)
	}
	if got.IsFullProtectionActive {
		t.Fatal("tamper off must break full protection")
	}
}

func TestParsePowerShellOutputStaleSignature(t *testing.T) {
	body := []byte(`{
        "defender_running": true,
        "am_running_mode": "Normal",
        "antivirus_signature_age_days": 45,
        "behavior_monitor_enabled": true,
        "on_access_protection_enabled": true,
        "antispyware_enabled": true,
        "tamper_protection_enabled": true
    }`)
	got, err := ParsePowerShellOutput(body)
	if err != nil {
		t.Fatal(err)
	}
	if !got.IsSignatureStale {
		t.Fatal("45-day signature must flag stale")
	}
	if got.IsFullProtectionActive {
		t.Fatal("stale signatures break full protection")
	}
}

func TestParsePowerShellOutputBOMTolerated(t *testing.T) {
	body := append([]byte{0xEF, 0xBB, 0xBF}, []byte(
		`{"defender_running":true,"am_running_mode":"Normal",
         "antivirus_signature_age_days":0,
         "behavior_monitor_enabled":true,"on_access_protection_enabled":true,
         "antispyware_enabled":true,"tamper_protection_enabled":true}`,
	)...)
	got, err := ParsePowerShellOutput(body)
	if err != nil {
		t.Fatalf("BOM payload must parse: %v", err)
	}
	if !got.IsFullProtectionActive {
		t.Fatal("expected full protection")
	}
}

func TestParsePowerShellOutputEmptyError(t *testing.T) {
	if _, err := ParsePowerShellOutput(nil); err == nil {
		t.Fatal("empty must error")
	}
}

func TestParsePowerShellOutputMalformedError(t *testing.T) {
	if _, err := ParsePowerShellOutput([]byte("not json")); err == nil {
		t.Fatal("malformed must error")
	}
}

// -- script shape spot-check ----------------------------------------

func TestPowerShellScriptShape(t *testing.T) {
	for _, must := range []string{
		"Get-MpComputerStatus",
		"Get-MpPreference",
		"defender_running",
		"exclusion_paths",
		"tamper_protection_enabled",
		"ConvertTo-Json",
	} {
		if !strings.Contains(PowerShellScript, must) {
			t.Fatalf("PowerShellScript missing %q", must)
		}
	}
}

// -- SortExclusionLists --------------------------------------------

func TestSortExclusionListsDeterministic(t *testing.T) {
	s := &State{
		ExclusionPaths: []string{"zz", "aa", "mm"},
	}
	SortExclusionLists(s)
	if s.ExclusionPaths[0] != "aa" || s.ExclusionPaths[2] != "zz" {
		t.Fatalf("sort: %v", s.ExclusionPaths)
	}
}
