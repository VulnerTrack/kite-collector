package windowsinfo

import (
	"strings"
	"testing"
)

// TestPinnedSourceStrings prevents drift between the Go const values
// and the SQLite CHECK constraint on host_windows_info.source.
func TestPinnedSourceStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(SourcePowerShellCIM), "powershell-cim"},
		{string(SourcePowerShellWMI), "powershell-wmi"},
		{string(SourceUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("source drift: got %q want %q", p.got, p.want)
		}
	}
}

// TestParsePowerShellOutputTypicalWindows11 covers the most common
// host shape: domain-joined Windows 11 Pro 23H2.
func TestParsePowerShellOutputTypicalWindows11(t *testing.T) {
	body := []byte(`{
        "hostname": "DESKTOP-CORP01",
        "domain": "corp.local",
        "workgroup": null,
        "is_domain_joined": true,
        "logged_on_user": "CORP\\alice",
        "manufacturer": "Dell Inc.",
        "model": "Latitude 7440",
        "total_physical_memory_bytes": 34359738368,
        "os_caption": "Microsoft Windows 11 Pro",
        "os_version": "10.0.22631",
        "os_architecture": "64-bit",
        "install_date": "2024-03-15T10:30:00Z",
        "last_boot_up_time": "2026-06-23T08:15:00Z",
        "os_build": "22631",
        "os_ubr": 4317,
        "os_display_version": "23H2",
        "os_product_name": "Windows 11 Pro",
        "os_edition_id": "Professional"
    }`)
	got, err := ParsePowerShellOutput(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.Source != SourcePowerShellCIM {
		t.Fatalf("source=%q", got.Source)
	}
	if got.Hostname != "DESKTOP-CORP01" {
		t.Fatalf("hostname=%q", got.Hostname)
	}
	if got.Domain != "corp.local" {
		t.Fatalf("domain=%q", got.Domain)
	}
	if !got.IsDomainJoined {
		t.Fatal("must flag domain-joined")
	}
	if got.LoggedOnUser != "CORP\\alice" {
		t.Fatalf("logged_on_user=%q", got.LoggedOnUser)
	}
	if got.TotalPhysicalMemoryBytes != 34359738368 {
		t.Fatalf("ram=%d", got.TotalPhysicalMemoryBytes)
	}
	if got.OSBuild != "22631" || got.OSUBR != 4317 {
		t.Fatalf("build=%s ubr=%d", got.OSBuild, got.OSUBR)
	}
	if got.OSDisplayVersion != "23H2" {
		t.Fatalf("display_version=%q", got.OSDisplayVersion)
	}
	if got.InstallDate != "2024-03-15T10:30:00Z" {
		t.Fatalf("install_date=%q (not normalised to RFC3339Z)", got.InstallDate)
	}
}

// TestParsePowerShellOutputWorkgroupHost covers the standalone (not
// domain-joined) host shape — workgroup populated, domain null.
func TestParsePowerShellOutputWorkgroupHost(t *testing.T) {
	body := []byte(`{
        "hostname": "HOME-PC",
        "domain": null,
        "workgroup": "WORKGROUP",
        "is_domain_joined": false,
        "logged_on_user": "HOME-PC\\bob",
        "manufacturer": "ASUS",
        "model": "ROG Strix",
        "total_physical_memory_bytes": 17179869184,
        "os_caption": "Microsoft Windows 11 Home",
        "os_version": "10.0.22631",
        "os_architecture": "64-bit",
        "install_date": null,
        "last_boot_up_time": null,
        "os_build": "22631",
        "os_ubr": 0,
        "os_display_version": null,
        "os_product_name": null,
        "os_edition_id": null
    }`)
	got, err := ParsePowerShellOutput(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.Domain != "" {
		t.Fatalf("domain=%q (should be empty)", got.Domain)
	}
	if got.Workgroup != "WORKGROUP" {
		t.Fatalf("workgroup=%q", got.Workgroup)
	}
	if got.IsDomainJoined {
		t.Fatal("workgroup host must NOT flag domain-joined")
	}
	if got.OSUBR != 0 {
		t.Fatalf("ubr=%d (defaulted)", got.OSUBR)
	}
	if got.InstallDate != "" {
		t.Fatalf("install_date=%q (null must coerce to empty)", got.InstallDate)
	}
}

// TestParsePowerShellOutputServerCoreSparseFields covers Server Core
// installs where ProductName / DisplayVersion can be missing entirely.
func TestParsePowerShellOutputServerCoreSparseFields(t *testing.T) {
	body := []byte(`{
        "hostname": "SRV2022-01",
        "domain": "corp.local",
        "workgroup": null,
        "is_domain_joined": true,
        "logged_on_user": null,
        "manufacturer": "Microsoft Corporation",
        "model": "Virtual Machine",
        "total_physical_memory_bytes": 8589934592,
        "os_caption": "Microsoft Windows Server 2022 Standard",
        "os_version": "10.0.20348",
        "os_architecture": "64-bit",
        "install_date": "2023-09-01T00:00:00Z",
        "last_boot_up_time": "2026-06-20T03:00:00Z",
        "os_build": "20348",
        "os_ubr": 2461,
        "os_display_version": null,
        "os_product_name": null,
        "os_edition_id": null
    }`)
	got, err := ParsePowerShellOutput(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.Hostname != "SRV2022-01" || got.OSBuild != "20348" {
		t.Fatalf("%+v", got)
	}
	if got.OSDisplayVersion != "" {
		t.Fatalf("sparse display_version must coerce to empty: %q", got.OSDisplayVersion)
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

// TestParsePowerShellOutputMalformedJSONError exercises the malformed-
// JSON guard.
func TestParsePowerShellOutputMalformedJSONError(t *testing.T) {
	if _, err := ParsePowerShellOutput([]byte("not json at all")); err == nil {
		t.Fatal("malformed json must error")
	}
}

// TestParsePowerShellOutputHandlesUTF8BOM covers the unusual case of
// PowerShell output starting with a UTF-8 BOM (custom transcripting).
func TestParsePowerShellOutputHandlesUTF8BOM(t *testing.T) {
	body := append([]byte{0xEF, 0xBB, 0xBF}, []byte(`{
        "hostname": "BOM-PC",
        "is_domain_joined": false,
        "total_physical_memory_bytes": 0,
        "os_ubr": 0
    }`)...)
	got, err := ParsePowerShellOutput(body)
	if err != nil {
		t.Fatalf("BOM-prefixed output must parse: %v", err)
	}
	if got.Hostname != "BOM-PC" {
		t.Fatalf("hostname=%q", got.Hostname)
	}
}

// TestParsePowerShellOutputHandlesHugeMemory covers the unsigned
// uint64 overflow case — TotalPhysicalMemory can exceed int64 max on
// theoretical multi-PB systems. We clamp without erroring.
func TestParsePowerShellOutputHandlesHugeMemory(t *testing.T) {
	body := []byte(`{
        "hostname": "HUGE",
        "is_domain_joined": false,
        "total_physical_memory_bytes": "18446744073709551615",
        "os_ubr": 0
    }`)
	got, err := ParsePowerShellOutput(body)
	if err != nil {
		t.Fatalf("huge-memory payload must parse: %v", err)
	}
	if got.TotalPhysicalMemoryBytes <= 0 {
		t.Fatalf("clamped to int64 max-ish; got %d", got.TotalPhysicalMemoryBytes)
	}
}

// TestParsePowerShellOutputNormaliseTimeAlternateLayouts ensures the
// time-normalisation helper accepts common non-RFC3339 PowerShell
// outputs.
func TestParsePowerShellOutputNormaliseTimeAlternateLayouts(t *testing.T) {
	body := []byte(`{
        "hostname": "X",
        "is_domain_joined": false,
        "total_physical_memory_bytes": 0,
        "os_ubr": 0,
        "install_date": "2023-04-05 12:34:56",
        "last_boot_up_time": "2026-06-23T08:15:00.123Z"
    }`)
	got, err := ParsePowerShellOutput(body)
	if err != nil {
		t.Fatal(err)
	}
	if got.InstallDate != "2023-04-05T12:34:56Z" {
		t.Fatalf("install_date=%q (canonicalisation broken)", got.InstallDate)
	}
	if !strings.HasPrefix(got.LastBootUpTime, "2026-06-23T08:15:00") {
		t.Fatalf("last_boot_up_time=%q", got.LastBootUpTime)
	}
}

// TestPowerShellScriptShape spot-checks the embedded script contains
// the three probes we depend on. Catches accidental edits.
func TestPowerShellScriptShape(t *testing.T) {
	for _, must := range []string{
		"Win32_ComputerSystem",
		"Win32_OperatingSystem",
		"HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
		"ConvertTo-Json",
		"is_domain_joined",
	} {
		if !strings.Contains(PowerShellScript, must) {
			t.Fatalf("PowerShellScript missing %q", must)
		}
	}
}

// TestSortInfosDeterministic exercises the fleet-aggregation helper.
func TestSortInfosDeterministic(t *testing.T) {
	in := []Info{{Hostname: "zzz"}, {Hostname: "aaa"}, {Hostname: "mmm"}}
	SortInfos(in)
	if in[0].Hostname != "aaa" || in[2].Hostname != "zzz" {
		t.Fatalf("sort: %+v", in)
	}
}
