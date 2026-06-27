package windowssoftware

import (
	"strings"
	"testing"
)

func TestPinnedSourceStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(SourceRegistryHKLM), "registry-hklm"},
		{string(SourceRegistryHKLMWow64), "registry-hklm-wow64"},
		{string(SourceRegistryHKCU), "registry-hkcu"},
		{string(SourceUnknown), "unknown"},
		{string(PatchSourceGetHotFix), "powershell-get-hotfix"},
		{string(PatchSourceQuickFixEngineering), "wmi-quickfixengineering"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("source drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestNormalizeKBID(t *testing.T) {
	cases := map[string]string{
		"KB5031356":   "KB5031356",
		"kb5031356":   "KB5031356",
		" Kb5031356 ": "KB5031356",
		"":            "",
		"5031356":     "5031356",
	}
	for in, want := range cases {
		if got := NormalizeKBID(in); got != want {
			t.Fatalf("NormalizeKBID(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCanonicaliseRegistryKey(t *testing.T) {
	in := `Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{12345}`
	got := canonicaliseRegistryKey(in)
	want := `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{12345}`
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestCanonicaliseRegistryKeyPassthrough(t *testing.T) {
	in := `HKEY_LOCAL_MACHINE\SOFTWARE\X`
	if got := canonicaliseRegistryKey(in); got != in {
		t.Fatalf("expected passthrough, got %q", got)
	}
}

func TestNormaliseInstallDate(t *testing.T) {
	if got := normaliseInstallDate("20240412"); got != "2024-04-12T00:00:00Z" {
		t.Fatalf("YYYYMMDD parse failed: %q", got)
	}
	if got := normaliseInstallDate("2024-04-12T08:00:00Z"); got != "2024-04-12T08:00:00Z" {
		t.Fatalf("RFC3339 passthrough: %q", got)
	}
	if got := normaliseInstallDate(""); got != "" {
		t.Fatalf("empty must stay empty: %q", got)
	}
	// Non-matching input should round-trip without panic.
	if got := normaliseInstallDate("garbage"); got != "garbage" {
		t.Fatalf("garbage must round-trip: %q", got)
	}
}

// -- ParsePowerShellOutput typical workstation -------------------------

func TestParsePowerShellOutputTypicalLaptop(t *testing.T) {
	body := []byte(`{
        "programs": [
            {
                "source": "registry-hklm",
                "registry_key": "Microsoft.PowerShell.Core\\Registry::HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{ABCDEF12-3456-7890-ABCD-EF1234567890}",
                "product_id": "{ABCDEF12-3456-7890-ABCD-EF1234567890}",
                "display_name": "Google Chrome",
                "display_version": "131.0.6778.85",
                "publisher": "Google LLC",
                "install_date": "20240412",
                "install_location": "C:\\Program Files\\Google\\Chrome",
                "uninstall_string": "MsiExec.exe /X{ABCDEF12-3456-7890-ABCD-EF1234567890}",
                "estimated_size_bytes": 314572800,
                "is_system_component": false,
                "is_per_user": false,
                "user_sid": "",
                "parent_key_name": ""
            },
            {
                "source": "registry-hkcu",
                "registry_key": "HKEY_USERS\\S-1-5-21-...\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Discord",
                "product_id": "Discord",
                "display_name": "Discord",
                "display_version": "1.0.9166",
                "publisher": "Discord Inc.",
                "install_date": "20240801",
                "is_per_user": true,
                "user_sid": "S-1-5-21-1234-5678-9012-1001"
            }
        ],
        "patches": [
            {
                "hotfix_id": "KB5031356",
                "description": "Security Update",
                "install_date": "2024-04-15T10:30:00Z",
                "installed_by": "NT AUTHORITY\\SYSTEM",
                "caption": "https://support.microsoft.com/help/5031356"
            },
            {
                "hotfix_id": "kb5034441",
                "description": "Update",
                "install_date": "2024-05-20T11:00:00Z"
            }
        ]
    }`)
	got, err := ParsePowerShellOutput(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got.Programs) != 2 {
		t.Fatalf("programs=%d", len(got.Programs))
	}
	chrome := got.Programs[0]
	if chrome.DisplayName != "Google Chrome" {
		t.Fatalf("name=%q", chrome.DisplayName)
	}
	if chrome.InstallDate != "2024-04-12T00:00:00Z" {
		t.Fatalf("install_date=%q (registry YYYYMMDD must normalise)", chrome.InstallDate)
	}
	if !strings.HasPrefix(chrome.RegistryKey, "HKEY_LOCAL_MACHINE\\") {
		t.Fatalf("registry_key must be canonicalised: %q", chrome.RegistryKey)
	}
	if chrome.EstimatedSizeBytes != 314572800 {
		t.Fatalf("size=%d", chrome.EstimatedSizeBytes)
	}
	if chrome.Source != SourceRegistryHKLM {
		t.Fatalf("source=%q", chrome.Source)
	}

	discord := got.Programs[1]
	if !discord.IsPerUser {
		t.Fatal("HKCU install must flag per-user")
	}
	if discord.Source != SourceRegistryHKCU {
		t.Fatalf("discord source=%q", discord.Source)
	}
	if !strings.HasPrefix(discord.UserSID, "S-1-5-21") {
		t.Fatalf("user_sid=%q", discord.UserSID)
	}

	if len(got.Patches) != 2 {
		t.Fatalf("patches=%d", len(got.Patches))
	}
	for _, p := range got.Patches {
		if !strings.HasPrefix(p.HotFixID, "KB") {
			t.Fatalf("hotfix_id must be canonicalised: %q", p.HotFixID)
		}
		if p.Source != PatchSourceGetHotFix {
			t.Fatalf("source=%q", p.Source)
		}
	}
}

func TestParsePowerShellOutputSkipsMalformedProgram(t *testing.T) {
	body := []byte(`{
        "programs": [
            {"source": "registry-hklm", "registry_key": "X", "product_id": ""},
            {"source": "registry-hklm", "registry_key": "Y", "product_id": "valid"}
        ],
        "patches": []
    }`)
	got, err := ParsePowerShellOutput(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Programs) != 1 || got.Programs[0].ProductID != "valid" {
		t.Fatalf("empty product_id must drop: %+v", got.Programs)
	}
}

func TestParsePowerShellOutputSkipsEmptyHotFixID(t *testing.T) {
	body := []byte(`{
        "programs": [],
        "patches": [
            {"hotfix_id": "", "description": "ghost"},
            {"hotfix_id": "KB1234567", "description": "real"}
        ]
    }`)
	got, err := ParsePowerShellOutput(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Patches) != 1 || got.Patches[0].HotFixID != "KB1234567" {
		t.Fatalf("empty hotfix_id must drop: %+v", got.Patches)
	}
}

func TestParsePowerShellOutputSingletonObjectUnwrap(t *testing.T) {
	body := []byte(`{
        "programs": {"source": "registry-hklm", "registry_key": "X", "product_id": "only"},
        "patches": {"hotfix_id": "KB1234567", "description": "sole"}
    }`)
	got, err := ParsePowerShellOutput(body)
	if err != nil {
		t.Fatalf("singleton parse: %v", err)
	}
	if len(got.Programs) != 1 || len(got.Patches) != 1 {
		t.Fatalf("singleton unwrap broken: %+v", got)
	}
}

func TestParsePowerShellOutputSystemComponentFlag(t *testing.T) {
	body := []byte(`{
        "programs": [{
            "source": "registry-hklm",
            "registry_key": "X",
            "product_id": "sys",
            "display_name": "Windows Component",
            "is_system_component": true
        }],
        "patches": []
    }`)
	got, err := ParsePowerShellOutput(body)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Programs[0].IsSystemComponent {
		t.Fatal("system_component flag must propagate")
	}
}

// -- error paths --------------------------------------------------------

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

// -- sort helpers -------------------------------------------------------

func TestSortPatchesDescending(t *testing.T) {
	in := []Patch{
		{HotFixID: "KB1000000"},
		{HotFixID: "KB9999999"},
		{HotFixID: "KB5000000"},
	}
	SortPatches(in)
	if in[0].HotFixID != "KB9999999" {
		t.Fatalf("first=%+v", in[0])
	}
	if in[2].HotFixID != "KB1000000" {
		t.Fatalf("last=%+v", in[2])
	}
}

func TestSortProgramsDeterministic(t *testing.T) {
	in := []Program{
		{RegistryKey: "Z", UserSID: ""},
		{RegistryKey: "A", UserSID: "S-1"},
		{RegistryKey: "A", UserSID: ""},
	}
	SortPrograms(in)
	if in[0].RegistryKey != "A" || in[0].UserSID != "" {
		t.Fatalf("first=%+v", in[0])
	}
	if in[2].RegistryKey != "Z" {
		t.Fatalf("last=%+v", in[2])
	}
}

// -- script shape spot-check --------------------------------------------

func TestPowerShellScriptShape(t *testing.T) {
	for _, must := range []string{
		`HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`,
		`HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`,
		`HKU:`,
		"Get-HotFix",
		"programs",
		"patches",
	} {
		if !strings.Contains(PowerShellScript, must) {
			t.Fatalf("PowerShellScript missing %q", must)
		}
	}
}
