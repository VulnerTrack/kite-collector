package scheduled

import (
	"strings"
	"testing"
)

func TestNormalizeWindowsTriggerKind(t *testing.T) {
	timeKinds := []string{
		"MSFT_TaskTimeTrigger",
		"MSFT_TaskDailyTrigger",
		"MSFT_TaskWeeklyTrigger",
		"MSFT_TaskMonthlyTrigger",
		"MSFT_TaskMonthlyDOWTrigger",
		"MSFT_TaskIdleTrigger",
		"MSFT_TaskSessionStateChangeTrigger",
	}
	for _, k := range timeKinds {
		if got := NormalizeWindowsTriggerKind(k); got != ScheduleTimeTrigger {
			t.Fatalf("%s = %q, want time-trigger", k, got)
		}
	}
	eventKinds := []string{
		"MSFT_TaskBootTrigger",
		"MSFT_TaskLogonTrigger",
		"MSFT_TaskRegistrationTrigger",
		"MSFT_TaskEventTrigger",
	}
	for _, k := range eventKinds {
		if got := NormalizeWindowsTriggerKind(k); got != ScheduleEventTrigger {
			t.Fatalf("%s = %q, want event-trigger", k, got)
		}
	}
	for _, k := range []string{"", "MSFT_WeirdNewTrigger"} {
		if got := NormalizeWindowsTriggerKind(k); got != ScheduleUnknown {
			t.Fatalf("%q = %q, want unknown", k, got)
		}
	}
}

func TestIsWindowsTaskEnabled(t *testing.T) {
	for _, s := range []string{"Disabled", "disabled", "Unknown", "0", "1"} {
		if IsWindowsTaskEnabled(s) {
			t.Fatalf("%q must be disabled", s)
		}
	}
	for _, s := range []string{"Ready", "Running", "Queued", "ready", "  Running  "} {
		if !IsWindowsTaskEnabled(s) {
			t.Fatalf("%q must be enabled", s)
		}
	}
}

func TestNormalizeWindowsRunAs(t *testing.T) {
	cases := map[string]string{
		"S-1-5-18":    "LocalSystem",
		"S-1-5-19":    "LocalService",
		"S-1-5-20":    "NetworkService",
		"CORP\\alice": "CORP\\alice",
		"":            "",
	}
	for in, want := range cases {
		if got := NormalizeWindowsRunAs(in); got != want {
			t.Fatalf("NormalizeWindowsRunAs(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestJoinTaskPath(t *testing.T) {
	cases := []struct {
		folder, name, want string
	}{
		{"\\Microsoft\\Windows\\UPnP\\", "UPnPHostConfig", "\\Microsoft\\Windows\\UPnP\\UPnPHostConfig"},
		{"\\", "Top", "\\Top"},
		{"\\Custom", "Task", "\\Custom\\Task"},
		{"", "Orphan", "Orphan"},
	}
	for _, c := range cases {
		if got := joinTaskPath(c.folder, c.name); got != c.want {
			t.Fatalf("joinTaskPath(%q,%q) = %q, want %q", c.folder, c.name, got, c.want)
		}
	}
}

func TestJoinExecuteArgs(t *testing.T) {
	cases := []struct{ exe, args, want string }{
		{"powershell.exe", "-c Get-Date", "powershell.exe -c Get-Date"},
		{"C:\\Windows\\System32\\notepad.exe", "", "C:\\Windows\\System32\\notepad.exe"},
		{"", "/c echo hi", "/c echo hi"},
		{"", "", ""},
	}
	for _, c := range cases {
		if got := joinExecuteArgs(c.exe, c.args); got != c.want {
			t.Fatalf("joinExecuteArgs(%q,%q) = %q, want %q", c.exe, c.args, got, c.want)
		}
	}
}

// -- ParseWindowsPowerShellOutput typical mix -------------------------

func TestParseWindowsPowerShellOutputTypicalTasks(t *testing.T) {
	body := []byte(`[
        {
            "name": "GoogleUpdateTaskMachineCore",
            "task_path": "\\",
            "state": "Ready",
            "run_as": "S-1-5-18",
            "run_level": "Highest",
            "execute": "C:\\Program Files (x86)\\Google\\Update\\GoogleUpdate.exe",
            "arguments": "/c",
            "trigger_kind": "MSFT_TaskDailyTrigger",
            "trigger_cron": "2024-01-01T05:00:00",
            "last_run_at": "2026-06-22T05:00:00Z",
            "next_run_at": "2026-06-23T05:00:00Z",
            "last_exit": 0
        },
        {
            "name": "EvilPersistence",
            "task_path": "\\Custom\\",
            "state": "Ready",
            "run_as": "CORP\\alice",
            "execute": "C:\\Users\\alice\\AppData\\Local\\Temp\\payload.exe",
            "arguments": "-stealth",
            "trigger_kind": "MSFT_TaskLogonTrigger",
            "trigger_cron": "",
            "last_run_at": null,
            "next_run_at": null,
            "last_exit": 0
        },
        {
            "name": "DisabledLegacy",
            "task_path": "\\Microsoft\\Windows\\Legacy\\",
            "state": "Disabled",
            "run_as": "S-1-5-19",
            "execute": "C:\\Windows\\System32\\legacy.exe",
            "trigger_kind": "MSFT_TaskBootTrigger",
            "last_exit": 0
        }
    ]`)
	got, err := ParseWindowsPowerShellOutput(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("tasks=%d", len(got))
	}

	chrome := got[0]
	if chrome.Source != SourceWindowsTaskScheduler {
		t.Fatalf("source=%q", chrome.Source)
	}
	if chrome.SourcePath != "\\GoogleUpdateTaskMachineCore" {
		t.Fatalf("source_path=%q", chrome.SourcePath)
	}
	if chrome.RunAs != "LocalSystem" {
		t.Fatalf("run_as=%q (SID must humanise)", chrome.RunAs)
	}
	if chrome.ScheduleKind != ScheduleTimeTrigger {
		t.Fatalf("schedule_kind=%q", chrome.ScheduleKind)
	}
	if chrome.Command != "C:\\Program Files (x86)\\Google\\Update\\GoogleUpdate.exe /c" {
		t.Fatalf("command=%q", chrome.Command)
	}
	if !chrome.Enabled {
		t.Fatal("Ready must flag enabled")
	}
	if chrome.CmdHash == "" {
		t.Fatal("cmd_hash must be populated")
	}
	if !IsPrivilegedRunAs(chrome.RunAs) {
		t.Fatal("LocalSystem must flag privileged")
	}

	evil := got[1]
	if evil.RunAs != "CORP\\alice" {
		t.Fatalf("run_as=%q", evil.RunAs)
	}
	if evil.ScheduleKind != ScheduleEventTrigger {
		t.Fatalf("logon-trigger schedule_kind=%q", evil.ScheduleKind)
	}
	if !IsUntrustedCommandPath(evil.Command) {
		t.Fatal("AppData\\Local\\Temp path must flag untrusted (CWE-829)")
	}

	disabled := got[2]
	if disabled.Enabled {
		t.Fatal("Disabled state must flag !Enabled")
	}
	if disabled.RunAs != "LocalService" {
		t.Fatalf("S-1-5-19 must humanise to LocalService: %q", disabled.RunAs)
	}
}

// -- ParseWindowsPowerShellOutput singleton-object unwrap -------------

func TestParseWindowsPowerShellOutputSingletonObject(t *testing.T) {
	body := []byte(`{
        "name": "Solo",
        "task_path": "\\",
        "state": "Ready",
        "run_as": "S-1-5-18",
        "execute": "C:\\Windows\\System32\\cmd.exe",
        "trigger_kind": "MSFT_TaskTimeTrigger",
        "last_exit": 0
    }`)
	got, err := ParseWindowsPowerShellOutput(body)
	if err != nil {
		t.Fatalf("singleton: %v", err)
	}
	if len(got) != 1 || got[0].Name != "Solo" {
		t.Fatalf("singleton unwrap broken: %+v", got)
	}
}

// -- ParseWindowsPowerShellOutput skips empty names -------------------

func TestParseWindowsPowerShellOutputSkipEmpty(t *testing.T) {
	body := []byte(`[
        {"name":"","state":"Ready"},
        {"name":"real","state":"Ready","execute":"cmd"}
    ]`)
	got, err := ParseWindowsPowerShellOutput(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Name != "real" {
		t.Fatalf("empty-name row must drop: %+v", got)
	}
}

// -- error paths ----------------------------------------------------

func TestParseWindowsPowerShellOutputEmptyError(t *testing.T) {
	if _, err := ParseWindowsPowerShellOutput(nil); err == nil {
		t.Fatal("empty must error")
	}
}

func TestParseWindowsPowerShellOutputMalformedError(t *testing.T) {
	if _, err := ParseWindowsPowerShellOutput([]byte("not json")); err == nil {
		t.Fatal("malformed must error")
	}
}

func TestParseWindowsPowerShellOutputBOMTolerated(t *testing.T) {
	body := append([]byte{0xEF, 0xBB, 0xBF}, []byte(
		`[{"name":"x","state":"Ready","execute":"cmd"}]`,
	)...)
	got, err := ParseWindowsPowerShellOutput(body)
	if err != nil {
		t.Fatalf("BOM payload must parse: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("len=%d", len(got))
	}
}

// -- script shape spot-check ----------------------------------------

func TestWindowsPowerShellScriptShape(t *testing.T) {
	for _, must := range []string{
		"Get-ScheduledTask",
		"Get-ScheduledTaskInfo",
		"Triggers",
		"Principal",
		"ConvertTo-Json",
	} {
		if !strings.Contains(WindowsPowerShellScript, must) {
			t.Fatalf("WindowsPowerShellScript missing %q", must)
		}
	}
}
