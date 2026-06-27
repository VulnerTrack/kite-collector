package services

import (
	"strings"
	"testing"
	"time"
)

func TestNormalizeWindowsState(t *testing.T) {
	cases := map[string]State{
		"Running":          StateRunning,
		"running":          StateRunning,
		"Stopped":          StateStopped,
		"Paused":           StateStopped,
		"Start Pending":    StateActivating,
		"Continue Pending": StateActivating,
		"Stop Pending":     StateDeactivating,
		"Pause Pending":    StateDeactivating,
		"":                 StateUnknown,
		"unknownword":      StateUnknown,
	}
	for in, want := range cases {
		if got := NormalizeWindowsState(in); got != want {
			t.Fatalf("NormalizeWindowsState(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNormalizeWindowsStartMode(t *testing.T) {
	cases := map[string]StartMode{
		"Auto":     StartAuto,
		"auto":     StartAuto,
		"Manual":   StartManual,
		"Disabled": StartDisabled,
		"Boot":     StartBoot,
		"System":   StartSystem,
		"":         StartUnknown,
		"weird":    StartUnknown,
	}
	for in, want := range cases {
		if got := NormalizeWindowsStartMode(in); got != want {
			t.Fatalf("NormalizeWindowsStartMode(%q) = %q, want %q", in, got, want)
		}
	}
}

// -- ParseWindowsPowerShellOutput typical Windows 11 fixture -----------

func TestParseWindowsPowerShellOutputTypical(t *testing.T) {
	body := []byte(`[
        {
            "name": "Spooler",
            "display_name": "Print Spooler",
            "description": "Loads files to memory for later printing.",
            "path_name": "C:\\WINDOWS\\System32\\spoolsv.exe",
            "start_mode": "Auto",
            "state": "Running",
            "start_name": "LocalSystem",
            "process_id": 2436,
            "exit_code": 0
        },
        {
            "name": "BITS",
            "display_name": "Background Intelligent Transfer Service",
            "path_name": "C:\\WINDOWS\\system32\\svchost.exe -k netsvcs -p",
            "start_mode": "Manual",
            "state": "Stopped",
            "start_name": "LocalSystem",
            "process_id": 0,
            "exit_code": 0
        },
        {
            "name": "WinDefend",
            "display_name": "Microsoft Defender Antivirus Service",
            "path_name": "\"C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18\\MsMpEng.exe\"",
            "start_mode": "Auto",
            "state": "Running",
            "start_name": "LocalSystem",
            "process_id": 4112,
            "exit_code": 0
        }
    ]`)
	got, err := ParseWindowsPowerShellOutput(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("services=%d, want 3", len(got))
	}

	spooler := got[0]
	if spooler.Manager != ManagerWindowsSCM {
		t.Fatalf("manager=%q", spooler.Manager)
	}
	if spooler.State != StateRunning {
		t.Fatalf("state=%q", spooler.State)
	}
	if spooler.StartMode != StartAuto {
		t.Fatalf("start_mode=%q", spooler.StartMode)
	}
	if spooler.PID != 2436 {
		t.Fatalf("pid=%d", spooler.PID)
	}
	if spooler.BinaryPath != "C:\\WINDOWS\\System32\\spoolsv.exe" {
		t.Fatalf("binary_path=%q", spooler.BinaryPath)
	}
	if spooler.RunAs != "LocalSystem" {
		t.Fatalf("run_as=%q", spooler.RunAs)
	}

	bits := got[1]
	if bits.State != StateStopped {
		t.Fatalf("BITS state=%q", bits.State)
	}
	if bits.StartMode != StartManual {
		t.Fatalf("BITS start_mode=%q", bits.StartMode)
	}
	if bits.PID != 0 {
		t.Fatalf("BITS pid=%d (stopped service)", bits.PID)
	}
}

// -- ParseWindowsPowerShellOutput pending-state coverage ---------------

func TestParseWindowsPowerShellOutputPendingStates(t *testing.T) {
	body := []byte(`[
        {"name":"a","start_mode":"Auto","state":"Start Pending","process_id":0,"exit_code":0},
        {"name":"b","start_mode":"Auto","state":"Stop Pending","process_id":0,"exit_code":0},
        {"name":"c","start_mode":"Manual","state":"Paused","process_id":0,"exit_code":0}
    ]`)
	got, err := ParseWindowsPowerShellOutput(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	wantStates := []State{StateActivating, StateDeactivating, StateStopped}
	for i, want := range wantStates {
		if got[i].State != want {
			t.Fatalf("service %d state=%q, want %q", i, got[i].State, want)
		}
	}
}

// -- ParseWindowsPowerShellOutput driver fixture (Boot/System start) ---

func TestParseWindowsPowerShellOutputDriverStartModes(t *testing.T) {
	body := []byte(`[
        {"name":"acpi","start_mode":"Boot","state":"Running","process_id":0,"exit_code":0},
        {"name":"crashdmp","start_mode":"System","state":"Running","process_id":0,"exit_code":0}
    ]`)
	got, err := ParseWindowsPowerShellOutput(body)
	if err != nil {
		t.Fatal(err)
	}
	if got[0].StartMode != StartBoot || got[1].StartMode != StartSystem {
		t.Fatalf("start modes=%q,%q", got[0].StartMode, got[1].StartMode)
	}
}

// -- ParseWindowsPowerShellOutput singleton-object unwrap --------------

func TestParseWindowsPowerShellOutputSingletonUnwrap(t *testing.T) {
	body := []byte(`{
        "name": "OnlyService",
        "start_mode": "Auto",
        "state": "Running",
        "process_id": 1,
        "exit_code": 0
    }`)
	got, err := ParseWindowsPowerShellOutput(body)
	if err != nil {
		t.Fatalf("singleton parse: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("singleton object should yield 1 service, got %d", len(got))
	}
	if got[0].Name != "OnlyService" {
		t.Fatalf("name=%q", got[0].Name)
	}
}

// -- ParseWindowsPowerShellOutput skip empty names ---------------------

func TestParseWindowsPowerShellOutputSkipEmptyName(t *testing.T) {
	body := []byte(`[
        {"name":"","start_mode":"Auto","state":"Running","process_id":0,"exit_code":0},
        {"name":"real","start_mode":"Auto","state":"Running","process_id":0,"exit_code":0}
    ]`)
	got, err := ParseWindowsPowerShellOutput(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Name != "real" {
		t.Fatalf("empty-name row must be skipped: %+v", got)
	}
}

// -- StampWindowsServices --------------------------------------------

func TestStampWindowsServices(t *testing.T) {
	svcs := []Service{{Name: "a"}, {Name: "b"}}
	now := time.Date(2026, 6, 23, 12, 0, 0, 0, time.UTC)
	StampWindowsServices(svcs, now)
	for i, s := range svcs {
		if !s.CollectedAt.Equal(now) {
			t.Fatalf("svc %d CollectedAt=%v", i, s.CollectedAt)
		}
		if !s.LastSeenAt.Equal(now) {
			t.Fatalf("svc %d LastSeenAt=%v", i, s.LastSeenAt)
		}
	}
}

// -- error paths -----------------------------------------------------

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
		`[{"name":"x","start_mode":"Auto","state":"Running","process_id":1,"exit_code":0}]`,
	)...)
	got, err := ParseWindowsPowerShellOutput(body)
	if err != nil {
		t.Fatalf("BOM payload must parse: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("len=%d", len(got))
	}
}

// -- script shape spot-check -----------------------------------------

func TestWindowsPowerShellScriptShape(t *testing.T) {
	for _, must := range []string{
		"Win32_Service",
		"start_mode",
		"start_name",
		"process_id",
		"ConvertTo-Json",
	} {
		if !strings.Contains(WindowsPowerShellScript, must) {
			t.Fatalf("WindowsPowerShellScript missing %q", must)
		}
	}
}
