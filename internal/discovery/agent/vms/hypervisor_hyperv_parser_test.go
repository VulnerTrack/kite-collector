package vms

import (
	"strings"
	"testing"
)

func TestNormalizeHyperVState(t *testing.T) {
	cases := map[string]State{
		"Off":          StateShutoff,
		"off":          StateShutoff,
		"Running":      StateRunning,
		"Saved":        StateSaved,
		"FastSaved":    StateSaved,
		"Paused":       StatePaused,
		"Stopping":     StateShutdown,
		"ShuttingDown": StateShutdown,
		"Starting":     StateUnknown,
		"Saving":       StateUnknown,
		"FastSaving":   StateUnknown,
		"":             StateUnknown,
		// Falls through to the libvirt-shared NormalizeState.
		"crashed":     StateCrashed,
		"weird-state": StateUnknown,
	}
	for in, want := range cases {
		if got := NormalizeHyperVState(in); got != want {
			t.Fatalf("NormalizeHyperVState(%q) = %q, want %q", in, got, want)
		}
	}
}

// -- ParseHyperVPowerShellOutput typical fixture ---------------------

func TestParseHyperVPowerShellOutputTypical(t *testing.T) {
	body := []byte(`[
        {
            "name": "WebServer01",
            "vm_uuid": "9ABCDEF1-2345-6789-ABCD-EF1234567890",
            "state": "Running",
            "vcpus": 4,
            "ram_bytes": 8589934592,
            "os_type": "Microsoft Windows Server 2022 Standard",
            "config_path": "C:\\ProgramData\\Microsoft\\Windows\\Hyper-V\\WebServer01.xml",
            "started_at": "2026-06-23T08:00:00Z",
            "notes": ""
        },
        {
            "name": "DevBox",
            "vm_uuid": "00000000-1111-2222-3333-444444444444",
            "state": "Off",
            "vcpus": 2,
            "ram_bytes": 4294967296,
            "os_type": "",
            "config_path": "D:\\VMs\\DevBox.xml",
            "started_at": null,
            "notes": "Spinning down"
        },
        {
            "name": "PausedAppliance",
            "vm_uuid": "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE",
            "state": "Paused",
            "vcpus": 1,
            "ram_bytes": 1073741824,
            "os_type": "Linux",
            "started_at": "2026-06-22T12:00:00Z",
            "notes": ""
        }
    ]`)
	got, err := ParseHyperVPowerShellOutput(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("vms=%d", len(got))
	}
	web := got[0]
	if web.Hypervisor != HypervisorHyperV {
		t.Fatalf("hypervisor=%q", web.Hypervisor)
	}
	if web.State != StateRunning {
		t.Fatalf("web state=%q", web.State)
	}
	if web.VCPUs != 4 {
		t.Fatalf("vcpus=%d", web.VCPUs)
	}
	if web.RAMBytes != 8589934592 {
		t.Fatalf("ram=%d", web.RAMBytes)
	}
	if web.StartedAt != "2026-06-23T08:00:00Z" {
		t.Fatalf("started_at=%q", web.StartedAt)
	}

	dev := got[1]
	if dev.State != StateShutoff {
		t.Fatalf("dev state=%q", dev.State)
	}
	if dev.StartedAt != "" {
		t.Fatalf("dev started_at must be empty when off: %q", dev.StartedAt)
	}

	paused := got[2]
	if paused.State != StatePaused {
		t.Fatalf("paused state=%q", paused.State)
	}
}

// -- ParseHyperVPowerShellOutput singleton-object unwrap -------------

func TestParseHyperVPowerShellOutputSingletonUnwrap(t *testing.T) {
	body := []byte(`{
        "name": "Solo",
        "vm_uuid": "FFFFFFFF-1111-2222-3333-444444444444",
        "state": "Running",
        "vcpus": 1,
        "ram_bytes": 2147483648
    }`)
	got, err := ParseHyperVPowerShellOutput(body)
	if err != nil {
		t.Fatalf("singleton: %v", err)
	}
	if len(got) != 1 || got[0].Name != "Solo" {
		t.Fatalf("singleton unwrap broken: %+v", got)
	}
}

// -- ParseHyperVPowerShellOutput skips empty rows --------------------

func TestParseHyperVPowerShellOutputSkipEmpty(t *testing.T) {
	body := []byte(`[
        {"name":"","vm_uuid":"","state":"Off"},
        {"name":"real","vm_uuid":"1","state":"Running","vcpus":1,"ram_bytes":1}
    ]`)
	got, err := ParseHyperVPowerShellOutput(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Name != "real" {
		t.Fatalf("empty-row must drop: %+v", got)
	}
}

// -- ParseHyperVPowerShellOutput sentinel JSON-number handling -------

func TestParseHyperVPowerShellOutputBigRAM(t *testing.T) {
	// 192 GiB — outside int32, must round-trip via int64/uint64.
	body := []byte(`[{"name":"big","vm_uuid":"big","state":"Running","vcpus":48,"ram_bytes":206158430208}]`)
	got, err := ParseHyperVPowerShellOutput(body)
	if err != nil {
		t.Fatal(err)
	}
	if got[0].RAMBytes != 206158430208 {
		t.Fatalf("ram=%d", got[0].RAMBytes)
	}
}

// -- error paths ----------------------------------------------------

func TestParseHyperVPowerShellOutputEmptyError(t *testing.T) {
	if _, err := ParseHyperVPowerShellOutput(nil); err == nil {
		t.Fatal("empty must error")
	}
}

func TestParseHyperVPowerShellOutputMalformedError(t *testing.T) {
	if _, err := ParseHyperVPowerShellOutput([]byte("not json")); err == nil {
		t.Fatal("malformed must error")
	}
}

func TestParseHyperVPowerShellOutputBOMTolerated(t *testing.T) {
	body := append([]byte{0xEF, 0xBB, 0xBF}, []byte(
		`[{"name":"x","vm_uuid":"x","state":"Running","vcpus":1,"ram_bytes":1}]`,
	)...)
	if _, err := ParseHyperVPowerShellOutput(body); err != nil {
		t.Fatalf("BOM payload must parse: %v", err)
	}
}

// -- script shape spot-check ----------------------------------------

func TestHyperVPowerShellScriptShape(t *testing.T) {
	for _, must := range []string{
		"Get-VM",
		"VMId",
		"State",
		"ProcessorCount",
		"MemoryAssigned",
		"ConvertTo-Json",
	} {
		if !strings.Contains(HyperVPowerShellScript, must) {
			t.Fatalf("HyperVPowerShellScript missing %q", must)
		}
	}
}
