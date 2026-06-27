package windowscpumem

import (
	"strings"
	"testing"
)

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

// -- ParsePowerShellOutput typical 1P/8C/16T host with 2 DIMMs ----------

func TestParsePowerShellOutputTypicalLaptop(t *testing.T) {
	body := []byte(`{
        "cpus": [
            {
                "device_id": "CPU0",
                "socket_designation": "U3E1",
                "manufacturer": "GenuineIntel",
                "name": "13th Gen Intel(R) Core(TM) i7-1365U",
                "description": "Intel64 Family 6 Model 186 Stepping 3",
                "family": 198,
                "processor_id": "BFEBFBFF000B06A3",
                "number_of_cores": 10,
                "number_of_logical_processors": 12,
                "max_clock_speed_mhz": 1800,
                "current_clock_speed_mhz": 1300,
                "l2_cache_size_kb": 9216,
                "l3_cache_size_kb": 12288,
                "virtualization_firmware_enabled": true,
                "vm_monitor_mode_extensions": true
            }
        ],
        "memory_modules": [
            {
                "tag": "Physical Memory 0",
                "device_locator": "Controller0-ChannelA",
                "bank_label": "BANK 0",
                "capacity_bytes": 17179869184,
                "manufacturer": "Micron Technology",
                "part_number": "MTC8C1084S1SC48BA1",
                "serial_number": "ABCDEF12",
                "speed_mhz": 4800,
                "configured_clock_speed_mhz": 4800,
                "memory_type": 34,
                "form_factor": 13
            },
            {
                "tag": "Physical Memory 1",
                "device_locator": "Controller0-ChannelB",
                "bank_label": "BANK 1",
                "capacity_bytes": 17179869184,
                "manufacturer": "Micron Technology",
                "part_number": "MTC8C1084S1SC48BA1",
                "serial_number": "ABCDEF13",
                "speed_mhz": 4800,
                "configured_clock_speed_mhz": 4800,
                "memory_type": 34,
                "form_factor": 13
            }
        ]
    }`)
	got, err := ParsePowerShellOutput(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got.CPUs) != 1 {
		t.Fatalf("cpus=%d", len(got.CPUs))
	}
	cpu := got.CPUs[0]
	if cpu.NumberOfCores != 10 || cpu.NumberOfLogicalProcessors != 12 {
		t.Fatalf("cores/threads: %d/%d", cpu.NumberOfCores, cpu.NumberOfLogicalProcessors)
	}
	if !cpu.VirtualizationFirmwareEnabled {
		t.Fatal("VT-x must be flagged enabled")
	}
	if cpu.L3CacheSizeKB != 12288 {
		t.Fatalf("l3=%d", cpu.L3CacheSizeKB)
	}

	if len(got.MemoryModules) != 2 {
		t.Fatalf("memory_modules=%d", len(got.MemoryModules))
	}
	total := int64(0)
	for _, m := range got.MemoryModules {
		total += m.CapacityBytes
	}
	if total != 34359738368 {
		t.Fatalf("total memory=%d (want 32 GiB)", total)
	}
	if got.MemoryModules[0].SpeedMHz != 4800 {
		t.Fatalf("speed=%d", got.MemoryModules[0].SpeedMHz)
	}
}

// -- ParsePowerShellOutput single-DIMM singleton-object unwrap ----------

func TestParsePowerShellOutputSingletonObjectUnwrap(t *testing.T) {
	// PowerShell ConvertTo-Json emits a singleton object instead of
	// a 1-element array when @(...) wrapping is missing. Our parser
	// must rescue the shape.
	body := []byte(`{
        "cpus": {
            "device_id": "CPU0",
            "manufacturer": "AMD",
            "name": "EPYC",
            "number_of_cores": 64,
            "number_of_logical_processors": 128,
            "max_clock_speed_mhz": 2450,
            "virtualization_firmware_enabled": true,
            "vm_monitor_mode_extensions": true
        },
        "memory_modules": {
            "tag": "Physical Memory 0",
            "device_locator": "DIMM_A1",
            "capacity_bytes": 68719476736,
            "speed_mhz": 3200,
            "memory_type": 26
        }
    }`)
	got, err := ParsePowerShellOutput(body)
	if err != nil {
		t.Fatalf("singleton unwrap parse: %v", err)
	}
	if len(got.CPUs) != 1 {
		t.Fatalf("singleton cpu unwrap failed: %+v", got)
	}
	if len(got.MemoryModules) != 1 {
		t.Fatalf("singleton memory unwrap failed: %+v", got)
	}
	if got.CPUs[0].NumberOfCores != 64 {
		t.Fatalf("cores=%d", got.CPUs[0].NumberOfCores)
	}
	if got.MemoryModules[0].CapacityBytes != 68719476736 {
		t.Fatalf("capacity=%d", got.MemoryModules[0].CapacityBytes)
	}
}

// -- ParsePowerShellOutput dual-socket host -----------------------------

func TestParsePowerShellOutputDualSocket(t *testing.T) {
	body := []byte(`{
        "cpus": [
            {"device_id": "CPU0", "number_of_cores": 32, "number_of_logical_processors": 64,
             "max_clock_speed_mhz": 2900, "virtualization_firmware_enabled": true,
             "vm_monitor_mode_extensions": true},
            {"device_id": "CPU1", "number_of_cores": 32, "number_of_logical_processors": 64,
             "max_clock_speed_mhz": 2900, "virtualization_firmware_enabled": true,
             "vm_monitor_mode_extensions": true}
        ],
        "memory_modules": []
    }`)
	got, err := ParsePowerShellOutput(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.CPUs) != 2 {
		t.Fatalf("cpus=%d", len(got.CPUs))
	}
	totalCores := got.CPUs[0].NumberOfCores + got.CPUs[1].NumberOfCores
	if totalCores != 64 {
		t.Fatalf("total cores=%d", totalCores)
	}
	SortCPUs(got.CPUs)
	if got.CPUs[0].DeviceID != "CPU0" {
		t.Fatalf("sort order: %+v", got.CPUs)
	}
}

// -- ParsePowerShellOutput virtualization disabled flag ----------------

func TestParsePowerShellOutputVTxDisabled(t *testing.T) {
	body := []byte(`{
        "cpus": [{
            "device_id": "CPU0",
            "number_of_cores": 4,
            "number_of_logical_processors": 8,
            "max_clock_speed_mhz": 3600,
            "virtualization_firmware_enabled": false,
            "vm_monitor_mode_extensions": false
        }],
        "memory_modules": []
    }`)
	got, err := ParsePowerShellOutput(body)
	if err != nil {
		t.Fatal(err)
	}
	if got.CPUs[0].VirtualizationFirmwareEnabled {
		t.Fatal("VT-x must be flagged disabled")
	}
	if got.CPUs[0].VMMonitorModeExtensions {
		t.Fatal("VMX must be flagged disabled")
	}
}

// -- ParsePowerShellOutput empty memory slots ---------------------------

func TestParsePowerShellOutputEmptyMemorySlots(t *testing.T) {
	// Hosts with empty DIMM slots can report a row with capacity 0
	// (some vendors do, others omit). We accept both shapes.
	body := []byte(`{
        "cpus": [],
        "memory_modules": [
            {"tag": "Physical Memory 0", "device_locator": "DIMM_A1",
             "capacity_bytes": 17179869184, "speed_mhz": 3200},
            {"tag": "Physical Memory 1", "device_locator": "DIMM_A2",
             "capacity_bytes": 0, "speed_mhz": 0}
        ]
    }`)
	got, err := ParsePowerShellOutput(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.MemoryModules) != 2 {
		t.Fatalf("modules=%d", len(got.MemoryModules))
	}
	emptyFound := false
	for _, m := range got.MemoryModules {
		if m.CapacityBytes == 0 && m.DeviceLocator == "DIMM_A2" {
			emptyFound = true
		}
	}
	if !emptyFound {
		t.Fatal("empty DIMM_A2 slot must be present in output")
	}
}

// -- error paths --------------------------------------------------------

func TestParsePowerShellOutputEmptyError(t *testing.T) {
	if _, err := ParsePowerShellOutput(nil); err == nil {
		t.Fatal("empty must error")
	}
}

func TestParsePowerShellOutputMalformedError(t *testing.T) {
	if _, err := ParsePowerShellOutput([]byte("not json at all")); err == nil {
		t.Fatal("malformed must error")
	}
}

func TestParsePowerShellOutputBOMTolerated(t *testing.T) {
	body := append([]byte{0xEF, 0xBB, 0xBF}, []byte(`{"cpus":[],"memory_modules":[]}`)...)
	if _, err := ParsePowerShellOutput(body); err != nil {
		t.Fatalf("BOM payload must parse: %v", err)
	}
}

// -- helpers ------------------------------------------------------------

func TestUnwrapSingletonValueArrayIdempotent(t *testing.T) {
	// Already an array: must be unchanged.
	in := `{"cpus":[{"device_id":"CPU0"}],"memory_modules":[]}`
	if out := string(unwrapSingletonArrays([]byte(in))); out != in {
		t.Fatalf("array form should be idempotent: %q vs %q", out, in)
	}
}

func TestUnwrapSingletonValueObjectGetsWrapped(t *testing.T) {
	in := `{"cpus":{"device_id":"CPU0"},"memory_modules":[]}`
	got := string(unwrapSingletonArrays([]byte(in)))
	if !strings.Contains(got, `"cpus":[{`) {
		t.Fatalf("singleton object must be wrapped: %q", got)
	}
}

// -- script shape spot-check --------------------------------------------

func TestPowerShellScriptShape(t *testing.T) {
	for _, must := range []string{
		"Win32_Processor",
		"Win32_PhysicalMemory",
		"ConvertTo-Json",
		"virtualization_firmware_enabled",
		"capacity_bytes",
	} {
		if !strings.Contains(PowerShellScript, must) {
			t.Fatalf("PowerShellScript missing %q", must)
		}
	}
}

func TestSortMemoryModulesDeterministic(t *testing.T) {
	in := []MemoryModule{
		{Tag: "Physical Memory 1", DeviceLocator: "DIMM_B1"},
		{Tag: "Physical Memory 0", DeviceLocator: "DIMM_A1"},
		{Tag: "Physical Memory 2", DeviceLocator: "DIMM_A1"},
	}
	SortMemoryModules(in)
	// device_locator sorts first, then tag.
	if in[0].DeviceLocator != "DIMM_A1" || in[0].Tag != "Physical Memory 0" {
		t.Fatalf("first=%+v", in[0])
	}
	if in[2].DeviceLocator != "DIMM_B1" {
		t.Fatalf("last=%+v", in[2])
	}
}
