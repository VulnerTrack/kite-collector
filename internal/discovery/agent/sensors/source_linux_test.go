//go:build linux

package sensors

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func writeHwmon(t *testing.T, root, hw, chip string, kv map[string]string) {
	t.Helper()
	dir := filepath.Join(root, hw)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "name"), []byte(chip), 0o644); err != nil {
		t.Fatal(err)
	}
	for k, v := range kv {
		if err := os.WriteFile(filepath.Join(dir, k), []byte(v), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestLinuxSourceEnumeratesHwmon(t *testing.T) {
	root := t.TempDir()

	// coretemp with two CPU cores + crit threshold.
	writeHwmon(t, root, "hwmon0", "coretemp", map[string]string{
		"temp1_input": "57000\n",
		"temp1_label": "Core 0",
		"temp1_max":   "100000",
		"temp1_crit":  "105000",
		"temp2_input": "55000",
		"temp2_label": "Core 1",
	})
	// nct6798 motherboard chip with fans + voltages.
	writeHwmon(t, root, "hwmon1", "nct6798", map[string]string{
		"fan1_input":  "1320",
		"fan2_input":  "0",
		"in0_input":   "1200", // VCore
		"temp1_input": "42000",
	})

	got, err := NewLinuxSource(root).Enumerate(context.Background())
	if err != nil {
		t.Fatalf("Enumerate: %v", err)
	}
	if len(got) != 6 {
		t.Fatalf("want 6 channels, got %d: %+v", len(got), got)
	}

	by := map[string]Sensor{}
	for _, s := range got {
		by[s.Chip+"/"+s.SensorName] = s
	}
	if by["coretemp/temp1"].ValueMillis != 57000 {
		t.Fatalf("core 0 value=%d", by["coretemp/temp1"].ValueMillis)
	}
	if by["coretemp/temp1"].SensorLabel != "Core 0" {
		t.Fatalf("core 0 label=%q", by["coretemp/temp1"].SensorLabel)
	}
	if by["coretemp/temp1"].SensorType != SensorTemp {
		t.Fatalf("core 0 type=%q", by["coretemp/temp1"].SensorType)
	}
	if by["coretemp/temp1"].CritMillis != 105000 {
		t.Fatalf("core 0 crit=%d", by["coretemp/temp1"].CritMillis)
	}
	if by["nct6798/fan1"].SensorType != SensorFan || by["nct6798/fan1"].ValueMillis != 1320 {
		t.Fatalf("fan wrong: %+v", by["nct6798/fan1"])
	}
	if by["nct6798/in0"].SensorType != SensorVoltage {
		t.Fatalf("voltage wrong: %+v", by["nct6798/in0"])
	}
}

func TestLinuxSourceMissingRootReturnsEmpty(t *testing.T) {
	got, err := NewLinuxSource(filepath.Join(t.TempDir(), "nope")).
		Enumerate(context.Background())
	if err != nil {
		t.Fatalf("missing must not error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want empty, got %d", len(got))
	}
}

func TestCollectorEndToEndAnnotations(t *testing.T) {
	root := t.TempDir()
	writeHwmon(t, root, "hwmon0", "coretemp", map[string]string{
		"temp1_input": "112000",
		"temp1_crit":  "100000",
	})
	got, err := NewCollectorWith(NewLinuxSource(root)).Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("len=%d", len(got))
	}
	if !got[0].IsThermalRisk {
		t.Fatalf("thermal risk missing: %+v", got[0])
	}
}
