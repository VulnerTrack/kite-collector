package software

import (
	"fmt"
	"testing"
)

func TestParseWindowsOSOutputLicensed(t *testing.T) {
	result, err := ParseWindowsOSOutput([]byte(`{"name":"Windows 11 Pro","version":"23H2","build":"22631","architecture":"64-bit","edition":"Professional","license_status":1}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Items) != 1 {
		t.Fatalf("items=%d", len(result.Items))
	}
	got := result.Items[0]
	if got.SoftwareName != "Windows 11 Pro" || got.License != "licensed" {
		t.Fatalf("unexpected OS inventory: %+v", got)
	}
	if got.PackageManager != "windows-os" || got.Version != "23H2 (build 22631)" {
		t.Fatalf("unexpected source/version: %+v", got)
	}
}

func TestParseWindowsOSOutputUnlicensedAndUnknown(t *testing.T) {
	for _, tc := range []struct {
		status int
		want   string
	}{{0, "unlicensed"}, {5, "unlicensed"}, {-1, "unknown"}} {
		result, err := ParseWindowsOSOutput([]byte(fmt.Sprintf(`{"name":"Microsoft Windows","version":"10.0","license_status":%d}`, tc.status)))
		if err != nil {
			t.Fatal(err)
		}
		if result.Items[0].License != tc.want {
			t.Fatalf("status %d: got %q want %q", tc.status, result.Items[0].License, tc.want)
		}
	}
}
