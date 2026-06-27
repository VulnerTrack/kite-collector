package mdmfingerprint

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// touch creates an empty file at relative path under root, materialising
// every intermediate directory. Tests use it to lay out fixture trees
// that mimic the real host paths the collector walks.
func touch(t *testing.T, root, rel string) {
	t.Helper()
	// Strip a leading drive letter from Windows fixture paths so
	// joinUnder's logic round-trips cleanly under any test runner.
	if len(rel) >= 2 && rel[1] == ':' {
		rel = rel[2:]
	}
	rel = strings.TrimPrefix(rel, "/")
	full := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(full), err)
	}
	if err := os.WriteFile(full, nil, 0o644); err != nil { //#nosec G306 -- fixture
		t.Fatalf("touch %s: %v", full, err)
	}
}

// mkdir is the directory equivalent of touch — for signal paths that
// are directory matches (e.g. "/Library/Application Support/JAMF").
func mkdir(t *testing.T, root, rel string) {
	t.Helper()
	if len(rel) >= 2 && rel[1] == ':' {
		rel = rel[2:]
	}
	rel = strings.TrimPrefix(rel, "/")
	full := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(full, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", full, err)
	}
}

func TestFSCollector_NoSignalsOnEmptyRoot(t *testing.T) {
	root := t.TempDir()
	c := NewFSCollector("test-empty", SourceLinuxFS, linuxSignals(), root)
	state, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	if len(state.Fingerprints) != 0 {
		t.Fatalf("expected zero fingerprints, got %d: %+v", len(state.Fingerprints), state.Fingerprints)
	}
	if state.IsMDMManaged {
		t.Fatalf("expected IsMDMManaged=false on empty root")
	}
	if state.Source != SourceLinuxFS {
		t.Fatalf("expected Source=%s, got %s", SourceLinuxFS, state.Source)
	}
}

func TestFSCollector_DetectsJamfOnMacOSFixture(t *testing.T) {
	root := t.TempDir()
	touch(t, root, "/usr/local/jamf/bin/jamf")
	mkdir(t, root, "/Library/Application Support/JAMF")
	touch(t, root, "/Library/LaunchDaemons/com.jamfsoftware.task.1.plist")

	c := NewFSCollector("test-jamf", SourceDarwinFS, macosSignals(), root)
	state, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	if !state.IsMDMManaged {
		t.Fatalf("expected IsMDMManaged=true with Jamf signals present")
	}
	if !containsVendor(state.Vendors, VendorJamf) {
		t.Fatalf("expected vendors to contain %s, got %v", VendorJamf, state.Vendors)
	}
	if len(state.Fingerprints) != 3 {
		t.Fatalf("expected 3 Jamf fingerprints, got %d: %+v", len(state.Fingerprints), state.Fingerprints)
	}
}

func TestFSCollector_DetectsAppleMDMEnrollmentAsHighConfidence(t *testing.T) {
	root := t.TempDir()
	touch(t, root, "/var/db/ConfigurationProfiles/Settings/.cloudConfigHasActivationRecord")

	c := NewFSCollector("test-apple", SourceDarwinFS, macosSignals(), root)
	state, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	if len(state.Fingerprints) != 1 {
		t.Fatalf("expected 1 fingerprint, got %d", len(state.Fingerprints))
	}
	fp := state.Fingerprints[0]
	if fp.Vendor != VendorAppleMDM {
		t.Fatalf("expected vendor %s, got %s", VendorAppleMDM, fp.Vendor)
	}
	if fp.Confidence != ConfidenceHigh {
		t.Fatalf("expected confidence high, got %s", fp.Confidence)
	}
	if !fp.Enrollment {
		t.Fatalf("expected enrollment=true on activation record")
	}
}

func TestFSCollector_DetectsMultipleVendorsAndDeduplicatesInVendors(t *testing.T) {
	root := t.TempDir()
	// Two Jamf signals plus one Kandji daemon.
	touch(t, root, "/usr/local/jamf/bin/jamf")
	mkdir(t, root, "/Library/Application Support/JAMF")
	touch(t, root, "/Library/LaunchDaemons/io.kandji.KandjiDaemon.plist")

	c := NewFSCollector("test-multi", SourceDarwinFS, macosSignals(), root)
	state, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	if len(state.Fingerprints) != 3 {
		t.Fatalf("expected 3 fingerprints, got %d", len(state.Fingerprints))
	}
	got := append([]Vendor(nil), state.Vendors...)
	sort.Slice(got, func(i, j int) bool { return got[i] < got[j] })
	want := []Vendor{VendorJamf, VendorKandji}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("expected vendors %v, got %v", want, got)
	}
}

func TestFSCollector_LinuxDetectsJumpCloudAndTanium(t *testing.T) {
	root := t.TempDir()
	touch(t, root, "/opt/jc/bin/jumpcloud-agent")
	touch(t, root, "/etc/systemd/system/jcagent.service")
	touch(t, root, "/opt/Tanium/TaniumClient/TaniumClient")

	c := NewFSCollector("test-linux", SourceLinuxFS, linuxSignals(), root)
	state, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	if !containsVendor(state.Vendors, VendorJumpCloud) || !containsVendor(state.Vendors, VendorTanium) {
		t.Fatalf("expected jumpcloud + tanium vendors, got %v", state.Vendors)
	}
}

func TestFSCollector_WindowsFixtureUsesDriveLetterStripping(t *testing.T) {
	root := t.TempDir()
	// Lay out fixture without the C: drive letter; joinUnder strips it.
	touch(t, root, "/Program Files (x86)/Microsoft Intune Management Extension/Microsoft.Management.Services.IntuneWindowsAgent.exe")

	c := NewFSCollector("test-win-fs", SourceWindowsFS, windowsFSSignals(), root)
	state, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	if !containsVendor(state.Vendors, VendorIntune) {
		t.Fatalf("expected intune vendor, got %v", state.Vendors)
	}
}

func TestRegistryCollector_EnrollmentRequiresSubkeys(t *testing.T) {
	signals := WindowsRegistrySignals()
	// Probe reports the Enrollments root exists but is empty — that
	// must NOT register as managed (leftover from unenrollment).
	probe := func(path string) (bool, bool, error) {
		if path == `SOFTWARE\Microsoft\Enrollments` {
			return true, false, nil
		}
		return false, false, nil
	}
	c := NewRegistryCollector(signals, probe)
	state, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	if len(state.Fingerprints) != 0 {
		t.Fatalf("expected zero fingerprints for empty enrollment root, got %+v", state.Fingerprints)
	}
}

func TestRegistryCollector_EnrollmentWithSubkeyFlagsManaged(t *testing.T) {
	signals := WindowsRegistrySignals()
	probe := func(path string) (bool, bool, error) {
		if path == `SOFTWARE\Microsoft\Enrollments` {
			return true, true, nil
		}
		return false, false, nil
	}
	c := NewRegistryCollector(signals, probe)
	state, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	if !state.IsMDMManaged {
		t.Fatalf("expected IsMDMManaged=true when enrollment subkey exists")
	}
	if !containsVendor(state.Vendors, VendorWindowsMDM) {
		t.Fatalf("expected windows-mdm vendor, got %v", state.Vendors)
	}
}

func TestRegistryCollector_IntunePolicyManagerHit(t *testing.T) {
	signals := WindowsRegistrySignals()
	probe := func(path string) (bool, bool, error) {
		if path == `SOFTWARE\Microsoft\PolicyManager\current\device` {
			return true, true, nil
		}
		return false, false, nil
	}
	c := NewRegistryCollector(signals, probe)
	state, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	if !containsVendor(state.Vendors, VendorIntune) {
		t.Fatalf("expected intune vendor, got %v", state.Vendors)
	}
}

func TestRegistryCollector_NilProbeIsSafe(t *testing.T) {
	c := NewRegistryCollector(WindowsRegistrySignals(), nil)
	state, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect with nil probe should not error, got %v", err)
	}
	if len(state.Fingerprints) != 0 {
		t.Fatalf("expected zero fingerprints with nil probe, got %+v", state.Fingerprints)
	}
}

func TestMergeStates_CombinesFingerprintsAndRollsUp(t *testing.T) {
	a := State{
		Source: SourceWindowsFS,
		Fingerprints: []Fingerprint{{
			Vendor:     VendorIntune,
			Product:    "Intune fs",
			Kind:       SignalAgentBinary,
			Evidence:   "C:/Program Files/...",
			Confidence: ConfidenceMedium,
		}},
	}
	b := State{
		Source: SourceWindowsRegistry,
		Fingerprints: []Fingerprint{{
			Vendor:     VendorWindowsMDM,
			Product:    "OMADM",
			Kind:       SignalEnrollmentRecord,
			Evidence:   `SOFTWARE\Microsoft\Enrollments`,
			Confidence: ConfidenceHigh,
			Enrollment: true,
		}},
	}
	merged := MergeStates(a, b)
	if !merged.IsMDMManaged {
		t.Fatalf("expected merged state to flag managed")
	}
	if !containsVendor(merged.Vendors, VendorIntune) || !containsVendor(merged.Vendors, VendorWindowsMDM) {
		t.Fatalf("expected both vendors after merge, got %v", merged.Vendors)
	}
	if len(merged.Fingerprints) != 2 {
		t.Fatalf("expected 2 fingerprints after merge, got %d", len(merged.Fingerprints))
	}
	if merged.Source != SourceWindowsFS {
		t.Fatalf("expected Source=%s (first non-empty), got %s", SourceWindowsFS, merged.Source)
	}
}

func TestAnnotate_LowConfidenceAloneDoesNotFlagManaged(t *testing.T) {
	state := State{Fingerprints: []Fingerprint{{
		Vendor:     VendorOsquery,
		Product:    "osquery",
		Kind:       SignalConfigDir,
		Confidence: ConfidenceLow,
	}}}
	Annotate(&state)
	if state.IsMDMManaged {
		t.Fatalf("low-confidence-only state must not flag managed")
	}
	if len(state.Vendors) != 1 || state.Vendors[0] != VendorOsquery {
		t.Fatalf("expected vendors=[osquery], got %v", state.Vendors)
	}
}

func TestTagsFromVendors(t *testing.T) {
	got := TagsFromVendors([]Vendor{VendorJamf, VendorIntune})
	want := map[string]string{
		"mdm":        "intune,jamf",
		"mdm.intune": "true",
		"mdm.jamf":   "true",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("TagsFromVendors mismatch: want %v, got %v", want, got)
	}
	if TagsFromVendors(nil) != nil {
		t.Fatalf("TagsFromVendors(nil) must return nil")
	}
}

func TestSortFingerprints_DeterministicOrder(t *testing.T) {
	fps := []Fingerprint{
		{Vendor: VendorKandji, Evidence: "b"},
		{Vendor: VendorJamf, Evidence: "z"},
		{Vendor: VendorJamf, Evidence: "a"},
	}
	SortFingerprints(fps)
	want := []Fingerprint{
		{Vendor: VendorJamf, Evidence: "a"},
		{Vendor: VendorJamf, Evidence: "z"},
		{Vendor: VendorKandji, Evidence: "b"},
	}
	if !reflect.DeepEqual(fps, want) {
		t.Fatalf("sort order mismatch: want %v, got %v", want, fps)
	}
}

func TestCollect_ContextCancelledReturnsError(t *testing.T) {
	root := t.TempDir()
	c := NewFSCollector("test-ctx", SourceLinuxFS, linuxSignals(), root)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Collect(ctx); err == nil {
		t.Fatalf("expected context cancellation error")
	}
}

func containsVendor(vs []Vendor, v Vendor) bool {
	for _, x := range vs {
		if x == v {
			return true
		}
	}
	return false
}
