package resource

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakePolicy lets tests drive OSDetector without depending on the host OS.
type fakePolicy struct {
	name      string
	osType    string
	osName    string
	osVersion string
	matches   bool
}

func (f fakePolicy) Name() string { return f.name }
func (f fakePolicy) Detect() (string, string, string, bool) {
	return f.osType, f.osName, f.osVersion, f.matches
}

func TestOSDetector_FirstMatchingPolicyWins(t *testing.T) {
	d := NewOSDetector(
		fakePolicy{name: "first", matches: false},
		fakePolicy{name: "second", osType: "linux", osName: "alpine", osVersion: "3.20", matches: true},
		fakePolicy{name: "third", osType: "darwin", osName: "macos", osVersion: "14", matches: true},
	)
	osType, osName, osVersion := d.Detect()
	assert.Equal(t, "linux", osType)
	assert.Equal(t, "alpine", osName)
	assert.Equal(t, "3.20", osVersion)
}

func TestOSDetector_RuntimeFallbackWhenNoPolicyMatches(t *testing.T) {
	d := NewOSDetector(
		fakePolicy{name: "skip-1", matches: false},
		fakePolicy{name: "skip-2", matches: false},
	)
	osType, osName, osVersion := d.Detect()
	assert.Equal(t, runtime.GOOS, osType)
	assert.Equal(t, runtime.GOOS, osName)
	assert.Equal(t, "unknown", osVersion)
}

func TestOSDetector_EmptyChainStillReturnsTriple(t *testing.T) {
	d := NewOSDetector()
	osType, osName, osVersion := d.Detect()
	assert.NotEmpty(t, osType)
	assert.NotEmpty(t, osName)
	assert.NotEmpty(t, osVersion)
}

func TestRuntimeFallbackPolicy_AlwaysMatches(t *testing.T) {
	p := RuntimeFallbackPolicy{}
	assert.Equal(t, "runtime:fallback", p.Name())
	osType, osName, osVersion, ok := p.Detect()
	assert.True(t, ok)
	assert.Equal(t, runtime.GOOS, osType)
	assert.Equal(t, runtime.GOOS, osName)
	assert.Equal(t, "unknown", osVersion)
}

func TestLinuxOSReleasePolicy_NameIsStable(t *testing.T) {
	assert.Equal(t, "linux:os-release", NewLinuxOSReleasePolicy().Name())
}

func TestLinuxOSReleasePolicy_DetectFromFixture(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("LinuxOSReleasePolicy is a no-op on non-Linux")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "os-release")
	require.NoError(t, os.WriteFile(path, []byte(`ID=ubuntu
VERSION_ID="22.04"
PRETTY_NAME="Ubuntu 22.04"
`), 0o600))

	p := LinuxOSReleasePolicy{path: path}
	osType, osName, osVersion, ok := p.Detect()
	assert.True(t, ok)
	assert.Equal(t, "linux", osType)
	assert.Equal(t, "ubuntu", osName)
	assert.Equal(t, "22.04", osVersion)
}

func TestLinuxOSReleasePolicy_DetectFallsBackOnMissingKeys(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("LinuxOSReleasePolicy is a no-op on non-Linux")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "os-release")
	require.NoError(t, os.WriteFile(path, []byte("# empty file\n"), 0o600))

	p := LinuxOSReleasePolicy{path: path}
	osType, osName, osVersion, ok := p.Detect()
	assert.True(t, ok)
	assert.Equal(t, "linux", osType)
	assert.Equal(t, "linux", osName, "missing ID falls back to 'linux'")
	assert.Equal(t, "unknown", osVersion, "missing VERSION_ID falls back to 'unknown'")
}

func TestLinuxOSReleasePolicy_DetectMissingFile(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("LinuxOSReleasePolicy is a no-op on non-Linux")
	}
	p := LinuxOSReleasePolicy{path: "/nonexistent/os-release"}
	_, _, _, ok := p.Detect()
	assert.False(t, ok, "missing file must signal not-applicable")
}

// TestLinuxOSReleasePolicy_NotApplicableOffLinux pins behaviour on non-Linux
// hosts: the policy reports ok=false so the detector falls through. We can
// only assert this directly on non-Linux hosts; on Linux we exercise the
// happy path via the fixture test above.
func TestLinuxOSReleasePolicy_NotApplicableOffLinux(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("Linux hosts hit the happy path; covered by the fixture test")
	}
	_, _, _, ok := NewLinuxOSReleasePolicy().Detect()
	assert.False(t, ok)
}

func TestDefaultOSDetector_ProducesContractTriple(t *testing.T) {
	osType, osName, osVersion := defaultOSDetector().Detect()
	assert.NotEmpty(t, osType)
	assert.NotEmpty(t, osName)
	assert.NotEmpty(t, osVersion)
}

func TestOrDefault(t *testing.T) {
	assert.Equal(t, "fallback", orDefault("", "fallback"))
	assert.Equal(t, "value", orDefault("value", "fallback"))
}
