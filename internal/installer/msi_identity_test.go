package installer

import (
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// isolateInstallRoots pins the allow-listed install roots to one known value so
// the assertions do not depend on whatever the CI runner happens to export.
func isolateInstallRoots(t *testing.T, programFiles string) {
	t.Helper()
	for _, name := range installDirAllowRootVars {
		t.Setenv(name, "")
	}
	t.Setenv("ProgramFiles", programFiles)
}

// TestPackMSIGUID_KnownUpgradeCode pins the exact registry key name the R7
// pre-flight check opens. The transform has no partial-credit failure mode: a
// single mis-swapped nibble produces a key that simply does not exist, the
// lookup reports "no prior install", and the installer silently lays down the
// duplicate tree R7 exists to prevent. Hard-coding the expected value is the
// only way to catch that on a Linux CI with no registry.
func TestPackMSIGUID_KnownUpgradeCode(t *testing.T) {
	packed, err := packMSIGUID(MSIUpgradeCode)
	require.NoError(t, err)
	assert.Equal(t, "3D449B91B39402A459D2FDC1B6E0F23E", packed)
}

func TestPackMSIGUID_AcceptsBracedAndMixedCase(t *testing.T) {
	bare, err := packMSIGUID(MSIUpgradeCode)
	require.NoError(t, err)

	braced, err := packMSIGUID("{19B944D3-493B-4A20-952D-DF1C6B0E2FE3}")
	require.NoError(t, err)

	assert.Equal(t, bare, braced,
		"braces and case must not change the packed form")
}

func TestUnpackMSIGUID_RoundTrips(t *testing.T) {
	packed, err := packMSIGUID(MSIUpgradeCode)
	require.NoError(t, err)

	unpacked, err := unpackMSIGUID(packed)
	require.NoError(t, err)
	assert.Equal(t, "{19B944D3-493B-4A20-952D-DF1C6B0E2FE3}", unpacked)
}

func TestPackMSIGUID_RejectsMalformed(t *testing.T) {
	for _, bad := range []string{
		"",
		"19b944d3-493b-4a20-952d",
		"19b944d3-493b-4a20-952d-df1c6b0e2fe3aa",
		"19b944d3-493b-4a20-952d-df1c6b0e2fzz",
	} {
		_, err := packMSIGUID(bad)
		assert.Error(t, err, "packMSIGUID(%q) must be rejected", bad)
	}
}

func TestPriorInstall_PreflightResult(t *testing.T) {
	assert.Equal(t, PreflightFreshInstall, PriorInstall{}.PreflightResult())
	assert.Equal(t, PreflightUpgradeFromMSI,
		PriorInstall{Kind: PriorInstallMSI}.PreflightResult())
	assert.Equal(t, PreflightUpgradeFromSelfContained,
		PriorInstall{Kind: PriorInstallSelfContained}.PreflightResult())
	assert.False(t, PriorInstall{}.Found())
	assert.True(t, PriorInstall{Kind: PriorInstallMSI}.Found())
}

// TestValidateInstallDir_RejectsTraversal is the security-relevant case: /DIR=
// reaches an elevated process that writes an executable and points a
// LocalSystem service at it, so a path escaping the allow-listed roots is a
// privilege-escalation primitive.
func TestValidateInstallDir_RejectsTraversal(t *testing.T) {
	root := t.TempDir()
	isolateInstallRoots(t, root)

	require.NoError(t, ValidateInstallDir(filepath.Join(root, "Kite Collector")))
	require.NoError(t, ValidateInstallDir(filepath.Join(root, "a", "b")))

	assert.Error(t, ValidateInstallDir(""),
		"empty must be rejected")
	assert.Error(t, ValidateInstallDir("relative/path"),
		"relative paths must be rejected")
	assert.Error(t, ValidateInstallDir(root),
		"the root itself is not a valid install directory")
	assert.Error(t, ValidateInstallDir(filepath.Join(root, "..", "escaped")),
		"traversal out of the root must be rejected after cleaning")
}

func TestValidateInstallDir_NoRootsConfigured(t *testing.T) {
	for _, name := range installDirAllowRootVars {
		t.Setenv(name, "")
	}
	assert.Error(t, ValidateInstallDir("/anywhere"),
		"with no allow-listed root there is nothing to validate against")
}

func TestResolveInstallDir_AdoptsExistingPriorTree(t *testing.T) {
	prior := t.TempDir()
	opts := Options{BinaryDir: filepath.Join(t.TempDir(), "kite-collector")}

	assert.Equal(t, opts.BinaryDir,
		ResolveInstallDir(opts, PriorInstall{}),
		"a fresh install keeps the smart default")

	assert.Equal(t, filepath.Clean(prior),
		ResolveInstallDir(opts, PriorInstall{
			Kind:            PriorInstallMSI,
			InstallLocation: prior,
		}),
		"an existing prior tree is upgraded in place")

	assert.Equal(t, opts.BinaryDir,
		ResolveInstallDir(opts, PriorInstall{
			Kind:            PriorInstallMSI,
			InstallLocation: filepath.Join(prior, "does-not-exist"),
		}),
		"a recorded location that no longer exists is not adopted")

	userOpts := opts
	userOpts.UserMode = true
	assert.Equal(t, userOpts.BinaryDir,
		ResolveInstallDir(userOpts, PriorInstall{
			Kind:            PriorInstallMSI,
			InstallLocation: prior,
		}),
		"a per-user install never adopts a machine-wide MSI tree")
}

func TestMSIDefaultInstallDir_WindowsOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		assert.NotEmpty(t, MSIDefaultInstallDir())
		return
	}
	assert.Empty(t, MSIDefaultInstallDir(),
		"there is no %ProgramFiles% to fall back to off Windows")
}
