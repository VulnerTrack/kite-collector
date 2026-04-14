package osutil

import (
	"os"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEnvSetCommand_Unix(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix-only test")
	}
	got := EnvSetCommand("KITE_WAZUH_ENDPOINT", "https://localhost:55000")
	assert.Equal(t, `export KITE_WAZUH_ENDPOINT=https://localhost:55000`, got)
}

func TestPathSeparator(t *testing.T) {
	got := PathSeparator()
	switch runtime.GOOS {
	case "windows":
		assert.Equal(t, `\`, got)
	default:
		assert.Equal(t, "/", got)
	}
}

func TestConfigDir_NonEmpty(t *testing.T) {
	dir := ConfigDir()
	assert.NotEmpty(t, dir, "ConfigDir should return a non-empty path")
}

func TestShellName_NonEmpty(t *testing.T) {
	name := ShellName()
	assert.NotEmpty(t, name)
}

func TestIsPowerShell(t *testing.T) {
	// Clear PSModulePath to test the false path — GitHub Actions
	// Ubuntu runners have pwsh installed which sets this variable.
	_ = os.Unsetenv("PSModulePath")
	assert.False(t, IsPowerShell())

	// Set it to test the true path.
	t.Setenv("PSModulePath", "/opt/microsoft/powershell/Modules")
	assert.True(t, IsPowerShell())
}
