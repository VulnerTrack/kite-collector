package software

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/discovery/agent/windowssoftware"
)

func TestWindowsProgramsToSoftwareIncludesChromeAndPerUserApps(t *testing.T) {
	result := WindowsProgramsToSoftware([]windowssoftware.Program{
		{
			DisplayName:     "Google Chrome",
			DisplayVersion:  "128.0.6613.120",
			Publisher:       "Google LLC",
			InstallLocation: `C:\Program Files\Google\Chrome\Application`,
			Source:          windowssoftware.SourceRegistryHKLM,
		},
		{
			DisplayName:    "Discord",
			DisplayVersion: "1.0.9164",
			Publisher:      "Discord Inc.",
			Source:         windowssoftware.SourceRegistryHKCU,
			IsPerUser:      true,
		},
	})

	require.Len(t, result.Items, 2)
	chrome := result.Items[1]
	assert.Equal(t, "Google Chrome", chrome.SoftwareName)
	assert.Equal(t, "Google LLC", chrome.Vendor)
	assert.Equal(t, `C:\Program Files\Google\Chrome\Application`, chrome.InstallPath)
	assert.Equal(t, "registry-hklm", chrome.PackageManager)
	assert.NotEmpty(t, chrome.CPE23)

	discord := result.Items[0]
	assert.Contains(t, discord.Description, "per-user")
}

func TestWindowsProgramsToSoftwareKeepsNamedSystemComponentsAndSkipsNamelessStubs(t *testing.T) {
	result := WindowsProgramsToSoftware([]windowssoftware.Program{
		{ProductID: "nameless-stub", Source: windowssoftware.SourceRegistryHKLM},
		{
			DisplayName:       "Microsoft Edge WebView2 Runtime",
			Source:            windowssoftware.SourceRegistryHKLMWow64,
			IsSystemComponent: true,
		},
	})

	require.Len(t, result.Items, 1)
	assert.Equal(t, "x86", result.Items[0].Architecture)
	assert.Contains(t, result.Items[0].Description, "system component")
}
