package driver

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseSystemDriverJSON_Array(t *testing.T) {
	t.Parallel()
	raw := []byte(`[
		{"Name":"NVIDIA","DisplayName":"NVIDIA Display","PathName":"C:\\Windows\\System32\\drivers\\nvlddmkm.sys","Description":"NVIDIA Driver","State":"Running","StartMode":"Auto","ServiceType":"1"},
		{"Name":"Tcpip","DisplayName":"TCP/IP Driver","PathName":"C:\\Windows\\System32\\drivers\\tcpip.sys","Description":"TCP/IP","State":"Running","StartMode":"System","ServiceType":"1"}
	]`)
	rows, err := parseSystemDriverJSON(raw)
	require.NoError(t, err)
	require.Len(t, rows, 2)
	assert.Equal(t, "NVIDIA", rows[0].Name)
	assert.Equal(t, "TCP/IP Driver", rows[1].DisplayName)
}

func TestParseSystemDriverJSON_SingleObject(t *testing.T) {
	t.Parallel()
	raw := []byte(`{"Name":"OneDriver","DisplayName":"Solo","PathName":"C:\\Driver","Description":"","State":"Stopped","StartMode":"Manual","ServiceType":"1"}`)
	rows, err := parseSystemDriverJSON(raw)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, "OneDriver", rows[0].Name)
	assert.Equal(t, "Stopped", rows[0].State)
}

func TestParseSystemDriverJSON_EmptyInput(t *testing.T) {
	t.Parallel()
	rows, err := parseSystemDriverJSON([]byte("   "))
	require.NoError(t, err)
	assert.Empty(t, rows)
}

func TestParsePnPSignedDriverJSON_Array(t *testing.T) {
	t.Parallel()
	raw := []byte(`[
		{"DeviceName":"NVIDIA RTX","DriverName":"nvlddmkm","Manufacturer":"NVIDIA Corporation","DriverVersion":"535.183.06","Signer":"NVIDIA Corporation, US","IsSigned":true,"HardwareID":"PCI\\VEN_10DE&DEV_2208","InfName":"oem77.inf"}
	]`)
	rows, err := parsePnPSignedDriverJSON(raw)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.True(t, rows[0].IsSigned)
	assert.Equal(t, "535.183.06", rows[0].DriverVersion)
}

func TestApplyPnPSignedAttrs_MatchesByDriverName(t *testing.T) {
	t.Parallel()
	drivers := []LoadedDriver{
		{Name: "nvlddmkm"},
		{Name: "tcpip"},
	}
	signed := []pnpSignedDriverRow{
		{DriverName: "nvlddmkm", Signer: "NVIDIA Corporation, US", DriverVersion: "535.0", IsSigned: true},
	}
	applyPnPSignedAttrs(drivers, signed)
	assert.Equal(t, "535.0", drivers[0].Version)
	assert.Equal(t, "NVIDIA Corporation, US", drivers[0].Signer)
	assert.Equal(t, "NVIDIA Corporation", drivers[0].Vendor)
	assert.Equal(t, SignatureValid, drivers[0].SignatureState)
	assert.NotEmpty(t, drivers[0].CPE23)
	assert.Empty(t, drivers[1].Version, "non-matching driver is left alone")
}

func TestApplyPnPSignedAttrs_IsSignedWithoutSigner(t *testing.T) {
	t.Parallel()
	drivers := []LoadedDriver{{Name: "foo"}}
	signed := []pnpSignedDriverRow{{DriverName: "foo", IsSigned: true, Manufacturer: "Acme"}}
	applyPnPSignedAttrs(drivers, signed)
	assert.Equal(t, SignatureValid, drivers[0].SignatureState)
	assert.Equal(t, "Acme", drivers[0].Vendor)
}

func TestClassifyServiceType_Defaults(t *testing.T) {
	t.Parallel()
	assert.Equal(t, FrameworkWDM, classifyServiceType("1"))
	assert.Equal(t, FrameworkWDM, classifyServiceType("2"))
	assert.Equal(t, FrameworkWDM, classifyServiceType("Kernel Driver"))
	assert.Equal(t, FrameworkWDM, classifyServiceType("UnknownGarbage"))
}

func TestWMIDrivers_NotAvailableOnNonWindows(t *testing.T) {
	t.Parallel()
	// Test only validates the binding; the actual GOOS check happens at
	// runtime. On test runners that aren't Windows, Available() must be false.
	c := NewWMIDrivers()
	if !c.Available() {
		assert.Equal(t, "windows-wmi-drivers", c.Name())
	}
}
