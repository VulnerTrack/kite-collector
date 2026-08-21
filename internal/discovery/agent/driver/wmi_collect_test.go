package driver

import (
	"context"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/discovery/agent/software"
)

// fakePowershellScript answers the two WMI queries Collect issues, keyed on
// the CIM class name inside the -Command payload, with realistic
// ConvertTo-Json -Compress output.
const fakePowershellScript = `case "$*" in
  *Win32_PnPSignedDriver*)
    printf '%s' '[{"DeviceName":"Intel(R) Ethernet","DriverName":"e1dexpress","Manufacturer":"Intel","DriverVersion":"12.18.9.23","Signer":"Microsoft Windows Hardware Compatibility Publisher","IsSigned":true,"HardwareID":"PCI\\VEN_8086","InfName":"e1d68x64.inf"}]'
    ;;
  *Win32_SystemDriver*)
    printf '%s' '[{"Name":"e1dexpress","DisplayName":"Intel(R) PRO/1000 PCI Express","PathName":"C:\\Windows\\system32\\drivers\\e1d68x64.sys","Description":"Intel Ethernet driver","State":"Running","StartMode":"Manual","ServiceType":"Kernel Driver"},{"Name":"npfs","DisplayName":"Named Pipe File System","PathName":"","Description":"NPFS","State":"Running","StartMode":"System","ServiceType":"File System Driver"}]'
    ;;
  *)
    echo "unexpected query" >&2
    exit 1
    ;;
esac
exit 0
`

func TestWMICollect_HappyPathMergesPnPAttrs(t *testing.T) {
	bin := writeFakeTool(t, "powershell", fakePowershellScript)
	collected := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	w := NewWMIDrivers()
	w.powershellPath = bin
	w.now = func() time.Time { return collected }

	res, err := w.Collect(context.Background())
	require.NoError(t, err)
	require.Len(t, res.Drivers, 2)

	eth := findByName(res.Drivers, "e1dexpress")
	require.NotNil(t, eth)
	assert.Equal(t, "Intel(R) PRO/1000 PCI Express", eth.DisplayName)
	assert.Equal(t, `C:\Windows\system32\drivers\e1d68x64.sys`, eth.Path)
	assert.Equal(t, "Running", eth.State)
	assert.Equal(t, "Manual", eth.StartMode)
	assert.Equal(t, FrameworkWDM, eth.DriverFramework)
	assert.Equal(t, collected, eth.CollectedAt)
	assert.Equal(t, runtime.GOARCH, eth.Architecture)
	// Attributes merged in from the Win32_PnPSignedDriver row:
	assert.Equal(t, "Microsoft Windows Hardware Compatibility Publisher", eth.Signer)
	assert.Equal(t, SignatureValid, eth.SignatureState)
	assert.Equal(t, "12.18.9.23", eth.Version)
	assert.Equal(t, "Microsoft Windows Hardware Compatibility Publisher", eth.Vendor,
		"vendor falls back to the signer's first comma-separated segment")
	assert.Equal(t,
		software.BuildCPE23WithTargetSW(eth.Vendor, "e1dexpress", "12.18.9.23", "windows"),
		eth.CPE23)
	assert.Empty(t, eth.Authentihash, "nonexistent PathName must not produce a hash")

	npfs := findByName(res.Drivers, "npfs")
	require.NotNil(t, npfs)
	assert.Empty(t, npfs.SignatureState, "drivers without a PnP row keep their zero signature state")
	assert.Empty(t, npfs.Signer)
	assert.Empty(t, npfs.Version)
}

func TestWMICollect_PnPQueryFailureIsTolerated(t *testing.T) {
	// The PnP query exits non-zero; Collect must still return the system
	// drivers without signer decoration.
	bin := writeFakeTool(t, "powershell", `case "$*" in
  *Win32_PnPSignedDriver*)
    echo "Get-CimInstance : Access denied" >&2
    exit 1
    ;;
  *Win32_SystemDriver*)
    printf '%s' '{"Name":"npfs","DisplayName":"Named Pipe File System","PathName":"","Description":"NPFS","State":"Running","StartMode":"System","ServiceType":"File System Driver"}'
    ;;
esac
exit 0
`)
	w := NewWMIDrivers()
	w.powershellPath = bin

	res, err := w.Collect(context.Background())
	require.NoError(t, err, "a failing PnP query must not abort collection")
	require.Len(t, res.Drivers, 1, "the single-object JSON quirk must decode to one row")
	assert.Equal(t, "npfs", res.Drivers[0].Name)
	assert.Empty(t, res.Drivers[0].Signer)
}

func TestWMICollect_SystemDriverQueryFailureIsFatal(t *testing.T) {
	bin := writeFakeTool(t, "powershell", `echo "The RPC server is unavailable." >&2
exit 1
`)
	w := NewWMIDrivers()
	w.powershellPath = bin

	res, err := w.Collect(context.Background())
	require.Error(t, err)
	assert.Nil(t, res)
	assert.Contains(t, err.Error(), "Win32_SystemDriver: ")
	assert.Contains(t, err.Error(), "The RPC server is unavailable.")
}

func TestWMICollect_MalformedJSONIsFatal(t *testing.T) {
	bin := writeFakeTool(t, "powershell", `printf '%s' '[{"Name": truncated'
exit 0
`)
	w := NewWMIDrivers()
	w.powershellPath = bin

	res, err := w.Collect(context.Background())
	require.Error(t, err)
	assert.Nil(t, res)
	assert.Contains(t, err.Error(), "unmarshal Win32_SystemDriver array")
}

func TestParsePnPSignedDriverJSON_SingleObject(t *testing.T) {
	t.Parallel()

	rows, err := parsePnPSignedDriverJSON([]byte(`{"DriverName":"solo","Signer":"S","IsSigned":true}`))
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, "solo", rows[0].DriverName)
	assert.Equal(t, "S", rows[0].Signer)
	assert.True(t, rows[0].IsSigned)
}

func TestParsePnPSignedDriverJSON_EmptyInput(t *testing.T) {
	t.Parallel()

	rows, err := parsePnPSignedDriverJSON([]byte("   \n"))
	require.NoError(t, err)
	assert.Nil(t, rows, "whitespace-only output means zero rows, not an error")
}

func TestParsePnPSignedDriverJSON_Malformed(t *testing.T) {
	t.Parallel()

	rows, err := parsePnPSignedDriverJSON([]byte(`[{"DriverName":`))
	require.Error(t, err)
	assert.Nil(t, rows)
	assert.Contains(t, err.Error(), "unmarshal Win32_PnPSignedDriver array")

	rows, err = parsePnPSignedDriverJSON([]byte(`{"DriverName":`))
	require.Error(t, err)
	assert.Nil(t, rows)
	assert.Contains(t, err.Error(), "unmarshal Win32_PnPSignedDriver row")
}
