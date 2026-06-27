package driver

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParsePnPUtilCSV_RealishOutput(t *testing.T) {
	t.Parallel()
	raw := "Published Name,Original Name,Provider Name,Class Name,Class GUID,Driver Version,Signer Name\n" +
		"oem77.inf,nv_dispi.inf,NVIDIA,Display adapters,{4d36e968-e325-11ce-bfc1-08002be10318},535.183.06,Microsoft Windows Hardware Compatibility Publisher\n" +
		"oem89.inf,wpdmtp.inf,Microsoft,Portable Devices,{eec5ad98-8080-425f-922a-dabf3de3f69a},10.0.19041.1,Microsoft Windows\n"
	rows, errs := ParsePnPUtilCSV(raw)
	require.Empty(t, errs)
	require.Len(t, rows, 2)

	assert.Equal(t, "oem77.inf", rows[0].PublishedName)
	assert.Equal(t, "nv_dispi.inf", rows[0].OriginalName)
	assert.Equal(t, "NVIDIA", rows[0].Provider)
	assert.Equal(t, "535.183.06", rows[0].Version)
	assert.Equal(t, "Microsoft Windows Hardware Compatibility Publisher", rows[0].Signer)
}

func TestParsePnPUtilCSV_MissingHeader(t *testing.T) {
	t.Parallel()
	raw := "Published Name,Provider Name\n" +
		"oem77.inf,NVIDIA\n"
	rows, errs := ParsePnPUtilCSV(raw)
	require.Empty(t, errs)
	require.Len(t, rows, 1)
	assert.Equal(t, "oem77.inf", rows[0].PublishedName)
	assert.Equal(t, "NVIDIA", rows[0].Provider)
	assert.Empty(t, rows[0].Version, "absent column yields empty string, not error")
}

func TestParsePnPUtilCSV_EmptyInput(t *testing.T) {
	t.Parallel()
	rows, errs := ParsePnPUtilCSV("")
	assert.Empty(t, rows)
	assert.Empty(t, errs)
}

func TestSignatureStateFromPnPUtil_NoSignerIsUnknown(t *testing.T) {
	t.Parallel()
	assert.Equal(t, SignatureUnknown, signatureStateFromPnPUtil(PnPUtilRow{}))
	assert.Equal(t, SignatureValid, signatureStateFromPnPUtil(PnPUtilRow{Signer: "Microsoft Windows"}))
	assert.Equal(t, SignatureValid, signatureStateFromPnPUtil(PnPUtilRow{Signer: "Microsoft Windows Hardware Compatibility Publisher"}))
}

func TestPnPUtilDrivers_Name(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "windows-pnputil", NewPnPUtilDrivers().Name())
}
