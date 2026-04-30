package driver

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const sampleSiPolicyXML = `<?xml version="1.0" encoding="utf-8"?>
<SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy">
  <FileRules>
    <Deny ID="ID_DENY_RWDRV_SHA256"
          FriendlyName="rwdrv.sys SHA256"
          Hash="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"/>
    <Deny ID="ID_DENY_RWDRV_SHA1"
          FriendlyName="rwdrv.sys SHA1"
          Hash="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"/>
    <Deny ID="ID_DENY_FILENAME"
          FriendlyName="mhyprot.sys"
          FileName="mhyprot.sys"
          MinimumFileVersion="1.0.0.0"/>
  </FileRules>
</SiPolicy>`

func TestParseMSFTBlocklistXML_Sample(t *testing.T) {
	t.Parallel()
	bl, err := ParseMSFTBlocklistXML([]byte(sampleSiPolicyXML))
	require.NoError(t, err)
	assert.GreaterOrEqual(t, bl.Size(), 3)
}

func TestMSFTBlocklist_MatchBySHA256(t *testing.T) {
	t.Parallel()
	bl, err := ParseMSFTBlocklistXML([]byte(sampleSiPolicyXML))
	require.NoError(t, err)
	r := bl.Match(LoadedDriver{
		OnDiskSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	})
	require.NotNil(t, r)
	assert.Equal(t, "ID_DENY_RWDRV_SHA256", r.ID)
}

func TestMSFTBlocklist_MatchByAuthentihashFallsBackToSHA256(t *testing.T) {
	t.Parallel()
	bl, err := ParseMSFTBlocklistXML([]byte(sampleSiPolicyXML))
	require.NoError(t, err)
	// Same hash listed under both SHA-256 maps for ambiguity-safe matching.
	r := bl.Match(LoadedDriver{
		Authentihash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	})
	require.NotNil(t, r)
}

func TestMSFTBlocklist_MatchByFilename(t *testing.T) {
	t.Parallel()
	bl, err := ParseMSFTBlocklistXML([]byte(sampleSiPolicyXML))
	require.NoError(t, err)
	r := bl.Match(LoadedDriver{
		Path: "C:\\Windows\\System32\\drivers\\mhyprot.sys",
	})
	require.NotNil(t, r)
	assert.Equal(t, "ID_DENY_FILENAME", r.ID)
}

func TestMSFTBlocklist_MatchByDriverName(t *testing.T) {
	t.Parallel()
	bl, err := ParseMSFTBlocklistXML([]byte(sampleSiPolicyXML))
	require.NoError(t, err)
	r := bl.Match(LoadedDriver{Name: "mhyprot.sys"})
	require.NotNil(t, r)
}

func TestMSFTBlocklist_NoMatchOnEmpty(t *testing.T) {
	t.Parallel()
	bl, err := ParseMSFTBlocklistXML([]byte(sampleSiPolicyXML))
	require.NoError(t, err)
	assert.Nil(t, bl.Match(LoadedDriver{}))
}

func TestLoadMSFTBlocklistFromFile(t *testing.T) {
	t.Parallel()
	tmp := filepath.Join(t.TempDir(), "policy.xml")
	require.NoError(t, os.WriteFile(tmp, []byte(sampleSiPolicyXML), 0o600))
	bl, err := LoadMSFTBlocklistFromFile(tmp)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, bl.Size(), 3)
}

func TestLoadMSFTBlocklistFromFile_Missing(t *testing.T) {
	t.Parallel()
	_, err := LoadMSFTBlocklistFromFile(filepath.Join(t.TempDir(), "nope.xml"))
	require.Error(t, err)
}

func TestParseMSFTBlocklistXML_BadInput(t *testing.T) {
	t.Parallel()
	_, err := ParseMSFTBlocklistXML([]byte("<not-xml"))
	require.Error(t, err)
}
