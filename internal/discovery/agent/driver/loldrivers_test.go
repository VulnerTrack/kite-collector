package driver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const sampleLOLDriversJSON = `[
	{
		"Id": "id-1",
		"Category": "vulnerable driver",
		"Verified": "TRUE",
		"Tags": ["EDR-Bypass"],
		"KnownVulnerableSamples_CVE": ["CVE-2022-31246"],
		"MitreID": ["T1068"],
		"KnownVulnerableSamples": [
			{
				"Filename": "rwdrv.sys",
				"MD5": "111",
				"SHA1": "222",
				"SHA256": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
				"Authentihash": "abcdef0123",
				"ImportedHash": "12345IMPHASH",
				"Description": "Vulnerable driver",
				"Company": "Some Vendor"
			}
		],
		"OriginalFilename": [{ "Filename": "rwdrv.sys", "Sha256": "AA..." }]
	},
	{
		"Id": "id-2",
		"Category": "vulnerable driver",
		"Verified": "FALSE",
		"KnownVulnerableSamples": [
			{
				"Filename": "mhyprot.sys",
				"SHA256": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
			}
		]
	}
]`

func TestParseLOLDriversJSON_Sample(t *testing.T) {
	t.Parallel()
	entries, err := ParseLOLDriversJSON([]byte(sampleLOLDriversJSON))
	require.NoError(t, err)
	require.Len(t, entries, 2)
	assert.Equal(t, "id-1", entries[0].ID)
	assert.Equal(t, []string{"CVE-2022-31246"}, entries[0].KnownVulnIDs)
}

func TestLOLDriversIndex_MatchBySHA256(t *testing.T) {
	t.Parallel()
	entries, err := ParseLOLDriversJSON([]byte(sampleLOLDriversJSON))
	require.NoError(t, err)
	idx := NewLOLDriversIndex(entries)

	hit := idx.Match(LoadedDriver{
		OnDiskSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	})
	require.NotNil(t, hit)
	assert.Equal(t, "id-1", hit.ID)
}

func TestLOLDriversIndex_MatchByAuthentihash(t *testing.T) {
	t.Parallel()
	entries, err := ParseLOLDriversJSON([]byte(sampleLOLDriversJSON))
	require.NoError(t, err)
	idx := NewLOLDriversIndex(entries)

	hit := idx.Match(LoadedDriver{Authentihash: "ABCDEF0123"})
	require.NotNil(t, hit)
	assert.Equal(t, "id-1", hit.ID)
}

func TestLOLDriversIndex_MatchByImportHash(t *testing.T) {
	t.Parallel()
	entries, err := ParseLOLDriversJSON([]byte(sampleLOLDriversJSON))
	require.NoError(t, err)
	idx := NewLOLDriversIndex(entries)

	hit := idx.Match(LoadedDriver{ImportHash: "12345imphash"})
	require.NotNil(t, hit)
	assert.Equal(t, "id-1", hit.ID)
}

func TestLOLDriversIndex_MatchByFilenameFallback(t *testing.T) {
	t.Parallel()
	entries, err := ParseLOLDriversJSON([]byte(sampleLOLDriversJSON))
	require.NoError(t, err)
	idx := NewLOLDriversIndex(entries)

	hit := idx.Match(LoadedDriver{Path: "C:\\Windows\\System32\\drivers\\rwdrv.sys"})
	require.NotNil(t, hit)
	assert.Equal(t, "id-1", hit.ID)
}

func TestLOLDriversIndex_NoMatch(t *testing.T) {
	t.Parallel()
	entries, err := ParseLOLDriversJSON([]byte(sampleLOLDriversJSON))
	require.NoError(t, err)
	idx := NewLOLDriversIndex(entries)

	hit := idx.Match(LoadedDriver{Name: "innocent.ko", OnDiskSHA256: "ffff"})
	assert.Nil(t, hit)
}

func TestLOLDriversIndex_Size(t *testing.T) {
	t.Parallel()
	entries, err := ParseLOLDriversJSON([]byte(sampleLOLDriversJSON))
	require.NoError(t, err)
	idx := NewLOLDriversIndex(entries)
	assert.Equal(t, 2, idx.Size())
}

func TestLoadLOLDriversFromFile(t *testing.T) {
	t.Parallel()
	tmp := filepath.Join(t.TempDir(), "drivers.json")
	require.NoError(t, os.WriteFile(tmp, []byte(sampleLOLDriversJSON), 0o600))
	entries, err := LoadLOLDriversFromFile(tmp)
	require.NoError(t, err)
	require.Len(t, entries, 2)
}

func TestLoadLOLDriversFromFile_Missing(t *testing.T) {
	t.Parallel()
	_, err := LoadLOLDriversFromFile(filepath.Join(t.TempDir(), "nope.json"))
	require.Error(t, err)
}

func TestLOLDriversLoader_Load_HTTPError(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	loader := &LOLDriversLoader{
		HTTP:    &http.Client{Timeout: 2 * time.Second},
		FeedURL: srv.URL + "/drivers.json",
		MaxSize: 1 << 20,
	}
	_, err := loader.Load(context.Background())
	require.Error(t, err)
}

func TestLOLDriversLoader_Load_OK(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(sampleLOLDriversJSON))
	}))
	t.Cleanup(srv.Close)

	loader := &LOLDriversLoader{
		HTTP:    &http.Client{Timeout: 2 * time.Second},
		FeedURL: srv.URL + "/drivers.json",
		MaxSize: 1 << 20,
	}
	entries, err := loader.Load(context.Background())
	require.NoError(t, err)
	require.Len(t, entries, 2)
}

func TestFilepathBaseSafe_Cases(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "rwdrv.sys", filepathBaseSafe("C:\\Windows\\System32\\drivers\\rwdrv.sys"))
	assert.Equal(t, "rwdrv.sys", filepathBaseSafe("/lib/modules/6.1/rwdrv.sys"))
	assert.Equal(t, "rwdrv.sys", filepathBaseSafe("rwdrv.sys"))
}
