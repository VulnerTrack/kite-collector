package network

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseComposerLock_ExtractsLaravelVersion(t *testing.T) {
	body := []byte(`{
	  "packages": [
	    {"name": "laravel/framework", "version": "v11.9.2"},
	    {"name": "guzzlehttp/guzzle", "version": "7.8.1"}
	  ],
	  "packages-dev": [
	    {"name": "phpunit/phpunit", "version": "10.5.20"}
	  ]
	}`)
	rows := parseComposerLock(body)
	require.Len(t, rows, 3)

	byName := map[string]string{}
	vendor := map[string]string{}
	for _, r := range rows {
		byName[r.SoftwareName] = r.Version
		vendor[r.SoftwareName] = r.Vendor
		assert.Equal(t, pkgMgrComposer, r.PackageManager)
	}
	assert.Equal(t, "11.9.2", byName["laravel/framework"], "the 'v' prefix is stripped")
	assert.Equal(t, "laravel", vendor["laravel/framework"], "vendor split from vendor/name")
	assert.Equal(t, "7.8.1", byName["guzzlehttp/guzzle"])
	assert.Equal(t, "10.5.20", byName["phpunit/phpunit"], "dev packages are included")
}

func TestParseComposerJSON_ConstraintsAndPlatformSkip(t *testing.T) {
	body := []byte(`{
	  "require": {"php": "^8.2", "laravel/framework": "^11.0", "ext-json": "*"},
	  "require-dev": {"nunomaduro/collision": "^8.0"}
	}`)
	rows := parseComposerJSON(body)
	names := map[string]string{}
	for _, r := range rows {
		names[r.SoftwareName] = r.Version
	}
	assert.Equal(t, "^11.0", names["laravel/framework"], "constraint preserved as version")
	assert.NotContains(t, names, "php", "platform requirement skipped")
	assert.NotContains(t, names, "ext-json", "extension requirement skipped")
	assert.Contains(t, names, "nunomaduro/collision")
}

func TestParseInstalledJSON_ModernAndLegacy(t *testing.T) {
	modern := parseInstalledJSON([]byte(`{"packages":[{"name":"laravel/framework","version":"v10.48.4"}]}`))
	require.Len(t, modern, 1)
	assert.Equal(t, "10.48.4", modern[0].Version)

	legacy := parseInstalledJSON([]byte(`[{"name":"symfony/console","version":"v6.4.0"}]`))
	require.Len(t, legacy, 1)
	assert.Equal(t, "6.4.0", legacy[0].Version)
}

func TestParsePackageLock_V2AndV1(t *testing.T) {
	v2 := parsePackageLock([]byte(`{
	  "lockfileVersion": 3,
	  "packages": {
	    "": {"name": "app", "version": "1.0.0"},
	    "node_modules/react": {"version": "18.3.1"},
	    "node_modules/@inertiajs/core": {"version": "1.0.14"}
	  }
	}`))
	byName := map[string]string{}
	for _, r := range v2 {
		byName[r.SoftwareName] = r.Version
		assert.Equal(t, pkgMgrNPM, r.PackageManager)
	}
	assert.Equal(t, "18.3.1", byName["react"], "node_modules/ prefix stripped")
	assert.Equal(t, "1.0.14", byName["@inertiajs/core"])
	assert.NotContains(t, byName, "", "the root project entry is skipped")

	v1 := parsePackageLock([]byte(`{"dependencies":{"vue":{"version":"3.4.21"}}}`))
	require.Len(t, v1, 1)
	assert.Equal(t, "3.4.21", v1[0].Version)
}

func TestFetchManifest_RejectsHTMLAnd404(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/composer.lock", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"packages":[{"name":"laravel/framework","version":"v11.31.0"}]}`))
	})
	mux.HandleFunc("/composer.json", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`<!DOCTYPE html><html>404 styled page</html>`))
	})
	mux.HandleFunc("/package.json", func(w http.ResponseWriter, _ *http.Request) {
		// A 200 that returns the SPA index HTML must NOT be parsed as JSON.
		_, _ = w.Write([]byte(`<!DOCTYPE html><html><div id="app"></div></html>`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := srv.Client()
	// composer.lock: 200 JSON -> parsed.
	body, ok := fetchManifest(context.Background(), client, srv.URL+"/composer.lock", 3*time.Second)
	require.True(t, ok)
	assert.Contains(t, string(body), "laravel/framework")
	// composer.json: 404 -> rejected.
	_, ok = fetchManifest(context.Background(), client, srv.URL+"/composer.json", 3*time.Second)
	assert.False(t, ok, "404 is not a disclosure")
	// package.json: 200 HTML -> rejected by the JSON-shape guard.
	_, ok = fetchManifest(context.Background(), client, srv.URL+"/package.json", 3*time.Second)
	assert.False(t, ok, "a 200 HTML catch-all is not a manifest")
}

func TestProbeVersionDisclosure_EndToEnd(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/composer.lock", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"packages":[{"name":"laravel/framework","version":"v11.31.0"},{"name":"laravel/sanctum","version":"v4.0.2"}]}`))
	})
	// composer.json present too, but must be skipped once the lock produced rows.
	mux.HandleFunc("/composer.json", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"require":{"laravel/framework":"^11.0"}}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	u, err := url.Parse(srv.URL)
	require.NoError(t, err)
	port, err := strconv.Atoi(u.Port())
	require.NoError(t, err)

	rows := probeVersionDisclosure(context.Background(), srv.Client(), "http", u.Hostname(), port, 3*time.Second)
	byName := map[string]string{}
	for _, r := range rows {
		byName[r.SoftwareName] = r.Version
		assert.Contains(t, r.InstallPath, "/composer.lock", "rows are attributed to the disclosing URL")
	}
	assert.Equal(t, "11.31.0", byName["laravel/framework"], "exact version from the lockfile")
	assert.Equal(t, "4.0.2", byName["laravel/sanctum"])
	// The looser composer.json constraint must not appear once the lock won.
	for _, r := range rows {
		assert.NotEqual(t, "^11.0", r.Version, "constraint manifest skipped when lock is present")
	}
}
