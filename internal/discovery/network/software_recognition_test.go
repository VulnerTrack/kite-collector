package network

import (
	"context"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/discovery/network/apifingerprint"
	"github.com/vulnertrack/kite-collector/internal/discovery/network/compositefingerprint"
	"github.com/vulnertrack/kite-collector/internal/discovery/network/headerfingerprint"
	"github.com/vulnertrack/kite-collector/internal/discovery/network/servicefp"
)

func TestServiceSoftware_MapsBannerToProductVersion(t *testing.T) {
	results := map[int]servicefp.Result{
		3306: {Protocol: "mysql", Version: "8.4.3"},
		6379: {Protocol: "redis", Version: "7.2.4"},
		443:  {Protocol: "http", TLS: true}, // web protocol: skipped here
		80:   {Protocol: "http"},            // web protocol: skipped here
	}
	sw := serviceSoftware(results)
	require.Len(t, sw, 2, "only the non-web services become software rows")

	byName := map[string]int{}
	for i, s := range sw {
		byName[s.SoftwareName] = i
	}

	mysql := sw[byName["MySQL"]]
	assert.Equal(t, "8.4.3", mysql.Version, "MySQL version comes straight off the handshake banner")
	assert.Equal(t, "Oracle", mysql.Vendor)
	assert.Equal(t, pkgMgrNetworkService, mysql.PackageManager)
	assert.Equal(t, "tcp/3306", mysql.InstallPath, "install path records the listening port")
	assert.NotEqual(t, mysql.ID.String(), "00000000-0000-0000-0000-000000000000", "rows get a UUID")

	redis := sw[byName["Redis"]]
	assert.Equal(t, "7.2.4", redis.Version)
}

func TestServiceSoftware_EmptyIsNil(t *testing.T) {
	assert.Nil(t, serviceSoftware(nil))
	assert.Nil(t, serviceSoftware(map[int]servicefp.Result{80: {Protocol: "http"}}),
		"a host with only web services yields no service-software rows")
}

func TestWebSoftwareFromResult_DedupesAcrossSurfacesAndLiftsVersion(t *testing.T) {
	res := compositefingerprint.CompositeResult{
		Endpoint: "https://shop.example:443",
		Header: &headerfingerprint.Result{
			Fingerprints: []headerfingerprint.Fingerprint{
				{Vendor: "Laravel", Product: "Laravel (PHP)", Confidence: headerfingerprint.ConfidenceLow, Evidence: []string{"cookie:XSRF-TOKEN"}},
			},
		},
		API: &apifingerprint.Result{
			Fingerprints: []apifingerprint.Fingerprint{
				// Same product from a second surface, stronger confidence.
				{Vendor: "Laravel", Product: "Laravel (PHP)", Confidence: apifingerprint.ConfidenceHigh, Evidence: []string{"x-ratelimit-limit"}},
				// A JS lib whose version leaks in a CDN URL.
				{Vendor: "Bootstrap Core Team", Product: "Bootstrap", Confidence: apifingerprint.ConfidenceHigh, Evidence: []string{"script-src: maxcdn.bootstrapcdn.com/bootstrap/3.4.1/css/bootstrap.min.css"}},
			},
		},
	}
	sw := webSoftwareFromResult(res)
	require.Len(t, sw, 2, "Laravel from two surfaces collapses to one row")

	byName := map[string]int{}
	for i, s := range sw {
		byName[s.SoftwareName] = i
	}
	laravel := sw[byName["Laravel (PHP)"]]
	assert.Equal(t, "Laravel", laravel.Vendor)
	assert.Equal(t, pkgMgrNetworkFingerprint, laravel.PackageManager)

	boot := sw[byName["Bootstrap"]]
	assert.Equal(t, "3.4.1", boot.Version, "version is lifted from the CDN URL evidence")
}

func TestExtractVersion(t *testing.T) {
	assert.Equal(t, "3.4.1", extractVersion([]string{"bootstrap/3.4.1/css"}))
	assert.Equal(t, "8.0", extractVersion([]string{"MySQL 8.0 community"}))
	assert.Equal(t, "", extractVersion([]string{"no version here"}))
	assert.Equal(t, "", extractVersion(nil))
}

func TestServiceProduct(t *testing.T) {
	p, v := serviceProduct("mysql")
	assert.Equal(t, "MySQL", p)
	assert.Equal(t, "Oracle", v)

	p, v = serviceProduct("unknown-thing")
	assert.Equal(t, "unknown-thing", p, "unmapped protocols fall back to the protocol id")
	assert.Equal(t, "", v)
}

func TestDedupeSoftware(t *testing.T) {
	in := serviceSoftware(map[int]servicefp.Result{
		3306: {Protocol: "mysql", Version: "8.4.3"},
	})
	// Duplicate the same logical row.
	in = append(in, in[0])
	out := dedupeSoftware(in)
	assert.Len(t, out, 1, "identical (name,version,pkg,path) rows collapse")
}

func TestTLSNameRejected(t *testing.T) {
	rejected := compositefingerprint.CompositeResult{
		Errors: []compositefingerprint.MechanismError{
			{Mechanism: "tls", Message: "tls handshake: remote error: tls: unrecognized name"},
		},
	}
	assert.True(t, tlsNameRejected(rejected))

	clean := compositefingerprint.CompositeResult{
		Errors: []compositefingerprint.MechanismError{
			{Mechanism: "header", Message: "context deadline exceeded"},
		},
	}
	assert.False(t, tlsNameRejected(clean))
}

func TestVHostCandidates_ConfiguredWinAndCap(t *testing.T) {
	configured := []string{
		"a.example.com", "b.example.com", "c.example.com",
		"d.example.com", "e.example.com", "f.example.com",
		"g.example.com", // 7th — beyond the cap
		"*.wild.example.com", "has/slash", "",
	}
	// TEST-NET-1 (RFC 5737): guaranteed to have no useful PTR, so the
	// reverse lookup contributes nothing and the test stays hermetic.
	ip := netip.MustParseAddr("192.0.2.1")
	got := vhostCandidates(context.Background(), ip, configured, compositefingerprint.CompositeResult{})

	assert.LessOrEqual(t, len(got), maxVHostCandidates, "candidate list is capped")
	assert.Contains(t, got, "a.example.com")
	for _, name := range got {
		assert.NotContains(t, name, "*", "wildcards are dropped")
		assert.NotContains(t, name, "/", "path-like values are dropped")
		assert.NotEmpty(t, name)
	}
}
