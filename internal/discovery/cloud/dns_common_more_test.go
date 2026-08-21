package cloud

// dns_common_more_test.go: coverage for the shared cloud/dns helpers —
// dnsSafeClient's production vs test-override branches (using IP-literal URLs
// so endpoint validation never issues a DNS query) and the untyped-config
// coercion helpers.

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDNSSafeClient_TestOverrideKeepsInjectedClient(t *testing.T) {
	existing := &http.Client{Timeout: 5 * time.Second}
	got, err := dnsSafeClient(HardeningSourceRoute53, "http://127.0.0.1:9999", defaultRoute53BaseURL, existing)
	require.NoError(t, err)
	assert.Same(t, existing, got, "an overridden base URL must keep the injected client")
}

func TestDNSSafeClient_ProdDefaultBuildsSafeClient(t *testing.T) {
	// TEST-NET-3 IP literal: resolves locally (no DNS query), is not a
	// private/loopback address, and no connection is ever opened.
	prod := "https://203.0.113.10"
	got, err := dnsSafeClient(HardeningSourceRoute53, prod, prod, nil)
	require.NoError(t, err)
	require.NotNil(t, got)

	client, ok := got.(*http.Client)
	require.True(t, ok, "production path must return a concrete *http.Client")
	assert.Equal(t, 30*time.Second, client.Timeout, "SafeClient must apply the shared 30s timeout")
}

func TestDNSSafeClient_ProdDefaultValidationError(t *testing.T) {
	prod := "ftp://203.0.113.10"
	_, err := dnsSafeClient(HardeningSourceGCP, prod, prod, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), HardeningSourceGCP, "error must be attributed to the source")
	assert.Contains(t, err.Error(), "scheme")
}

func TestToStringSlice(t *testing.T) {
	assert.Nil(t, toStringSlice(nil))
	assert.Equal(t, []string{"a", "b"}, toStringSlice([]string{"a", "b"}), "[]string passes through")
	assert.Equal(t, []string{"x", "y"}, toStringSlice([]any{"x", 7, "y", true}),
		"non-string elements must be dropped")
	assert.Nil(t, toStringSlice("not-a-slice"))
	assert.Empty(t, toStringSlice([]any{}))
}

func TestToString(t *testing.T) {
	assert.Equal(t, "v", toString("v"))
	assert.Equal(t, "", toString(nil))
	assert.Equal(t, "", toString(42))
}

func TestIsValidDNSRecordType_ClosedSet(t *testing.T) {
	for _, valid := range []string{"A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "SRV", "PTR", "CAA", "DS"} {
		assert.True(t, IsValidDNSRecordType(valid), "type %s must be accepted", valid)
	}
	for _, invalid := range []string{"SPF", "a", "", "ALIAS"} {
		assert.False(t, IsValidDNSRecordType(invalid), "type %q must be rejected", invalid)
	}
}
