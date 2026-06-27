package cloud

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// cloudflareMockServer returns an httptest server that mimics the subset of
// the Cloudflare API v4 used by CloudflareDNS.Discover. Tests inject canned
// JSON payloads for /zones and /zones/:id/dns_records; the captured paths
// allow assertions about which endpoints were hit.
func cloudflareMockServer(t *testing.T, zonesJSON, recordsJSON string) (*httptest.Server, *[]string) {
	t.Helper()
	var calls []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		calls = append(calls, req.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(req.URL.Path, "/dns_records"):
			_, _ = w.Write([]byte(recordsJSON))
		case strings.HasSuffix(req.URL.Path, "/zones"):
			_, _ = w.Write([]byte(zonesJSON))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func TestCloudflareDiscover_DisabledByConfig(t *testing.T) {
	c := NewDNSCloudflare()
	assets, err := c.Discover(context.Background(), map[string]any{"enabled": false})
	require.NoError(t, err)
	assert.Nil(t, assets)
	assert.Nil(t, c.Snapshot())
}

func TestCloudflareDiscover_NoTokenErrorsWhenConfigured(t *testing.T) {
	t.Setenv("CF_API_TOKEN", "")
	c := NewDNSCloudflare()
	_, err := c.Discover(context.Background(), map[string]any{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "CF_API_TOKEN")
}

func TestCloudflareDiscover_NoTokenSkipsWhenUnconfigured(t *testing.T) {
	t.Setenv("CF_API_TOKEN", "")
	c := NewDNSCloudflare()
	assets, err := c.Discover(context.Background(), nil)
	require.NoError(t, err)
	assert.Nil(t, assets)
	assert.Nil(t, c.Snapshot())
}

func TestCloudflareDiscover_HappyPath(t *testing.T) {
	t.Setenv("CF_API_TOKEN", "test-token")

	zones := `{
	  "success": true,
	  "errors": [],
	  "result": [
	    {
	      "id": "zone-id-1",
	      "name": "example.com",
	      "status": "active",
	      "type": "full",
	      "name_servers": ["ns1.cloudflare.com", "ns2.cloudflare.com"],
	      "original_name_servers": ["ns-old.example.com"],
	      "paused": false,
	      "account": {"id": "acc-1", "name": "Test Account"},
	      "plan": {"id": "free", "name": "Free Plan"}
	    }
	  ],
	  "result_info": {"page": 1, "per_page": 50, "total_pages": 1, "count": 1, "total_count": 1}
	}`

	records := `{
	  "success": true,
	  "errors": [],
	  "result": [
	    {
	      "id": "rec-1",
	      "zone_id": "zone-id-1",
	      "name": "example.com",
	      "type": "A",
	      "content": "192.0.2.1",
	      "ttl": 300
	    },
	    {
	      "id": "rec-2",
	      "zone_id": "zone-id-1",
	      "name": "www.example.com",
	      "type": "CNAME",
	      "content": "example.com",
	      "ttl": 0
	    },
	    {
	      "id": "rec-3",
	      "zone_id": "zone-id-1",
	      "name": "_dmarc.example.com",
	      "type": "BOGUS",
	      "content": "v=DMARC1; p=none",
	      "ttl": 60
	    }
	  ],
	  "result_info": {"page": 1, "per_page": 50, "total_pages": 1, "count": 3, "total_count": 3}
	}`

	srv, calls := cloudflareMockServer(t, zones, records)

	c := NewDNSCloudflare()
	c.baseURL = srv.URL
	c.httpClient = srv.Client()

	assets, err := c.Discover(context.Background(), map[string]any{"enabled": true})
	require.NoError(t, err)
	assert.Nil(t, assets)

	snap := c.Snapshot()
	require.NotNil(t, snap)
	assert.Equal(t, DNSProviderCloudflare, snap.Provider)
	require.Len(t, snap.Zones, 1)
	require.Len(t, snap.Records, 2, "BOGUS record type must be dropped by IsValidDNSRecordType filter")

	z := snap.Zones[0]
	assert.Equal(t, "zone-id-1", z.ProviderZoneID)
	assert.Equal(t, "example.com.", z.ZoneName, "trailing dot must be added")
	assert.False(t, z.IsPrivate)
	assert.False(t, z.DNSSECEnabled)
	assert.Equal(t, "cloudflare:acc-1", z.AccountRef)
	require.NotNil(t, z.RecordCount)
	assert.Equal(t, 3, *z.RecordCount, "RecordCount counts every record returned by the API, including dropped types")

	byKey := map[string]DNSRecord{}
	for _, r := range snap.Records {
		byKey[r.RecordName+"|"+r.RecordType] = r
	}
	cname := byKey["www.example.com.|CNAME"]
	assert.Equal(t, uint32(300), cname.TTL, "ttl=0 from API must default to 300")
	assert.Equal(t, `["example.com"]`, cname.ValuesJSON)

	require.NotEmpty(t, *calls)
	assert.Contains(t, (*calls)[0], "/zones")
}

func TestCloudflareDiscover_AccountFilter(t *testing.T) {
	t.Setenv("CF_API_TOKEN", "test-token")

	zones := `{"success": true, "errors": [], "result": [], "result_info": {"page": 1, "per_page": 50, "total_pages": 1}}`
	records := `{"success": true, "errors": [], "result": [], "result_info": {"page": 1, "per_page": 50, "total_pages": 1}}`

	var capturedQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if strings.HasSuffix(req.URL.Path, "/zones") {
			capturedQuery = req.URL.RawQuery
			_, _ = w.Write([]byte(zones))
			return
		}
		_, _ = w.Write([]byte(records))
	}))
	t.Cleanup(srv.Close)

	c := NewDNSCloudflare()
	c.baseURL = srv.URL
	c.httpClient = srv.Client()

	_, err := c.Discover(context.Background(), map[string]any{"account_id": "acc-99"})
	require.NoError(t, err)
	assert.Contains(t, capturedQuery, "account.id=acc-99",
		"account_id config must pass through as the account.id query param")
}

func TestCloudflareNameAndSnapshotBeforeDiscover(t *testing.T) {
	c := NewDNSCloudflare()
	assert.Equal(t, "cloud_dns_cloudflare", c.Name())
	assert.Nil(t, c.Snapshot())
}
