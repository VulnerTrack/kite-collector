package cloud

// dns_discover_more_test.go: full Discover() pipelines for the GCP Cloud DNS
// and Azure DNS sources. Their zone/record APIs already accept a baseURL
// override, but token acquisition targets hardcoded endpoints (GCE metadata
// server, Microsoft identity platform) — interceptHosts supplies those.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- GCP Cloud DNS --------------------------------------------------------

func gcpDNSZoneServer(t *testing.T) *httptest.Server {
	t.Helper()
	zones := `{
	  "managedZones": [
	    {
	      "id": "10",
	      "name": "example-com",
	      "dnsName": "example.com.",
	      "description": "primary",
	      "visibility": "public",
	      "nameServers": ["ns-cloud-a1.googledomains.com."],
	      "dnssecConfig": {"state": "on", "nonExistence": "nsec3"}
	    },
	    {
	      "id": "11",
	      "name": "internal-corp",
	      "dnsName": "corp.internal",
	      "visibility": "private"
	    }
	  ]
	}`
	publicRRSets := `{
	  "rrsets": [
	    {"name": "example.com.", "type": "A", "ttl": 300, "rrdatas": ["192.0.2.1"]},
	    {"name": "txt.example.com.", "type": "TXT", "ttl": 0, "rrdatas": ["v=spf1 -all"]},
	    {"name": "weird.example.com.", "type": "SPF", "ttl": 60, "rrdatas": ["x"]},
	    {"name": "empty.example.com", "type": "NS", "ttl": 120}
	  ]
	}`
	privateRRSets := `{"rrsets": []}`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(req.URL.Path, "/managedZones/example-com/rrsets"):
			_, _ = w.Write([]byte(publicRRSets))
		case strings.Contains(req.URL.Path, "/managedZones/internal-corp/rrsets"):
			_, _ = w.Write([]byte(privateRRSets))
		case strings.Contains(req.URL.Path, "/managedZones"):
			_, _ = w.Write([]byte(zones))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestGCPDNSDiscover_FullPipeline(t *testing.T) {
	interceptHosts(t, hostRoutes{
		gcpMetadataHost: gcpMetadataTokenHandler("dns-tok", nil),
	})
	srv := gcpDNSZoneServer(t)

	g := NewDNSGCP()
	g.baseURL = srv.URL
	g.httpClient = srv.Client()

	machines, err := g.Discover(context.Background(), map[string]any{"project_id": "proj-1"})
	require.NoError(t, err)
	assert.Nil(t, machines, "Discover must not return machines")

	snap := g.Snapshot()
	require.NotNil(t, snap)
	assert.Equal(t, DNSProviderGCPCloudDNS, snap.Provider)
	require.Len(t, snap.Zones, 2)

	pub := snap.Zones[0]
	assert.Equal(t, "example-com", pub.ProviderZoneID)
	assert.Equal(t, "example.com.", pub.ZoneName)
	assert.Equal(t, "gcp:proj-1", pub.AccountRef)
	assert.False(t, pub.IsPrivate)
	assert.True(t, pub.DNSSECEnabled)
	require.NotNil(t, pub.RecordCount)
	assert.Equal(t, 4, *pub.RecordCount, "record count reflects all fetched rrsets, pre-filter")
	assert.Contains(t, pub.RawMetadata, `"dnssec_state":"on"`)

	priv := snap.Zones[1]
	assert.Equal(t, "corp.internal.", priv.ZoneName, "missing trailing dot must be added")
	assert.True(t, priv.IsPrivate)
	assert.False(t, priv.DNSSECEnabled, "zone without dnssecConfig defaults to disabled")
	require.NotNil(t, priv.RecordCount)
	assert.Equal(t, 0, *priv.RecordCount)

	require.Len(t, snap.Records, 3, "unsupported SPF record must be filtered out")
	byName := map[string]DNSRecord{}
	for _, rec := range snap.Records {
		byName[rec.RecordName] = rec
	}
	a := byName["example.com."]
	assert.Equal(t, "A", a.RecordType)
	assert.Equal(t, uint32(300), a.TTL)
	assert.Equal(t, `["192.0.2.1"]`, a.ValuesJSON)
	assert.Equal(t, pub.ID, a.ZoneID, "record must reference the surrogate zone UUID")

	txt := byName["txt.example.com."]
	assert.Equal(t, uint32(300), txt.TTL, "zero TTL must default to 300")

	ns := byName["empty.example.com."]
	assert.Equal(t, "[]", ns.ValuesJSON, "nil rrdatas must serialize as an empty JSON array")
}

func TestGCPDNSDiscover_TokenFailureErrorsWhenConfigured(t *testing.T) {
	interceptHosts(t, hostRoutes{}) // metadata unreachable
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", filepath.Join(t.TempDir(), "absent.json"))

	g := NewDNSGCP()
	_, err := g.Discover(context.Background(), map[string]any{"project_id": "proj-1"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "could not obtain access token")
}

func TestGCPDNSDiscover_ZoneListFailure(t *testing.T) {
	interceptHosts(t, hostRoutes{
		gcpMetadataHost: gcpMetadataTokenHandler("dns-tok", nil),
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("denied"))
	}))
	t.Cleanup(srv.Close)

	g := NewDNSGCP()
	g.baseURL = srv.URL
	g.httpClient = srv.Client()

	_, err := g.Discover(context.Background(), map[string]any{"project_id": "proj-1"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cloud_dns_gcp")
	assert.Nil(t, g.Snapshot(), "snapshot must stay nil when zone listing fails")
}

func TestGCPDNSDiscover_RecordListFailureEmitsPartialZone(t *testing.T) {
	interceptHosts(t, hostRoutes{
		gcpMetadataHost: gcpMetadataTokenHandler("dns-tok", nil),
	})
	zones := `{"managedZones": [{"id": "1", "name": "half-zone", "dnsName": "half.example."}]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if strings.Contains(req.URL.Path, "/rrsets") {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(zones))
	}))
	t.Cleanup(srv.Close)

	g := NewDNSGCP()
	g.baseURL = srv.URL
	g.httpClient = srv.Client()

	_, err := g.Discover(context.Background(), map[string]any{"project_id": "proj-1"})
	require.NoError(t, err, "record-set failure must degrade to partial zone data")

	snap := g.Snapshot()
	require.NotNil(t, snap)
	require.Len(t, snap.Zones, 1)
	require.NotNil(t, snap.Zones[0].RecordCount)
	assert.Equal(t, 0, *snap.Zones[0].RecordCount)
	assert.Empty(t, snap.Records)
}

// --- Azure DNS ------------------------------------------------------------

func azureDNSZoneServer(t *testing.T) *httptest.Server {
	t.Helper()
	publicZones := `{
	  "value": [
	    {
	      "id": "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Network/dnsZones/example.com",
	      "name": "example.com",
	      "type": "Microsoft.Network/dnsZones",
	      "location": "global",
	      "properties": {"numberOfRecordSets": 2, "maxNumberOfRecordSets": 10000}
	    }
	  ]
	}`
	privateZones := `{
	  "value": [
	    {
	      "id": "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Network/privateDnsZones/corp.internal",
	      "name": "corp.internal",
	      "type": "Microsoft.Network/privateDnsZones",
	      "location": "global",
	      "properties": {"numberOfRecordSets": 0, "maxNumberOfRecordSets": 25000}
	    }
	  ]
	}`
	publicRecordSets := `{
	  "value": [
	    {
	      "id": "/rs/a",
	      "name": "www",
	      "type": "Microsoft.Network/dnsZones/A",
	      "properties": {"TTL": 60, "ARecords": [{"ipv4Address": "10.0.0.1"}]}
	    },
	    {
	      "id": "/rs/cname",
	      "name": "alias",
	      "type": "Microsoft.Network/dnsZones/CNAME",
	      "properties": {"TTL": 0, "CNAMERecord": {"cname": "target.example.com"}}
	    },
	    {
	      "id": "/rs/bogus",
	      "name": "odd",
	      "type": "Microsoft.Network/dnsZones/BOGUS",
	      "properties": {"TTL": 60}
	    }
	  ]
	}`
	privateRecordSets := `{"value": []}`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(req.URL.Path, "/privateDnsZones/corp.internal/recordsets"):
			_, _ = w.Write([]byte(privateRecordSets))
		case strings.Contains(req.URL.Path, "/dnsZones/example.com/recordsets"):
			_, _ = w.Write([]byte(publicRecordSets))
		case strings.Contains(req.URL.Path, "/privateDnsZones"):
			_, _ = w.Write([]byte(privateZones))
		case strings.Contains(req.URL.Path, "/dnsZones"):
			_, _ = w.Write([]byte(publicZones))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestAzureDNSDiscover_FullPipeline(t *testing.T) {
	setAzureEnvCreds(t, "")
	interceptHosts(t, hostRoutes{
		azureLoginHost: azureTokenHandler("dns-tok", nil),
	})
	srv := azureDNSZoneServer(t)

	a := NewDNSAzure()
	a.baseURL = srv.URL
	a.httpClient = srv.Client()

	machines, err := a.Discover(context.Background(), map[string]any{"subscription_id": "sub-1"})
	require.NoError(t, err)
	assert.Nil(t, machines, "Discover must not return machines")

	snap := a.Snapshot()
	require.NotNil(t, snap)
	assert.Equal(t, DNSProviderAzureDNS, snap.Provider)
	require.Len(t, snap.Zones, 2)

	pub := snap.Zones[0]
	assert.Equal(t, "example.com.", pub.ZoneName)
	assert.Equal(t, "azure:sub-1", pub.AccountRef)
	assert.False(t, pub.IsPrivate)
	assert.False(t, pub.DNSSECEnabled)
	require.NotNil(t, pub.RecordCount)
	assert.Equal(t, 3, *pub.RecordCount, "record count reflects all fetched record sets, pre-filter")
	assert.Contains(t, pub.RawMetadata, `"resource_group":"rg"`)

	priv := snap.Zones[1]
	assert.Equal(t, "corp.internal.", priv.ZoneName)
	assert.True(t, priv.IsPrivate, "privateDnsZones type must mark the zone private")

	require.Len(t, snap.Records, 2, "unsupported BOGUS record must be filtered out")
	byName := map[string]DNSRecord{}
	for _, rec := range snap.Records {
		byName[rec.RecordName] = rec
	}
	www := byName["www.example.com."]
	assert.Equal(t, "A", www.RecordType)
	assert.Equal(t, uint32(60), www.TTL)
	assert.Equal(t, `["10.0.0.1"]`, www.ValuesJSON)
	assert.Equal(t, pub.ID, www.ZoneID)

	alias := byName["alias.example.com."]
	assert.Equal(t, "CNAME", alias.RecordType)
	assert.Equal(t, uint32(300), alias.TTL, "zero TTL must default to 300")
	assert.Equal(t, `["target.example.com"]`, alias.ValuesJSON)
}

func TestAzureDNSDiscover_EnumeratesSubscriptions(t *testing.T) {
	setAzureEnvCreds(t, "")
	srv := azureDNSZoneServer(t)
	interceptHosts(t, hostRoutes{
		azureLoginHost: azureTokenHandler("dns-tok", nil),
		azureARMHost: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"value": [{"subscriptionId": "sub-1", "state": "Enabled"}]}`))
		}),
	})

	a := NewDNSAzure()
	a.baseURL = srv.URL
	a.httpClient = srv.Client()

	_, err := a.Discover(context.Background(), map[string]any{})
	require.NoError(t, err)

	snap := a.Snapshot()
	require.NotNil(t, snap)
	require.Len(t, snap.Zones, 2, "zones must be discovered for the enumerated subscription")
	assert.Equal(t, "azure:sub-1", snap.Zones[0].AccountRef)
}

func TestAzureDNSDiscover_TokenFailure(t *testing.T) {
	setAzureEnvCreds(t, "sub-1")
	interceptHosts(t, hostRoutes{
		azureLoginHost: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("bad client"))
		}),
	})

	a := NewDNSAzure()
	_, err := a.Discover(context.Background(), map[string]any{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cloud_dns_azure: token")
}

func TestAzureDNSDiscover_ListSubscriptionsFailure(t *testing.T) {
	setAzureEnvCreds(t, "")
	interceptHosts(t, hostRoutes{
		azureLoginHost: azureTokenHandler("dns-tok", nil),
		azureARMHost: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		}),
	})

	a := NewDNSAzure()
	_, err := a.Discover(context.Background(), map[string]any{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "list subscriptions")
}

func TestAzureDNSDiscover_ZoneListFailureContinues(t *testing.T) {
	setAzureEnvCreds(t, "")
	interceptHosts(t, hostRoutes{
		azureLoginHost: azureTokenHandler("dns-tok", nil),
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("denied"))
	}))
	t.Cleanup(srv.Close)

	a := NewDNSAzure()
	a.baseURL = srv.URL
	a.httpClient = srv.Client()

	_, err := a.Discover(context.Background(), map[string]any{"subscription_id": "sub-1"})
	require.NoError(t, err, "per-subscription zone failure must not abort discovery")

	snap := a.Snapshot()
	require.NotNil(t, snap)
	assert.Empty(t, snap.Zones)
	assert.Empty(t, snap.Records)
}

func TestAzureDNSDiscover_RecordSetFailureEmitsPartialZone(t *testing.T) {
	setAzureEnvCreds(t, "")
	interceptHosts(t, hostRoutes{
		azureLoginHost: azureTokenHandler("dns-tok", nil),
	})
	zones := `{
	  "value": [
	    {
	      "id": "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Network/dnsZones/half.example",
	      "name": "half.example",
	      "type": "Microsoft.Network/dnsZones",
	      "properties": {}
	    }
	  ]
	}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(req.URL.Path, "/recordsets"):
			w.WriteHeader(http.StatusBadRequest)
		case strings.Contains(req.URL.Path, "/privateDnsZones"):
			_, _ = w.Write([]byte(`{"value": []}`))
		default:
			_, _ = w.Write([]byte(zones))
		}
	}))
	t.Cleanup(srv.Close)

	a := NewDNSAzure()
	a.baseURL = srv.URL
	a.httpClient = srv.Client()

	_, err := a.Discover(context.Background(), map[string]any{"subscription_id": "sub-1"})
	require.NoError(t, err)

	snap := a.Snapshot()
	require.NotNil(t, snap)
	require.Len(t, snap.Zones, 1)
	require.NotNil(t, snap.Zones[0].RecordCount)
	assert.Equal(t, 0, *snap.Zones[0].RecordCount)
	assert.Empty(t, snap.Records)
}
