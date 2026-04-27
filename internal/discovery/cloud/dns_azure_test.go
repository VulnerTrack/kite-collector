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

func TestAzureDNSDiscover_DisabledByConfig(t *testing.T) {
	a := NewDNSAzure()
	assets, err := a.Discover(context.Background(), map[string]any{"enabled": false})
	require.NoError(t, err)
	assert.Nil(t, assets)
	assert.Nil(t, a.Snapshot())
}

func TestAzureDNSDiscover_NoCredentialsErrorsWhenConfigured(t *testing.T) {
	t.Setenv("AZURE_TENANT_ID", "")
	t.Setenv("AZURE_CLIENT_ID", "")
	t.Setenv("AZURE_CLIENT_SECRET", "")
	a := NewDNSAzure()
	_, err := a.Discover(context.Background(), map[string]any{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "AZURE_")
}

func TestAzureDNSDiscover_NoCredentialsSkipsWhenUnconfigured(t *testing.T) {
	t.Setenv("AZURE_TENANT_ID", "")
	t.Setenv("AZURE_CLIENT_ID", "")
	t.Setenv("AZURE_CLIENT_SECRET", "")
	a := NewDNSAzure()
	assets, err := a.Discover(context.Background(), nil)
	require.NoError(t, err)
	assert.Nil(t, assets)
	assert.Nil(t, a.Snapshot())
}

func TestAzureDNSNameAndSnapshotBeforeDiscover(t *testing.T) {
	a := NewDNSAzure()
	assert.Equal(t, "cloud_dns_azure", a.Name())
	assert.Nil(t, a.Snapshot())
}

func TestAzureDNS_ListZones_PaginatesAndMergesPublicAndPrivate(t *testing.T) {
	publicResp := `{
	  "value": [
	    {
	      "id": "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Network/dnsZones/example.com",
	      "name": "example.com",
	      "type": "Microsoft.Network/dnsZones",
	      "location": "global",
	      "properties": {"numberOfRecordSets": 3, "maxNumberOfRecordSets": 10000}
	    }
	  ]
	}`
	privateResp := `{
	  "value": [
	    {
	      "id": "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Network/privateDnsZones/internal.example",
	      "name": "internal.example",
	      "type": "Microsoft.Network/privateDnsZones",
	      "location": "global",
	      "properties": {"numberOfRecordSets": 2, "maxNumberOfRecordSets": 25000}
	    }
	  ]
	}`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(req.URL.Path, "/privateDnsZones"):
			_, _ = w.Write([]byte(privateResp))
		case strings.Contains(req.URL.Path, "/dnsZones"):
			_, _ = w.Write([]byte(publicResp))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)

	a := NewDNSAzure()
	a.baseURL = srv.URL
	a.httpClient = srv.Client()

	zones, err := a.listZones(context.Background(), "fake-token", "sub-1")
	require.NoError(t, err)
	require.Len(t, zones, 2)

	names := []string{zones[0].Name, zones[1].Name}
	assert.Contains(t, names, "example.com")
	assert.Contains(t, names, "internal.example")
}

func TestAzureDNS_ListRecordSets_FollowsNextLink(t *testing.T) {
	page1 := `{
	  "value": [
	    {
	      "id": "/zone/recordset/a",
	      "name": "www",
	      "type": "Microsoft.Network/dnsZones/A",
	      "properties": {"TTL": 60, "ARecords": [{"ipv4Address": "10.0.0.1"}]}
	    }
	  ],
	  "nextLink": "%s/page2"
	}`
	page2 := `{
	  "value": [
	    {
	      "id": "/zone/recordset/cname",
	      "name": "alias",
	      "type": "Microsoft.Network/dnsZones/CNAME",
	      "properties": {"TTL": 300, "CNAMERecord": {"cname": "target.example.com"}}
	    }
	  ]
	}`

	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(req.URL.Path, "/page2") {
			_, _ = w.Write([]byte(page2))
			return
		}
		// Inject the page2 URL using the live test server URL.
		_, _ = w.Write([]byte(strings.Replace(page1, "%s", srv.URL, 1)))
	}))
	t.Cleanup(srv.Close)

	a := NewDNSAzure()
	a.baseURL = srv.URL
	a.httpClient = srv.Client()

	zoneID := "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/dnsZones/example.com"
	records, err := a.listRecordSets(context.Background(), "fake-token", zoneID, false)
	require.NoError(t, err)
	require.Len(t, records, 2, "nextLink must drive the second page fetch")
	assert.Equal(t, "www", records[0].Name)
	assert.Equal(t, "alias", records[1].Name)
}

func TestExtractResourceGroup(t *testing.T) {
	cases := map[string]string{
		"/subscriptions/s/resourceGroups/my-rg/providers/Microsoft.Network/dnsZones/x": "my-rg",
		"/subscriptions/s/resourceGroups/only-rg":                                      "only-rg",
		"/subscriptions/s/providers/Microsoft.Network/x":                               "",
		"": "",
	}
	for in, want := range cases {
		assert.Equal(t, want, extractResourceGroup(in), "input=%q", in)
	}
}

func TestExtractAzureRecordType(t *testing.T) {
	cases := map[string]string{
		"Microsoft.Network/dnsZones/A":           "A",
		"Microsoft.Network/dnsZones/CNAME":       "CNAME",
		"Microsoft.Network/privateDnsZones/AAAA": "AAAA",
		"raw":                                    "raw",
		"":                                       "",
	}
	for in, want := range cases {
		assert.Equal(t, want, extractAzureRecordType(in), "input=%q", in)
	}
}

func TestExtractAzureRecordValues(t *testing.T) {
	props := azureDNSRecordSetProperties{
		ARecords:    []azureDNSARecord{{IPv4Address: "1.1.1.1"}, {IPv4Address: "2.2.2.2"}},
		AAAARecords: []azureDNSAAAARecord{{IPv6Address: "::1"}},
		CNAMERecord: azureDNSCNAMERecord{CNAME: "target.example.com"},
		MXRecords:   []azureDNSMXRecord{{Preference: 10, Exchange: "mail.example.com"}},
		TXTRecords:  []azureDNSTXTRecord{{Value: []string{"v=spf1 -all"}}},
		NSRecords:   []azureDNSNSRecord{{NSDName: "ns1.example.com"}},
		SOARecord: azureDNSSOARecord{
			Host: "ns1.example.com", Email: "hostmaster.example.com",
			SerialNumber: 1, RefreshTime: 3600, RetryTime: 600,
			ExpireTime: 86400, MinimumTTL: 300,
		},
		SRVRecords: []azureDNSSRVRecord{{Priority: 1, Weight: 1, Port: 443, Target: "srv.example.com"}},
		PTRRecords: []azureDNSPTRRecord{{PTRDName: "ptr.example.com"}},
		CAARecords: []azureDNSCAARecord{{Flags: 0, Tag: "issue", Value: "letsencrypt.org"}},
	}

	assert.Equal(t, []string{"1.1.1.1", "2.2.2.2"}, extractAzureRecordValues("A", props))
	assert.Equal(t, []string{"::1"}, extractAzureRecordValues("AAAA", props))
	assert.Equal(t, []string{"target.example.com"}, extractAzureRecordValues("CNAME", props))
	assert.Equal(t, []string{"10 mail.example.com"}, extractAzureRecordValues("MX", props))
	assert.Equal(t, []string{"v=spf1 -all"}, extractAzureRecordValues("TXT", props))
	assert.Equal(t, []string{"ns1.example.com"}, extractAzureRecordValues("NS", props))
	assert.Equal(t, []string{"ns1.example.com hostmaster.example.com 1 3600 600 86400 300"},
		extractAzureRecordValues("SOA", props))
	assert.Equal(t, []string{"1 1 443 srv.example.com"}, extractAzureRecordValues("SRV", props))
	assert.Equal(t, []string{"ptr.example.com"}, extractAzureRecordValues("PTR", props))
	assert.Equal(t, []string{"0 issue letsencrypt.org"}, extractAzureRecordValues("CAA", props))
	assert.Equal(t, []string{}, extractAzureRecordValues("UNKNOWN", props))
}
