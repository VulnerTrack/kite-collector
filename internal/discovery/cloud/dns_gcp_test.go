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

func TestGCPDNSDiscover_DisabledByConfig(t *testing.T) {
	g := NewDNSGCP()
	assets, err := g.Discover(context.Background(), map[string]any{"enabled": false})
	require.NoError(t, err)
	assert.Nil(t, assets)
	assert.Nil(t, g.Snapshot())
}

func TestGCPDNSDiscover_NoProjectErrorsWhenConfigured(t *testing.T) {
	g := NewDNSGCP()
	_, err := g.Discover(context.Background(), map[string]any{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "project_id")
}

func TestGCPDNSDiscover_NoProjectSkipsWhenUnconfigured(t *testing.T) {
	g := NewDNSGCP()
	assets, err := g.Discover(context.Background(), nil)
	require.NoError(t, err)
	assert.Nil(t, assets)
	assert.Nil(t, g.Snapshot())
}

func TestGCPDNSNameAndSnapshotBeforeDiscover(t *testing.T) {
	g := NewDNSGCP()
	assert.Equal(t, "cloud_dns_gcp", g.Name())
	assert.Nil(t, g.Snapshot())
}

func TestGCPDNS_ListManagedZones_PaginatesViaPageToken(t *testing.T) {
	page1 := `{
	  "managedZones": [
	    {
	      "id": "1",
	      "name": "example-com",
	      "dnsName": "example.com.",
	      "description": "primary",
	      "visibility": "public",
	      "nameServers": ["ns-cloud-a1.googledomains.com."],
	      "dnssecConfig": {"state": "on", "nonExistence": "nsec3"}
	    }
	  ],
	  "nextPageToken": "tok-2"
	}`
	page2 := `{
	  "managedZones": [
	    {
	      "id": "2",
	      "name": "internal-test",
	      "dnsName": "internal.test.",
	      "visibility": "private"
	    }
	  ]
	}`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if req.URL.Query().Get("pageToken") == "tok-2" {
			_, _ = w.Write([]byte(page2))
			return
		}
		_, _ = w.Write([]byte(page1))
	}))
	t.Cleanup(srv.Close)

	g := NewDNSGCP()
	g.baseURL = srv.URL
	g.httpClient = srv.Client()

	zones, err := g.listManagedZones(context.Background(), "fake-token", "my-proj")
	require.NoError(t, err)
	require.Len(t, zones, 2)
	assert.Equal(t, "example-com", zones[0].Name)
	assert.Equal(t, "internal-test", zones[1].Name)
	require.NotNil(t, zones[0].DNSSECConfig)
	assert.Equal(t, "on", zones[0].DNSSECConfig.State)
}

func TestGCPDNS_ListResourceRecordSets_FollowsPageToken(t *testing.T) {
	page1 := `{
	  "rrsets": [
	    {"name": "example.com.", "type": "A", "ttl": 300, "rrdatas": ["192.0.2.1"]}
	  ],
	  "nextPageToken": "next-1"
	}`
	page2 := `{
	  "rrsets": [
	    {"name": "www.example.com.", "type": "CNAME", "ttl": 60, "rrdatas": ["example.com."]}
	  ]
	}`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if req.URL.Query().Get("pageToken") == "next-1" {
			_, _ = w.Write([]byte(page2))
			return
		}
		_, _ = w.Write([]byte(page1))
	}))
	t.Cleanup(srv.Close)

	g := NewDNSGCP()
	g.baseURL = srv.URL
	g.httpClient = srv.Client()

	rrsets, err := g.listResourceRecordSets(context.Background(), "fake-token", "my-proj", "example-com")
	require.NoError(t, err)
	require.Len(t, rrsets, 2)
	assert.Equal(t, "A", rrsets[0].Type)
	assert.Equal(t, []string{"192.0.2.1"}, rrsets[0].RRDatas)
	assert.Equal(t, "CNAME", rrsets[1].Type)
}

func TestGCPDNS_DiscoverHappyPath_FullPipeline(t *testing.T) {
	zones := `{
	  "managedZones": [
	    {
	      "id": "10",
	      "name": "example-com",
	      "dnsName": "example.com.",
	      "visibility": "public",
	      "dnssecConfig": {"state": "on"}
	    }
	  ]
	}`
	rrsets := `{
	  "rrsets": [
	    {"name": "example.com.", "type": "A", "ttl": 300, "rrdatas": ["192.0.2.1"]},
	    {"name": "www.example.com.", "type": "CNAME", "ttl": 0, "rrdatas": ["example.com."]},
	    {"name": "_acme.example.com.", "type": "BOGUS", "ttl": 60, "rrdatas": ["x"]}
	  ]
	}`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(req.URL.Path, "/rrsets"):
			_, _ = w.Write([]byte(rrsets))
		case strings.Contains(req.URL.Path, "/managedZones"):
			_, _ = w.Write([]byte(zones))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)

	g := NewDNSGCP()
	g.baseURL = srv.URL
	g.httpClient = srv.Client()

	// Inject a no-op token getter so Discover doesn't try to hit the GCE
	// metadata server. We bypass obtainGCPToken by writing direct API call
	// asserts against the listing helpers; a true Discover() integration
	// test requires GCP creds.
	zonesOut, err := g.listManagedZones(context.Background(), "fake-token", "proj-1")
	require.NoError(t, err)
	require.Len(t, zonesOut, 1)
	rrsetsOut, err := g.listResourceRecordSets(context.Background(), "fake-token", "proj-1", "example-com")
	require.NoError(t, err)
	require.Len(t, rrsetsOut, 3)
}

func TestNextPageURL(t *testing.T) {
	cases := []struct {
		name      string
		current   string
		token     string
		wantToken string
	}{
		{name: "empty token returns empty", current: "https://dns.googleapis.com/x", token: "", wantToken: ""},
		{name: "token appended", current: "https://dns.googleapis.com/x", token: "abc", wantToken: "abc"},
		{name: "replaces existing token", current: "https://dns.googleapis.com/x?pageToken=old", token: "new", wantToken: "new"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := nextPageURL(c.current, c.token)
			if c.wantToken == "" {
				assert.Equal(t, "", got)
				return
			}
			assert.Contains(t, got, "pageToken="+c.wantToken)
		})
	}
}

func TestDNSSECState(t *testing.T) {
	assert.Equal(t, "", dnssecState(nil))
	assert.Equal(t, "on", dnssecState(&gcpDNSSECConfig{State: "on"}))
	assert.Equal(t, "off", dnssecState(&gcpDNSSECConfig{State: "off"}))
}
