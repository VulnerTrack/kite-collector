package cloud

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RFC-0137 R8 hardening tests for the four Cloud DNS connectors.
//
// Coverage mapping (per the four behaviours R8 enumerates):
//   - SSRF block: N/A for Cloud DNS. All four base URLs are hardcoded package
//     constants (no operator-overridable URL), so there is no SSRF target to
//     reject — see Section 2.1/2.2. The retrofit still routes through
//     connectorkit.SafeClient for TLS/timeout consistency (R5), exercised by the
//     existing happy-path tests.
//   - Path-traversal rejection (F6): a provider-returned zone identifier
//     carrying a traversal sequence is rejected by safenet.SanitizePathSegment.
//     Route53/Cloudflare validate in Discover (their Discover is unit-testable);
//     Azure/GCP validate inside the record-set list helper (their Discover needs
//     a live token endpoint, so the helper is the testable seam).
//   - Pagination cap trip (F5): with a tiny cumulative byte cap, the first page
//     trips PaginationGuardV2 and surfaces an error rather than truncating.
//   - Credential zeroing: all four route their secrets through
//     connectorkit.Credentials.Zero(), whose in-place backing-array overwrite is
//     proven at the byte level in connectorkit's TestCredentialsZero_BackingMemory.

// --- Route53 -------------------------------------------------------------

func TestRoute53Discover_PaginationGuardTrips(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAEXAMPLE12345")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret/example/value")
	t.Setenv("KITE_PAGINATION_MAX_BYTES_TOTAL", "8")

	listZones := `<?xml version="1.0"?><ListHostedZonesResponse>` +
		`<HostedZones><HostedZone><Id>/hostedzone/Z1</Id><Name>example.com.</Name>` +
		`<Config><PrivateZone>false</PrivateZone></Config></HostedZone></HostedZones>` +
		`<IsTruncated>false</IsTruncated></ListHostedZonesResponse>`
	srv, _ := route53MockServer(t, listZones, "", "")

	r := NewDNSRoute53()
	r.baseURL = srv.URL
	r.httpClient = srv.Client()

	_, err := r.Discover(context.Background(), map[string]any{"enabled": true})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "pagination guard")
}

func TestRoute53Discover_RejectsUnsafeZoneID(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAEXAMPLE12345")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret/example/value")

	// After the /hostedzone/ prefix strip the id is "../../secret" — a traversal
	// that SanitizePathSegment must reject, skipping the zone so no dnssec/rrset
	// request is ever issued for it.
	listZones := `<?xml version="1.0"?><ListHostedZonesResponse>` +
		`<HostedZones><HostedZone><Id>/hostedzone/../../secret</Id><Name>evil.com.</Name>` +
		`<Config><PrivateZone>false</PrivateZone></Config></HostedZone></HostedZones>` +
		`<IsTruncated>false</IsTruncated></ListHostedZonesResponse>`
	srv, _ := route53MockServer(t, listZones, "", "")

	r := NewDNSRoute53()
	r.baseURL = srv.URL
	r.httpClient = srv.Client()

	_, err := r.Discover(context.Background(), map[string]any{"enabled": true})
	require.NoError(t, err)
	snap := r.Snapshot()
	require.NotNil(t, snap)
	assert.Empty(t, snap.Zones, "zone with a path-traversal hosted-zone id must be skipped")
}

// --- Cloudflare ----------------------------------------------------------

func TestCloudflareDiscover_PaginationGuardTrips(t *testing.T) {
	t.Setenv("CF_API_TOKEN", "test-token")
	t.Setenv("KITE_PAGINATION_MAX_BYTES_TOTAL", "8")

	zones := `{"success":true,"errors":[],"result":[{"id":"z1","name":"example.com",` +
		`"account":{"id":"a"},"plan":{"name":"Free"}}],` +
		`"result_info":{"page":1,"per_page":50,"total_pages":1}}`
	records := `{"success":true,"errors":[],"result":[],"result_info":{"page":1,"per_page":50,"total_pages":1}}`
	srv, _ := cloudflareMockServer(t, zones, records)

	c := NewDNSCloudflare()
	c.baseURL = srv.URL
	c.httpClient = srv.Client()

	_, err := c.Discover(context.Background(), map[string]any{"enabled": true})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "pagination guard")
}

func TestCloudflareDiscover_RejectsUnsafeZoneID(t *testing.T) {
	t.Setenv("CF_API_TOKEN", "test-token")

	zones := `{"success":true,"errors":[],"result":[{"id":"../../../etc/passwd","name":"evil.com",` +
		`"account":{"id":"a"},"plan":{"name":"Free"}}],` +
		`"result_info":{"page":1,"per_page":50,"total_pages":1}}`
	records := `{"success":true,"errors":[],"result":[],"result_info":{"page":1,"per_page":50,"total_pages":1}}`
	srv, _ := cloudflareMockServer(t, zones, records)

	c := NewDNSCloudflare()
	c.baseURL = srv.URL
	c.httpClient = srv.Client()

	_, err := c.Discover(context.Background(), map[string]any{"enabled": true})
	require.NoError(t, err)
	snap := c.Snapshot()
	require.NotNil(t, snap)
	assert.Empty(t, snap.Zones, "zone with a path-traversal id must be skipped")
}

// --- Azure (helper-level: Discover needs a live token endpoint) ----------

func TestAzureDNS_ListZones_PaginationGuardTrips(t *testing.T) {
	t.Setenv("KITE_PAGINATION_MAX_BYTES_TOTAL", "8")

	resp := `{"value":[{"id":"/subscriptions/s/resourceGroups/rg/providers/` +
		`Microsoft.Network/dnsZones/example.com","name":"example.com",` +
		`"type":"Microsoft.Network/dnsZones","properties":{}}]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(resp))
	}))
	t.Cleanup(srv.Close)

	a := NewDNSAzure()
	a.baseURL = srv.URL
	a.httpClient = srv.Client()

	_, err := a.listZones(context.Background(), "fake-token", "sub-1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "pagination guard")
}

func TestAzureDNS_ListRecordSets_RejectsUnsafeZoneID(t *testing.T) {
	a := NewDNSAzure()
	a.baseURL = "https://management.azure.example"

	// A middle segment of the ARM resource id is a bare ".." traversal —
	// sanitizeAzureResourceID must reject it before any request is issued.
	zoneID := "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/dnsZones/../../../etc"
	_, err := a.listRecordSets(context.Background(), "tok", zoneID, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsafe segment")
}

// --- GCP (helper-level: Discover needs the metadata server) --------------

func TestGCPDNS_ListManagedZones_PaginationGuardTrips(t *testing.T) {
	t.Setenv("KITE_PAGINATION_MAX_BYTES_TOTAL", "8")

	page := `{"managedZones":[{"id":"1","name":"z","dnsName":"z.","visibility":"public"}],"nextPageToken":"t2"}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(page))
	}))
	t.Cleanup(srv.Close)

	g := NewDNSGCP()
	g.baseURL = srv.URL
	g.httpClient = srv.Client()

	_, err := g.listManagedZones(context.Background(), "fake-token", "proj")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "pagination guard")
}

func TestGCPDNS_ListResourceRecordSets_RejectsUnsafeZoneName(t *testing.T) {
	g := NewDNSGCP()
	g.baseURL = "https://dns.googleapis.example"

	_, err := g.listResourceRecordSets(context.Background(), "tok", "proj", "../../etc/passwd")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "path traversal")
}
