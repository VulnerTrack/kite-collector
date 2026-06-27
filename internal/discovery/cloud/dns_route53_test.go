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

// route53MockServer returns an httptest server that mimics the subset of the
// Route53 management API used by Route53DNS.Discover. The handler dispatches on
// the URL path and serves canned XML payloads; tests can inspect the captured
// requests via the returned slice once the server is closed.
func route53MockServer(t *testing.T, listZonesXML, listRRSetsXML, dnssecXML string) (*httptest.Server, *[]string) {
	t.Helper()
	var calls []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		calls = append(calls, req.URL.Path)
		w.Header().Set("Content-Type", "text/xml")
		switch {
		case strings.HasSuffix(req.URL.Path, "/dnssec"):
			_, _ = w.Write([]byte(dnssecXML))
		case strings.HasSuffix(req.URL.Path, "/rrset"):
			_, _ = w.Write([]byte(listRRSetsXML))
		case strings.HasSuffix(req.URL.Path, "/hostedzone"):
			_, _ = w.Write([]byte(listZonesXML))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func TestRoute53Discover_DisabledByConfig(t *testing.T) {
	r := NewDNSRoute53()
	assets, err := r.Discover(context.Background(), map[string]any{"enabled": false})
	require.NoError(t, err)
	assert.Nil(t, assets)
	assert.Nil(t, r.Snapshot(), "snapshot must remain nil when source is disabled")
}

func TestRoute53Discover_NoCredentialsErrorsWhenConfigured(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "")

	r := NewDNSRoute53()
	_, err := r.Discover(context.Background(), map[string]any{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "AWS_ACCESS_KEY_ID")
}

func TestRoute53Discover_HappyPath(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAEXAMPLE12345")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret/example/value")

	listZones := `<?xml version="1.0" encoding="UTF-8"?>
<ListHostedZonesResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/">
  <HostedZones>
    <HostedZone>
      <Id>/hostedzone/Z1ABCDEFG</Id>
      <Name>example.com.</Name>
      <CallerReference>cli-2026-04-30</CallerReference>
      <Config>
        <Comment>primary public zone</Comment>
        <PrivateZone>false</PrivateZone>
      </Config>
      <ResourceRecordSetCount>3</ResourceRecordSetCount>
    </HostedZone>
  </HostedZones>
  <IsTruncated>false</IsTruncated>
</ListHostedZonesResponse>`

	listRRSets := `<?xml version="1.0" encoding="UTF-8"?>
<ListResourceRecordSetsResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/">
  <ResourceRecordSets>
    <ResourceRecordSet>
      <Name>example.com.</Name>
      <Type>A</Type>
      <TTL>300</TTL>
      <ResourceRecords>
        <ResourceRecord><Value>192.0.2.1</Value></ResourceRecord>
      </ResourceRecords>
    </ResourceRecordSet>
    <ResourceRecordSet>
      <Name>www.example.com.</Name>
      <Type>CNAME</Type>
      <TTL>60</TTL>
      <ResourceRecords>
        <ResourceRecord><Value>example.com.</Value></ResourceRecord>
      </ResourceRecords>
    </ResourceRecordSet>
    <ResourceRecordSet>
      <Name>orphan.example.com.</Name>
      <Type>CNAME</Type>
      <SetIdentifier>weighted-1</SetIdentifier>
      <Weight>50</Weight>
      <TTL>120</TTL>
      <ResourceRecords>
        <ResourceRecord><Value>old-bucket.s3.amazonaws.com.</Value></ResourceRecord>
      </ResourceRecords>
    </ResourceRecordSet>
  </ResourceRecordSets>
  <IsTruncated>false</IsTruncated>
</ListResourceRecordSetsResponse>`

	dnssec := `<?xml version="1.0" encoding="UTF-8"?>
<GetDNSSECResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/">
  <Status>
    <ServeSignature>NOT_SIGNING</ServeSignature>
  </Status>
</GetDNSSECResponse>`

	srv, calls := route53MockServer(t, listZones, listRRSets, dnssec)

	r := NewDNSRoute53()
	r.baseURL = srv.URL
	r.httpClient = srv.Client()

	assets, err := r.Discover(context.Background(), map[string]any{"enabled": true})
	require.NoError(t, err)
	assert.Nil(t, assets, "Discover must not return any model.Asset")

	snap := r.Snapshot()
	require.NotNil(t, snap)
	assert.Equal(t, DNSProviderRoute53, snap.Provider)
	require.Len(t, snap.Zones, 1)
	require.Len(t, snap.Records, 3)

	z := snap.Zones[0]
	assert.Equal(t, "Z1ABCDEFG", z.ProviderZoneID, "hostedzone/ prefix must be stripped")
	assert.Equal(t, "example.com.", z.ZoneName, "zone name must end with trailing dot")
	assert.False(t, z.IsPrivate)
	assert.False(t, z.DNSSECEnabled, "DNSSEC must be false when ServeSignature != SIGNING")
	assert.Equal(t, "aws:AKIAEXAM...", z.AccountRef, "account ref derived from access-key prefix")
	require.NotNil(t, z.RecordCount)
	assert.Equal(t, 3, *z.RecordCount)

	policies := map[string]string{}
	for _, rec := range snap.Records {
		policies[rec.RecordName+"|"+rec.RecordType] = rec.RoutingPolicy
	}
	assert.Equal(t, "", policies["example.com.|A"], "simple records have empty routing policy")
	assert.Equal(t, "weighted", policies["orphan.example.com.|CNAME"], "weighted records map to weighted")

	require.NotEmpty(t, *calls)
	assert.True(t, strings.HasSuffix((*calls)[0], "/hostedzone"))
}

func TestRoute53Discover_DNSSECEnabled(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIATEST")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secrettest")

	listZones := `<?xml version="1.0" encoding="UTF-8"?>
<ListHostedZonesResponse>
  <HostedZones>
    <HostedZone>
      <Id>/hostedzone/ZSEC</Id>
      <Name>secure.test</Name>
      <Config><PrivateZone>false</PrivateZone></Config>
      <ResourceRecordSetCount>0</ResourceRecordSetCount>
    </HostedZone>
  </HostedZones>
  <IsTruncated>false</IsTruncated>
</ListHostedZonesResponse>`

	emptyRRSets := `<?xml version="1.0" encoding="UTF-8"?>
<ListResourceRecordSetsResponse>
  <ResourceRecordSets></ResourceRecordSets>
  <IsTruncated>false</IsTruncated>
</ListResourceRecordSetsResponse>`

	dnssecOn := `<?xml version="1.0" encoding="UTF-8"?>
<GetDNSSECResponse>
  <Status><ServeSignature>SIGNING</ServeSignature></Status>
</GetDNSSECResponse>`

	srv, _ := route53MockServer(t, listZones, emptyRRSets, dnssecOn)

	r := NewDNSRoute53()
	r.baseURL = srv.URL
	r.httpClient = srv.Client()

	_, err := r.Discover(context.Background(), nil)
	require.NoError(t, err)
	snap := r.Snapshot()
	require.NotNil(t, snap)
	require.Len(t, snap.Zones, 1)
	assert.True(t, snap.Zones[0].DNSSECEnabled)
	assert.Equal(t, "secure.test.", snap.Zones[0].ZoneName, "missing trailing dot must be added")
}

func TestNormalizeZoneName(t *testing.T) {
	cases := map[string]string{
		"":              "",
		"example.com":   "example.com.",
		"example.com.":  "example.com.",
		"foo.bar.test.": "foo.bar.test.",
	}
	for in, want := range cases {
		assert.Equal(t, want, normalizeZoneName(in), "input=%q", in)
	}
}

func TestNormalizeRoute53HostedZoneID(t *testing.T) {
	cases := map[string]string{
		"/hostedzone/Z1ABCDEFG": "Z1ABCDEFG",
		"hostedzone/Z2XYZ":      "Z2XYZ",
		"Z3RAW":                 "Z3RAW",
		"":                      "",
	}
	for in, want := range cases {
		assert.Equal(t, want, normalizeRoute53HostedZoneID(in), "input=%q", in)
	}
}

func TestDeriveAWSAccountRef(t *testing.T) {
	assert.Equal(t, "aws", deriveAWSAccountRef(""))
	assert.Equal(t, "aws:AKIAEXAM...", deriveAWSAccountRef("AKIAEXAMPLE1234567890"))
	assert.Equal(t, "aws:short", deriveAWSAccountRef("short"))
}

func TestDeriveRoutingPolicy(t *testing.T) {
	cases := []struct {
		want string
		rec  route53ResourceRecordSet
	}{
		{want: "failover", rec: route53ResourceRecordSet{Failover: "PRIMARY"}},
		{want: "geolocation", rec: route53ResourceRecordSet{GeoLocation: &route53GeoLocation{CountryCode: "US"}}},
		{want: "latency", rec: route53ResourceRecordSet{Region: "us-east-1"}},
		{want: "weighted", rec: route53ResourceRecordSet{Weight: 10}},
		{want: "multivalue", rec: route53ResourceRecordSet{MultiValueAnswer: true}},
		{want: "", rec: route53ResourceRecordSet{}},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, deriveRoutingPolicy(c.rec))
	}
}

func TestRoute53_NameAndSnapshotBeforeDiscover(t *testing.T) {
	r := NewDNSRoute53()
	assert.Equal(t, "cloud_dns_route53", r.Name())
	assert.Nil(t, r.Snapshot(), "snapshot must be nil before Discover runs")
}
