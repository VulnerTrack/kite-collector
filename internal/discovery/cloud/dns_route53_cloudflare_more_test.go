package cloud

// dns_route53_cloudflare_more_test.go: pagination edges, routing/alias record
// mapping, DNSSEC error handling, and the assume-role branch for the Route53
// source, plus pagination and API-failure branches for the Cloudflare source.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Route53 ---------------------------------------------------------------

const route53EmptyRRSetsXML = `<?xml version="1.0"?>
<ListResourceRecordSetsResponse>
  <ResourceRecordSets></ResourceRecordSets>
  <IsTruncated>false</IsTruncated>
</ListResourceRecordSetsResponse>`

const route53DNSSECOffXML = `<?xml version="1.0"?>
<GetDNSSECResponse><Status><ServeSignature>NOT_SIGNING</ServeSignature></Status></GetDNSSECResponse>`

const route53OneZoneXML = `<?xml version="1.0"?>
<ListHostedZonesResponse>
  <HostedZones>
    <HostedZone>
      <Id>/hostedzone/ZONLY</Id>
      <Name>only.example.</Name>
      <Config><PrivateZone>false</PrivateZone></Config>
      <ResourceRecordSetCount>0</ResourceRecordSetCount>
    </HostedZone>
  </HostedZones>
  <IsTruncated>false</IsTruncated>
</ListHostedZonesResponse>`

func TestRoute53Discover_NilConfigNoCredsSkips(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "")

	r := NewDNSRoute53()
	machines, err := r.Discover(context.Background(), nil)
	require.NoError(t, err)
	assert.Nil(t, machines)
	assert.Nil(t, r.Snapshot())
}

func TestRoute53Discover_AssumeRoleUsesAssumedCredentials(t *testing.T) {
	setAWSEnvCreds(t, "")
	var gotRoleArn string
	interceptHosts(t, hostRoutes{
		"sts.us-east-1.amazonaws.com": http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			_ = req.ParseForm()
			gotRoleArn = req.PostForm.Get("RoleArn")
			w.Header().Set("Content-Type", "text/xml")
			_, _ = w.Write([]byte(awsSTSXML))
		}),
	})
	srv, _ := route53MockServer(t, route53OneZoneXML, route53EmptyRRSetsXML, route53DNSSECOffXML)

	r := NewDNSRoute53()
	r.baseURL = srv.URL
	r.httpClient = srv.Client()

	_, err := r.Discover(context.Background(), map[string]any{
		"assume_role": "arn:aws:iam::123456789012:role/dns-audit",
	})
	require.NoError(t, err)
	assert.Equal(t, "arn:aws:iam::123456789012:role/dns-audit", gotRoleArn)

	snap := r.Snapshot()
	require.NotNil(t, snap)
	require.Len(t, snap.Zones, 1)
	assert.Equal(t, "aws:ASIAASSU...", snap.Zones[0].AccountRef,
		"account ref must derive from the assumed-role access key")
}

func TestRoute53Discover_AssumeRoleFailureFallsBack(t *testing.T) {
	setAWSEnvCreds(t, "")
	interceptHosts(t, hostRoutes{
		"sts.us-east-1.amazonaws.com": http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("AccessDenied"))
		}),
	})
	srv, _ := route53MockServer(t, route53OneZoneXML, route53EmptyRRSetsXML, route53DNSSECOffXML)

	r := NewDNSRoute53()
	r.baseURL = srv.URL
	r.httpClient = srv.Client()

	_, err := r.Discover(context.Background(), map[string]any{
		"assume_role": "arn:aws:iam::123456789012:role/denied",
	})
	require.NoError(t, err, "AssumeRole failure must degrade to source credentials")

	snap := r.Snapshot()
	require.NotNil(t, snap)
	require.Len(t, snap.Zones, 1)
	assert.Equal(t, "aws:AKIDSOUR...", snap.Zones[0].AccountRef,
		"account ref must derive from the source access key on fallback")
}

func TestRoute53Discover_AliasUnsupportedAndDefaultTTL(t *testing.T) {
	setAWSEnvCreds(t, "")
	rrsets := `<?xml version="1.0"?>
<ListResourceRecordSetsResponse>
  <ResourceRecordSets>
    <ResourceRecordSet>
      <Name>alias.example.com.</Name>
      <Type>A</Type>
      <AliasTarget>
        <HostedZoneId>Z2FDTNDATAQYW2</HostedZoneId>
        <DNSName>d123.cloudfront.net.</DNSName>
        <EvaluateTargetHealth>false</EvaluateTargetHealth>
      </AliasTarget>
    </ResourceRecordSet>
    <ResourceRecordSet>
      <Name>odd.example.com.</Name>
      <Type>NAPTR</Type>
      <TTL>60</TTL>
      <ResourceRecords>
        <ResourceRecord><Value>x</Value></ResourceRecord>
      </ResourceRecords>
    </ResourceRecordSet>
  </ResourceRecordSets>
  <IsTruncated>false</IsTruncated>
</ListResourceRecordSetsResponse>`
	srv, _ := route53MockServer(t, route53OneZoneXML, rrsets, route53DNSSECOffXML)

	r := NewDNSRoute53()
	r.baseURL = srv.URL
	r.httpClient = srv.Client()

	_, err := r.Discover(context.Background(), map[string]any{})
	require.NoError(t, err)

	snap := r.Snapshot()
	require.NotNil(t, snap)
	require.Len(t, snap.Zones, 1)
	require.NotNil(t, snap.Zones[0].RecordCount)
	assert.Equal(t, 2, *snap.Zones[0].RecordCount, "count reflects fetched records, pre-filter")

	require.Len(t, snap.Records, 1, "unsupported NAPTR record must be filtered out")
	rec := snap.Records[0]
	assert.Equal(t, "alias.example.com.", rec.RecordName)
	assert.Equal(t, "A", rec.RecordType)
	assert.Equal(t, uint32(300), rec.TTL, "alias records without TTL must default to 300")
	assert.Equal(t, `["ALIAS:d123.cloudfront.net."]`, rec.ValuesJSON)
}

func TestRoute53Discover_RecordListFailureEmitsPartialZone(t *testing.T) {
	setAWSEnvCreds(t, "")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "text/xml")
		switch {
		case strings.HasSuffix(req.URL.Path, "/rrset"):
			w.WriteHeader(http.StatusBadRequest)
		case strings.HasSuffix(req.URL.Path, "/dnssec"):
			_, _ = w.Write([]byte(route53DNSSECOffXML))
		default:
			_, _ = w.Write([]byte(route53OneZoneXML))
		}
	}))
	t.Cleanup(srv.Close)

	r := NewDNSRoute53()
	r.baseURL = srv.URL
	r.httpClient = srv.Client()

	_, err := r.Discover(context.Background(), map[string]any{})
	require.NoError(t, err, "record-set failure must degrade to partial zone data")

	snap := r.Snapshot()
	require.NotNil(t, snap)
	require.Len(t, snap.Zones, 1)
	require.NotNil(t, snap.Zones[0].RecordCount)
	assert.Equal(t, 0, *snap.Zones[0].RecordCount)
	assert.Empty(t, snap.Records)
}

func TestRoute53Discover_DNSSECAuthErrorDefaultsDisabled(t *testing.T) {
	setAWSEnvCreds(t, "")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "text/xml")
		switch {
		case strings.HasSuffix(req.URL.Path, "/dnssec"):
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("denied"))
		case strings.HasSuffix(req.URL.Path, "/rrset"):
			_, _ = w.Write([]byte(route53EmptyRRSetsXML))
		default:
			_, _ = w.Write([]byte(route53OneZoneXML))
		}
	}))
	t.Cleanup(srv.Close)

	r := NewDNSRoute53()
	r.baseURL = srv.URL
	r.httpClient = srv.Client()

	_, err := r.Discover(context.Background(), map[string]any{})
	require.NoError(t, err)

	snap := r.Snapshot()
	require.NotNil(t, snap)
	require.Len(t, snap.Zones, 1)
	assert.False(t, snap.Zones[0].DNSSECEnabled,
		"an auth error on GetDNSSEC must default the zone to DNSSEC-disabled")
}

func TestRoute53GetDNSSECStatus(t *testing.T) {
	creds := awsCredentials{accessKey: "AK", secretKey: "SK"}

	t.Run("non-auth error treated as not configured", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("NoSuchKeySigningKey"))
		}))
		t.Cleanup(srv.Close)

		r := NewDNSRoute53()
		r.baseURL = srv.URL
		r.httpClient = srv.Client()

		enabled, err := r.getDNSSECStatus(context.Background(), creds, "ZX")
		require.NoError(t, err)
		assert.False(t, enabled)
	})

	t.Run("auth error propagates", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		}))
		t.Cleanup(srv.Close)

		r := NewDNSRoute53()
		r.baseURL = srv.URL
		r.httpClient = srv.Client()

		_, err := r.getDNSSECStatus(context.Background(), creds, "ZX")
		require.Error(t, err)
		var ae *authError
		assert.ErrorAs(t, err, &ae)
	})

	t.Run("malformed XML errors", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("<broken"))
		}))
		t.Cleanup(srv.Close)

		r := NewDNSRoute53()
		r.baseURL = srv.URL
		r.httpClient = srv.Client()

		_, err := r.getDNSSECStatus(context.Background(), creds, "ZX")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "parse")
	})
}

func TestRoute53ListHostedZones_PaginatesViaMarker(t *testing.T) {
	page1 := `<?xml version="1.0"?>
<ListHostedZonesResponse>
  <HostedZones>
    <HostedZone><Id>/hostedzone/Z1</Id><Name>one.example.</Name>
      <Config><PrivateZone>false</PrivateZone></Config></HostedZone>
  </HostedZones>
  <IsTruncated>true</IsTruncated>
  <NextMarker>m2</NextMarker>
</ListHostedZonesResponse>`
	page2 := `<?xml version="1.0"?>
<ListHostedZonesResponse>
  <HostedZones>
    <HostedZone><Id>/hostedzone/Z2</Id><Name>two.example.</Name>
      <Config><PrivateZone>true</PrivateZone></Config></HostedZone>
  </HostedZones>
  <IsTruncated>false</IsTruncated>
</ListHostedZonesResponse>`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "text/xml")
		if req.URL.Query().Get("marker") == "m2" {
			_, _ = w.Write([]byte(page2))
			return
		}
		_, _ = w.Write([]byte(page1))
	}))
	t.Cleanup(srv.Close)

	r := NewDNSRoute53()
	r.baseURL = srv.URL
	r.httpClient = srv.Client()

	zones, err := r.listHostedZones(context.Background(), awsCredentials{accessKey: "AK", secretKey: "SK"})
	require.NoError(t, err)
	require.Len(t, zones, 2, "NextMarker must drive the second page fetch")
	assert.Equal(t, "/hostedzone/Z1", zones[0].ID)
	assert.Equal(t, "/hostedzone/Z2", zones[1].ID)
	assert.True(t, zones[1].Config.PrivateZone)
}

func TestRoute53ListHostedZones_MalformedXML(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("this is not xml"))
	}))
	t.Cleanup(srv.Close)

	r := NewDNSRoute53()
	r.baseURL = srv.URL
	r.httpClient = srv.Client()

	_, err := r.listHostedZones(context.Background(), awsCredentials{accessKey: "AK", secretKey: "SK"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parsing response")
}

func TestRoute53ListResourceRecordSets_PaginatesViaNextRecord(t *testing.T) {
	page1 := `<?xml version="1.0"?>
<ListResourceRecordSetsResponse>
  <ResourceRecordSets>
    <ResourceRecordSet>
      <Name>a.example.com.</Name><Type>A</Type><TTL>300</TTL>
      <ResourceRecords><ResourceRecord><Value>192.0.2.1</Value></ResourceRecord></ResourceRecords>
    </ResourceRecordSet>
  </ResourceRecordSets>
  <IsTruncated>true</IsTruncated>
  <NextRecordName>b.example.com.</NextRecordName>
  <NextRecordType>CNAME</NextRecordType>
  <NextRecordIdentifier>set-1</NextRecordIdentifier>
</ListResourceRecordSetsResponse>`
	page2 := `<?xml version="1.0"?>
<ListResourceRecordSetsResponse>
  <ResourceRecordSets>
    <ResourceRecordSet>
      <Name>b.example.com.</Name><Type>CNAME</Type><TTL>60</TTL>
      <SetIdentifier>set-1</SetIdentifier>
      <ResourceRecords><ResourceRecord><Value>a.example.com.</Value></ResourceRecord></ResourceRecords>
    </ResourceRecordSet>
  </ResourceRecordSets>
  <IsTruncated>false</IsTruncated>
</ListResourceRecordSetsResponse>`
	var gotSecondPageQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "text/xml")
		if req.URL.Query().Get("name") != "" {
			gotSecondPageQuery = req.URL.RawQuery
			_, _ = w.Write([]byte(page2))
			return
		}
		_, _ = w.Write([]byte(page1))
	}))
	t.Cleanup(srv.Close)

	r := NewDNSRoute53()
	r.baseURL = srv.URL
	r.httpClient = srv.Client()

	records, err := r.listResourceRecordSets(context.Background(),
		awsCredentials{accessKey: "AK", secretKey: "SK"}, "ZPAGED")
	require.NoError(t, err)
	require.Len(t, records, 2)
	assert.Equal(t, "a.example.com.", records[0].Name)
	assert.Equal(t, "b.example.com.", records[1].Name)
	assert.Equal(t, "name=b.example.com.&type=CNAME&identifier=set-1", gotSecondPageQuery,
		"continuation query must carry name, type, and identifier")
}

func TestRoute53ListResourceRecordSets_MalformedXML(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<broken"))
	}))
	t.Cleanup(srv.Close)

	r := NewDNSRoute53()
	r.baseURL = srv.URL
	r.httpClient = srv.Client()

	_, err := r.listResourceRecordSets(context.Background(),
		awsCredentials{accessKey: "AK", secretKey: "SK"}, "ZBAD")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse")
}

// --- Cloudflare ------------------------------------------------------------

func TestCloudflareListZones_PaginatesAndFilters(t *testing.T) {
	page1 := `{"success":true,"errors":[],"result":[{"id":"z1","name":"one.example",` +
		`"account":{"id":"acct-1"},"plan":{"name":"Free"}}],` +
		`"result_info":{"page":1,"per_page":50,"total_pages":2}}`
	page2 := `{"success":true,"errors":[],"result":[{"id":"z2","name":"two.example",` +
		`"account":{"id":"acct-1"},"plan":{"name":"Free"}}],` +
		`"result_info":{"page":2,"per_page":50,"total_pages":2}}`
	var gotAccountFilter string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		gotAccountFilter = req.URL.Query().Get("account.id")
		if req.URL.Query().Get("page") == "2" {
			_, _ = w.Write([]byte(page2))
			return
		}
		_, _ = w.Write([]byte(page1))
	}))
	t.Cleanup(srv.Close)

	c := NewDNSCloudflare()
	c.baseURL = srv.URL
	c.httpClient = srv.Client()

	zones, err := c.listZones(context.Background(), "tok", "acct-1")
	require.NoError(t, err)
	require.Len(t, zones, 2, "total_pages must drive the second page fetch")
	assert.Equal(t, "z1", zones[0].ID)
	assert.Equal(t, "z2", zones[1].ID)
	assert.Equal(t, "acct-1", gotAccountFilter, "account scope filter must ride on the query")
}

func TestCloudflareListZones_APIFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"success":false,"errors":[{"message":"Invalid access token"}],"result":[]}`))
	}))
	t.Cleanup(srv.Close)

	c := NewDNSCloudflare()
	c.baseURL = srv.URL
	c.httpClient = srv.Client()

	_, err := c.listZones(context.Background(), "tok", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "zones api failure")
}

func TestCloudflareListZones_MalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{{`))
	}))
	t.Cleanup(srv.Close)

	c := NewDNSCloudflare()
	c.baseURL = srv.URL
	c.httpClient = srv.Client()

	_, err := c.listZones(context.Background(), "tok", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "zones parse")
}

func TestCloudflareListRecords_Paginates(t *testing.T) {
	page1 := `{"success":true,"errors":[],"result":[{"id":"r1","type":"A","name":"one.example",` +
		`"content":"192.0.2.1","ttl":300}],` +
		`"result_info":{"page":1,"per_page":50,"total_pages":2}}`
	page2 := `{"success":true,"errors":[],"result":[{"id":"r2","type":"TXT","name":"one.example",` +
		`"content":"v=spf1 -all","ttl":120}],` +
		`"result_info":{"page":2,"per_page":50,"total_pages":2}}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if req.URL.Query().Get("page") == "2" {
			_, _ = w.Write([]byte(page2))
			return
		}
		_, _ = w.Write([]byte(page1))
	}))
	t.Cleanup(srv.Close)

	c := NewDNSCloudflare()
	c.baseURL = srv.URL
	c.httpClient = srv.Client()

	records, err := c.listRecords(context.Background(), "tok", "z1")
	require.NoError(t, err)
	require.Len(t, records, 2)
	assert.Equal(t, "A", records[0].Type)
	assert.Equal(t, "TXT", records[1].Type)
}

func TestCloudflareListRecords_APIFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"success":false,"errors":[{"message":"forbidden"}],"result":[]}`))
	}))
	t.Cleanup(srv.Close)

	c := NewDNSCloudflare()
	c.baseURL = srv.URL
	c.httpClient = srv.Client()

	_, err := c.listRecords(context.Background(), "tok", "z1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "records api failure")
}

func TestCloudflareListRecords_MalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`]`))
	}))
	t.Cleanup(srv.Close)

	c := NewDNSCloudflare()
	c.baseURL = srv.URL
	c.httpClient = srv.Client()

	_, err := c.listRecords(context.Background(), "tok", "z1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "records parse")
}

func TestCloudflareListRecords_AuthError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("no"))
	}))
	t.Cleanup(srv.Close)

	c := NewDNSCloudflare()
	c.baseURL = srv.URL
	c.httpClient = srv.Client()

	_, err := c.listRecords(context.Background(), "tok", "z1")
	require.Error(t, err)
	var ae *authError
	assert.ErrorAs(t, err, &ae)
}

func TestCloudflareDiscover_ZoneListFailure(t *testing.T) {
	t.Setenv("CF_API_TOKEN", "test-token")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)

	c := NewDNSCloudflare()
	c.baseURL = srv.URL
	c.httpClient = srv.Client()

	_, err := c.Discover(context.Background(), map[string]any{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cloud_dns_cloudflare")
	assert.Nil(t, c.Snapshot())
}

func TestCloudflareDiscover_RecordListFailureEmitsPartialZone(t *testing.T) {
	t.Setenv("CF_API_TOKEN", "test-token")
	zones := `{"success":true,"errors":[],"result":[{"id":"zhalf","name":"half.example",` +
		`"account":{"id":"acct-9"},"plan":{"name":"Free"}}],` +
		`"result_info":{"page":1,"per_page":50,"total_pages":1}}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(req.URL.Path, "/dns_records") {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte(zones))
	}))
	t.Cleanup(srv.Close)

	c := NewDNSCloudflare()
	c.baseURL = srv.URL
	c.httpClient = srv.Client()

	_, err := c.Discover(context.Background(), map[string]any{})
	require.NoError(t, err, "record failure must degrade to partial zone data")

	snap := c.Snapshot()
	require.NotNil(t, snap)
	require.Len(t, snap.Zones, 1)
	assert.Equal(t, "cloudflare:acct-9", snap.Zones[0].AccountRef)
	require.NotNil(t, snap.Zones[0].RecordCount)
	assert.Equal(t, 0, *snap.Zones[0].RecordCount)
	assert.Empty(t, snap.Records)
}
