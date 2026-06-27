package cloudidentity

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestPinnedCloudProviderStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(CloudAWS), "aws"},
		{string(CloudAzure), "azure"},
		{string(CloudGCP), "gcp"},
		{string(CloudOracle), "oracle"},
		{string(CloudDigitalOcean), "digitalocean"},
		{string(CloudHetzner), "hetzner"},
		{string(CloudLinode), "linode"},
		{string(CloudNone), "none"},
		{string(CloudUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("cloud_provider drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestPinnedSourceStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(SourceAWSIMDSv2), "aws-imdsv2"},
		{string(SourceAWSIMDSv1), "aws-imdsv1"},
		{string(SourceAzureIMDS), "azure-imds"},
		{string(SourceGCPMetadata), "gcp-metadata"},
		{string(SourceNoProbe), "no-probe"},
		{string(SourceUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("source drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestHashPayloadDeterministic(t *testing.T) {
	a := HashPayload([]byte(`{"foo":"bar"}`))
	b := HashPayload([]byte(`{"foo":"bar"}`))
	if a != b || len(a) != 64 {
		t.Fatalf("a=%q b=%q", a, b)
	}
}

func TestEncodeStringList(t *testing.T) {
	if EncodeStringList(nil) != "[]" {
		t.Fatal("nil")
	}
	if got := EncodeStringList([]string{"prod", "web"}); got != `["prod","web"]` {
		t.Fatalf("got %q", got)
	}
}

// -- ParseAWSIdentityDocument ----------------------------------------

func TestParseAWSIdentityDocumentTypical(t *testing.T) {
	body := []byte(`{
        "accountId": "123456789012",
        "instanceId": "i-0abcdef1234567890",
        "region": "us-east-1",
        "availabilityZone": "us-east-1a",
        "instanceType": "m5.large",
        "imageId": "ami-0abc1234",
        "privateIp": "10.0.1.42"
    }`)
	got, err := ParseAWSIdentityDocument(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.CloudProvider != CloudAWS {
		t.Fatalf("cloud_provider=%q", got.CloudProvider)
	}
	if got.InstanceID != "i-0abcdef1234567890" {
		t.Fatalf("instance_id=%q", got.InstanceID)
	}
	if got.AccountID != "123456789012" {
		t.Fatalf("account_id=%q", got.AccountID)
	}
	if got.Region != "us-east-1" || got.AvailabilityZone != "us-east-1a" {
		t.Fatalf("region/az=%q/%q", got.Region, got.AvailabilityZone)
	}
	if got.PrivateIP != "10.0.1.42" {
		t.Fatalf("private_ip=%q", got.PrivateIP)
	}
	if got.RawPayloadHash == "" {
		t.Fatal("hash must be populated")
	}
}

func TestParseAWSIdentityDocumentEmptyError(t *testing.T) {
	if _, err := ParseAWSIdentityDocument(nil); err == nil {
		t.Fatal("empty must error")
	}
}

func TestParseAWSIdentityDocumentMalformedError(t *testing.T) {
	if _, err := ParseAWSIdentityDocument([]byte("not json")); err == nil {
		t.Fatal("malformed must error")
	}
}

// -- ParseAzureIMDS --------------------------------------------------

func TestParseAzureIMDSTypical(t *testing.T) {
	body := []byte(`{
        "compute": {
            "vmId": "abcd1234-5678-9abc-def0-123456789abc",
            "subscriptionId": "11111111-2222-3333-4444-555555555555",
            "location": "eastus",
            "vmSize": "Standard_D4s_v5",
            "name": "vm-web-01",
            "resourceGroupName": "rg-web-prod",
            "zone": "1",
            "priority": "Regular",
            "storageProfile": {
                "imageReference": {
                    "publisher": "Canonical",
                    "offer": "0001-com-ubuntu-server-jammy",
                    "sku": "22_04-lts-gen2",
                    "version": "latest"
                }
            },
            "tagsList": [
                {"name": "env", "value": "prod"},
                {"name": "owner", "value": "platform"}
            ]
        },
        "network": {
            "interface": [{
                "macAddress": "001234ABCDEF",
                "ipv4": {
                    "ipAddress": [{
                        "privateIpAddress": "10.0.1.42",
                        "publicIpAddress": "20.30.40.50"
                    }],
                    "subnet": [{"address": "10.0.1.0", "prefix": "24"}]
                }
            }]
        }
    }`)
	got, err := ParseAzureIMDS(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.CloudProvider != CloudAzure {
		t.Fatalf("cloud_provider=%q", got.CloudProvider)
	}
	if got.InstanceID != "abcd1234-5678-9abc-def0-123456789abc" {
		t.Fatalf("instance_id=%q (Azure vmId)", got.InstanceID)
	}
	if got.AccountID != "11111111-2222-3333-4444-555555555555" {
		t.Fatalf("subscription=%q", got.AccountID)
	}
	if got.Region != "eastus" || got.AvailabilityZone != "1" {
		t.Fatalf("region/zone=%q/%q", got.Region, got.AvailabilityZone)
	}
	if got.ResourceGroup != "rg-web-prod" {
		t.Fatalf("rg=%q", got.ResourceGroup)
	}
	if got.PrivateIP != "10.0.1.42" || got.PublicIP != "20.30.40.50" {
		t.Fatalf("priv/pub=%q/%q", got.PrivateIP, got.PublicIP)
	}
	if got.VNetID != "10.0.1.0/24" {
		t.Fatalf("vnet_id=%q", got.VNetID)
	}
	if got.IsSpotInstance {
		t.Fatal("Regular priority must NOT flag spot")
	}
	if got.ImageID != "Canonical:0001-com-ubuntu-server-jammy:22_04-lts-gen2:latest" {
		t.Fatalf("image_id=%q", got.ImageID)
	}
	if len(got.Tags) != 2 || got.Tags[0] != "env=prod" {
		t.Fatalf("tags=%v", got.Tags)
	}
}

func TestParseAzureIMDSSpotPriority(t *testing.T) {
	body := []byte(`{"compute":{"vmId":"x","priority":"Spot"}}`)
	got, _ := ParseAzureIMDS(body)
	if !got.IsSpotInstance {
		t.Fatal("Spot priority must flag")
	}
}

// -- ParseGCPMetadata ------------------------------------------------

func TestParseGCPMetadataTypical(t *testing.T) {
	body := []byte(`{
        "id": 6549073297500000000,
        "name": "vm-web-01",
        "hostname": "vm-web-01.internal",
        "zone": "projects/123456789/zones/us-central1-a",
        "machineType": "projects/123456789/machineTypes/e2-standard-4",
        "image": "projects/debian-cloud/global/images/debian-12-bookworm-v20240515",
        "tags": ["web", "prod"],
        "networkInterfaces": [{
            "ip": "10.128.0.42",
            "network": "projects/123456789/networks/default",
            "accessConfigs": [{"externalIp": "34.122.55.66"}]
        }],
        "scheduling": {"preemptible": false}
    }`)
	got, err := ParseGCPMetadata(body, "my-project-prod")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.CloudProvider != CloudGCP {
		t.Fatalf("cloud_provider=%q", got.CloudProvider)
	}
	if got.AccountID != "my-project-prod" {
		t.Fatalf("project_id=%q", got.AccountID)
	}
	if got.InstanceID != "6549073297500000000" {
		t.Fatalf("instance_id=%q", got.InstanceID)
	}
	if got.AvailabilityZone != "us-central1-a" || got.Region != "us-central1" {
		t.Fatalf("zone/region=%q/%q", got.AvailabilityZone, got.Region)
	}
	if got.InstanceType != "e2-standard-4" {
		t.Fatalf("instance_type=%q", got.InstanceType)
	}
	if got.PrivateIP != "10.128.0.42" || got.PublicIP != "34.122.55.66" {
		t.Fatalf("priv/pub=%q/%q", got.PrivateIP, got.PublicIP)
	}
	if got.IsSpotInstance {
		t.Fatal("preemptible=false must NOT flag spot")
	}
}

func TestParseGCPMetadataPreemptible(t *testing.T) {
	body := []byte(`{
        "id": 1,
        "zone": "projects/p/zones/us-central1-a",
        "machineType": "projects/p/machineTypes/n2-standard-1",
        "scheduling": {"preemptible": true}
    }`)
	got, _ := ParseGCPMetadata(body, "test")
	if !got.IsSpotInstance {
		t.Fatal("preemptible must flag spot")
	}
}

func TestGcpShortName(t *testing.T) {
	cases := map[string]string{
		"projects/p/zones/us-central1-a":        "us-central1-a",
		"projects/p/machineTypes/e2-standard-4": "e2-standard-4",
		"":                                      "",
		"single":                                "single",
	}
	for in, want := range cases {
		if got := gcpShortName(in); got != want {
			t.Fatalf("gcpShortName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestGcpRegionFromZone(t *testing.T) {
	cases := map[string]string{
		"projects/p/zones/us-central1-a": "us-central1",
		"europe-west2-c":                 "europe-west2",
		"no-zone":                        "no",
		"":                               "",
	}
	for in, want := range cases {
		if got := gcpRegionFromZone(in); got != want {
			t.Fatalf("gcpRegionFromZone(%q) = %q, want %q", in, got, want)
		}
	}
}

// -- probeCollector orchestration ------------------------------------

// fakeHTTP is an httpClient that returns canned responses by URL.
type fakeHTTP struct {
	t        *testing.T
	resps    map[string]func(req *http.Request) (*http.Response, error)
	default_ func(req *http.Request) (*http.Response, error)
}

func newFakeHTTP(t *testing.T) *fakeHTTP {
	return &fakeHTTP{t: t, resps: map[string]func(req *http.Request) (*http.Response, error){}}
}

func (f *fakeHTTP) set(rawURL string, fn func(req *http.Request) (*http.Response, error)) {
	u, err := url.Parse(rawURL)
	if err != nil {
		f.t.Fatalf("bad url: %v", err)
	}
	key := u.Scheme + "://" + u.Host + u.Path
	f.resps[key] = fn
}

func (f *fakeHTTP) Do(req *http.Request) (*http.Response, error) {
	key := req.URL.Scheme + "://" + req.URL.Host + req.URL.Path
	if fn, ok := f.resps[key]; ok {
		return fn(req)
	}
	if f.default_ != nil {
		return f.default_(req)
	}
	return nil, fmt.Errorf("no fake for %s %s", req.Method, key)
}

func mkResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(bytes.NewBufferString(body)),
		Header:     http.Header{},
	}
}

func newProbeCollectorWith(client httpClient) *probeCollector {
	c, _ := NewCollector().(*probeCollector)
	c.client = client
	return c
}

func TestCollectAWSIMDSv2Success(t *testing.T) {
	doc := `{"accountId":"123456789012","instanceId":"i-abc","region":"us-east-1","availabilityZone":"us-east-1a","instanceType":"t3.micro","imageId":"ami-1","privateIp":"10.0.0.5"}`
	fh := newFakeHTTP(t)
	fh.set("http://169.254.169.254/latest/api/token", func(req *http.Request) (*http.Response, error) {
		if req.Method != http.MethodPut {
			t.Fatalf("token request must be PUT, got %s", req.Method)
		}
		if req.Header.Get("X-aws-ec2-metadata-token-ttl-seconds") == "" {
			t.Fatal("missing TTL header")
		}
		return mkResponse(200, "tok-123"), nil
	})
	fh.set("http://169.254.169.254/latest/dynamic/instance-identity/document",
		func(req *http.Request) (*http.Response, error) {
			if req.Header.Get("X-aws-ec2-metadata-token") != "tok-123" {
				t.Fatalf("missing token header on doc request: %#v", req.Header)
			}
			return mkResponse(200, doc), nil
		})
	c := newProbeCollectorWith(fh)
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if got.CloudProvider != CloudAWS {
		t.Fatalf("cloud=%q", got.CloudProvider)
	}
	if got.Source != SourceAWSIMDSv2 {
		t.Fatalf("source=%q", got.Source)
	}
	if !got.IMDSv2Required {
		t.Fatal("v2 success must flag imds_v2_required")
	}
	if got.InstanceID != "i-abc" {
		t.Fatalf("instance_id=%q", got.InstanceID)
	}
}

func TestCollectAWSIMDSv1FallbackFlagsRiskyConfig(t *testing.T) {
	doc := `{"accountId":"1","instanceId":"i-old","region":"us-west-2","privateIp":"10.0.0.1"}`
	fh := newFakeHTTP(t)
	// Token request fails → fall back to IMDSv1.
	fh.set("http://169.254.169.254/latest/api/token", func(req *http.Request) (*http.Response, error) {
		return mkResponse(404, ""), nil
	})
	// IMDSv1 GET succeeds without token.
	fh.set("http://169.254.169.254/latest/dynamic/instance-identity/document",
		func(req *http.Request) (*http.Response, error) {
			if req.Header.Get("X-aws-ec2-metadata-token") != "" {
				t.Fatal("v1 path must NOT carry a token")
			}
			return mkResponse(200, doc), nil
		})
	c := newProbeCollectorWith(fh)
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got.CloudProvider != CloudAWS || got.Source != SourceAWSIMDSv1 {
		t.Fatalf("source=%q cloud=%q", got.Source, got.CloudProvider)
	}
	if got.IMDSv2Required {
		t.Fatal("v1 fallback success means IMDSv2 NOT required (security finding)")
	}
}

func TestCollectAzureWinsWhenAWSFails(t *testing.T) {
	azureBody := `{"compute":{"vmId":"v1","subscriptionId":"s1","location":"eastus","vmSize":"Standard_B2s","name":"vm-1","resourceGroupName":"rg-1"}}`
	fh := newFakeHTTP(t)
	// AWS both v2 + v1 fail.
	fh.set("http://169.254.169.254/latest/api/token", func(req *http.Request) (*http.Response, error) {
		return mkResponse(403, ""), nil
	})
	fh.set("http://169.254.169.254/latest/dynamic/instance-identity/document",
		func(req *http.Request) (*http.Response, error) {
			return mkResponse(403, ""), nil
		})
	// Azure succeeds.
	fh.set("http://169.254.169.254/metadata/instance",
		func(req *http.Request) (*http.Response, error) {
			if req.Header.Get("Metadata") != "true" {
				t.Fatal("Azure probe must set Metadata: true")
			}
			return mkResponse(200, azureBody), nil
		})
	c := newProbeCollectorWith(fh)
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got.CloudProvider != CloudAzure {
		t.Fatalf("cloud=%q", got.CloudProvider)
	}
	if got.Source != SourceAzureIMDS {
		t.Fatalf("source=%q", got.Source)
	}
	if got.AccountID != "s1" {
		t.Fatalf("subscription=%q", got.AccountID)
	}
}

func TestCollectGCPWinsWhenAWSAndAzureFail(t *testing.T) {
	gcpInst := `{"id":42,"hostname":"vm","zone":"projects/p/zones/us-central1-a","machineType":"projects/p/machineTypes/e2-small","networkInterfaces":[{"ip":"10.0.0.1"}]}`
	fh := newFakeHTTP(t)
	fh.default_ = func(req *http.Request) (*http.Response, error) {
		return mkResponse(404, ""), nil
	}
	fh.set("http://metadata.google.internal/computeMetadata/v1/project/project-id",
		func(req *http.Request) (*http.Response, error) {
			if req.Header.Get("Metadata-Flavor") != "Google" {
				t.Fatal("GCP probe must set Metadata-Flavor: Google")
			}
			return mkResponse(200, "my-project"), nil
		})
	fh.set("http://metadata.google.internal/computeMetadata/v1/instance/",
		func(req *http.Request) (*http.Response, error) {
			return mkResponse(200, gcpInst), nil
		})
	c := newProbeCollectorWith(fh)
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got.CloudProvider != CloudGCP {
		t.Fatalf("cloud=%q", got.CloudProvider)
	}
	if got.AccountID != "my-project" {
		t.Fatalf("project=%q", got.AccountID)
	}
	if got.InstanceID != "42" {
		t.Fatalf("instance_id=%q", got.InstanceID)
	}
}

func TestCollectOnPremReturnsCloudNone(t *testing.T) {
	fh := newFakeHTTP(t)
	fh.default_ = func(req *http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("connect timeout")
	}
	c := newProbeCollectorWith(fh)
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("on-prem must NOT error: %v", err)
	}
	if got.CloudProvider != CloudNone {
		t.Fatalf("cloud=%q (must be none)", got.CloudProvider)
	}
	if got.Source != SourceNoProbe {
		t.Fatalf("source=%q (must be no-probe)", got.Source)
	}
}

func TestCollectRespectsCancelledContext(t *testing.T) {
	c := newProbeCollectorWith(newFakeHTTP(t))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := c.Collect(ctx)
	if err == nil {
		t.Fatal("expected cancellation error")
	}
	if !strings.Contains(err.Error(), "cancelled") {
		t.Fatalf("err=%v", err)
	}
}

// -- SortInfos -------------------------------------------------------

func TestSortInfosDeterministic(t *testing.T) {
	in := []Info{
		{CloudProvider: CloudGCP, InstanceID: "z"},
		{CloudProvider: CloudAWS, InstanceID: "b"},
		{CloudProvider: CloudAWS, InstanceID: "a"},
	}
	SortInfos(in)
	if in[0].CloudProvider != CloudAWS || in[0].InstanceID != "a" {
		t.Fatalf("first=%+v", in[0])
	}
	if in[2].CloudProvider != CloudGCP {
		t.Fatalf("last=%+v", in[2])
	}
}
