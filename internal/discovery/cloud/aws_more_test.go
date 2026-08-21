package cloud

// aws_more_test.go: coverage for the AWS EC2 source paths whose endpoints are
// hardcoded (regional EC2 Query API, STS AssumeRole) via the interceptHosts
// test transport, plus SigV4 canonicalization edge cases.

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/model"
)

const awsEC2XMLTwoInstances = `<?xml version="1.0" encoding="UTF-8"?>
<DescribeInstancesResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
  <reservationSet>
    <item>
      <instancesSet>
        <item>
          <instanceId>i-linux01</instanceId>
          <instanceState><name>running</name></instanceState>
          <tagSet>
            <item><key>Name</key><value>api-server</value></item>
          </tagSet>
        </item>
        <item>
          <instanceId>i-win01</instanceId>
          <platform>windows</platform>
          <instanceState><name>running</name></instanceState>
          <tagSet></tagSet>
        </item>
      </instancesSet>
    </item>
  </reservationSet>
</DescribeInstancesResponse>`

const awsSTSXML = `<?xml version="1.0" encoding="UTF-8"?>
<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleResult>
    <Credentials>
      <AccessKeyId>ASIAASSUMED</AccessKeyId>
      <SecretAccessKey>assumedSecret</SecretAccessKey>
      <SessionToken>assumedSession</SessionToken>
    </Credentials>
  </AssumeRoleResult>
</AssumeRoleResponse>`

// setAWSEnvCreds sets the standard AWS environment variables for the test.
func setAWSEnvCreds(t *testing.T, region string) {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIDSOURCE")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "sourceSecret")
	t.Setenv("AWS_SESSION_TOKEN", "")
	t.Setenv("AWS_REGION", region)
}

// awsEC2Handler serves a fixed DescribeInstances response and records the
// request body and headers for signing assertions.
func awsEC2Handler(xmlBody string, gotBody *string, gotAuth, gotSecTok *string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if gotBody != nil {
			_ = req.ParseForm()
			*gotBody = req.PostForm.Encode()
		}
		if gotAuth != nil {
			*gotAuth = req.Header.Get("Authorization")
		}
		if gotSecTok != nil {
			*gotSecTok = req.Header.Get("X-Amz-Security-Token")
		}
		w.Header().Set("Content-Type", "text/xml")
		_, _ = w.Write([]byte(xmlBody))
	})
}

func TestAWSName(t *testing.T) {
	assert.Equal(t, "aws_ec2", NewAWS().Name())
}

func TestTruncateBoundary(t *testing.T) {
	assert.Equal(t, "abcde", truncate("abcde", 5), "exactly at limit must not be truncated")
	assert.Equal(t, "abcde...", truncate("abcdef", 5))
	assert.Equal(t, "", truncate("", 5))
}

func TestCanonicalQueryString_Empty(t *testing.T) {
	u, err := url.Parse("https://ec2.us-east-1.amazonaws.com/")
	require.NoError(t, err)
	assert.Equal(t, "", canonicalQueryString(u))
}

func TestCanonicalQueryString_SortsKeysAndValues(t *testing.T) {
	u, err := url.Parse("https://example.com/?b=2&a=zz&a=aa&c=x%20y")
	require.NoError(t, err)
	assert.Equal(t, "a=aa&a=zz&b=2&c=x+y", canonicalQueryString(u),
		"keys and multi-values must be sorted, values query-escaped")
}

func TestCanonicalURI(t *testing.T) {
	assert.Equal(t, "/", canonicalURI(&url.URL{}), "empty path must canonicalize to /")
	assert.Equal(t, "/foo/bar", canonicalURI(&url.URL{Path: "/foo/bar"}))
}

func TestParseDescribeInstancesResponse_MalformedXML(t *testing.T) {
	_, err := parseDescribeInstancesResponse([]byte(`<unclosed`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parsing EC2 XML response")
}

func TestAWSDiscover_FullFlow(t *testing.T) {
	setAWSEnvCreds(t, "")
	var gotBody, gotAuth string
	interceptHosts(t, hostRoutes{
		"ec2.us-east-1.amazonaws.com": awsEC2Handler(awsEC2XMLTwoInstances, &gotBody, &gotAuth, nil),
	})

	machines, err := NewAWS().Discover(context.Background(), map[string]any{
		"regions": []any{"us-east-1"},
	})
	require.NoError(t, err)
	require.Len(t, machines, 2)

	assert.Equal(t, "api-server", machines[0].Hostname, "Name tag must win over instance id")
	assert.Equal(t, "linux", machines[0].OSFamily)
	assert.Equal(t, model.MachineTypeCloudInstance, machines[0].MachineType)
	assert.Equal(t, "aws_ec2", machines[0].DiscoverySource)
	assert.Equal(t, "us-east-1", machines[0].Environment)
	assert.Equal(t, model.AuthorizationUnknown, machines[0].IsAuthorized)
	assert.Equal(t, model.ManagedUnknown, machines[0].IsManaged)

	assert.Equal(t, "i-win01", machines[1].Hostname, "untagged instance falls back to instance id")
	assert.Equal(t, "windows", machines[1].OSFamily)

	assert.Contains(t, gotBody, "Action=DescribeInstances")
	assert.Contains(t, gotBody, "Filter.1.Name=instance-state-name")
	assert.Contains(t, gotBody, "Filter.1.Value.1=running")
	assert.Contains(t, gotAuth, "AWS4-HMAC-SHA256 Credential=AKIDSOURCE/")
	assert.Contains(t, gotAuth, "/us-east-1/ec2/aws4_request")
}

func TestAWSDiscover_DefaultRegionWhenUnset(t *testing.T) {
	setAWSEnvCreds(t, "")
	interceptHosts(t, hostRoutes{
		"ec2.us-east-1.amazonaws.com": awsEC2Handler(awsEC2XMLTwoInstances, nil, nil, nil),
	})

	machines, err := NewAWS().Discover(context.Background(), map[string]any{})
	require.NoError(t, err)
	assert.Len(t, machines, 2, "no regions configured must default to us-east-1")
}

func TestAWSDiscover_DefaultRegionFromEnv(t *testing.T) {
	setAWSEnvCreds(t, "eu-central-1")
	interceptHosts(t, hostRoutes{
		"ec2.eu-central-1.amazonaws.com": awsEC2Handler(awsEC2XMLTwoInstances, nil, nil, nil),
	})

	machines, err := NewAWS().Discover(context.Background(), map[string]any{})
	require.NoError(t, err)
	require.Len(t, machines, 2, "AWS_REGION must select the regional endpoint")
	assert.Equal(t, "eu-central-1", machines[0].Environment)
}

func TestAWSDiscover_AssumeRole(t *testing.T) {
	setAWSEnvCreds(t, "")
	var gotRoleArn, gotSession, gotAuth, gotSecTok string
	interceptHosts(t, hostRoutes{
		"sts.us-east-1.amazonaws.com": http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			_ = req.ParseForm()
			gotRoleArn = req.PostForm.Get("RoleArn")
			gotSession = req.PostForm.Get("RoleSessionName")
			w.Header().Set("Content-Type", "text/xml")
			_, _ = w.Write([]byte(awsSTSXML))
		}),
		"ec2.us-east-1.amazonaws.com": awsEC2Handler(awsEC2XMLTwoInstances, nil, &gotAuth, &gotSecTok),
	})

	machines, err := NewAWS().Discover(context.Background(), map[string]any{
		"regions":     []any{"us-east-1"},
		"assume_role": "arn:aws:iam::123456789012:role/scanner",
	})
	require.NoError(t, err)
	assert.Len(t, machines, 2)

	assert.Equal(t, "arn:aws:iam::123456789012:role/scanner", gotRoleArn)
	assert.Equal(t, "kite-collector", gotSession)
	assert.Contains(t, gotAuth, "Credential=ASIAASSUMED/",
		"EC2 call must be signed with the assumed-role access key")
	assert.Equal(t, "assumedSession", gotSecTok,
		"assumed-role session token must ride on X-Amz-Security-Token")
}

func TestAWSDiscover_AssumeRoleFailureFallsBack(t *testing.T) {
	setAWSEnvCreds(t, "")
	var gotAuth string
	interceptHosts(t, hostRoutes{
		"sts.us-east-1.amazonaws.com": http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("AccessDenied"))
		}),
		"ec2.us-east-1.amazonaws.com": awsEC2Handler(awsEC2XMLTwoInstances, nil, &gotAuth, nil),
	})

	machines, err := NewAWS().Discover(context.Background(), map[string]any{
		"regions":     []any{"us-east-1"},
		"assume_role": "arn:aws:iam::123456789012:role/denied",
	})
	require.NoError(t, err, "AssumeRole failure must degrade to source credentials")
	assert.Len(t, machines, 2)
	assert.Contains(t, gotAuth, "Credential=AKIDSOURCE/",
		"fallback must sign with the source access key")
}

func TestAWSDiscover_DescribeFailureReturnsPartial(t *testing.T) {
	setAWSEnvCreds(t, "")
	interceptHosts(t, hostRoutes{
		"ec2.us-east-1.amazonaws.com": http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("UnauthorizedOperation"))
		}),
		"ec2.eu-west-1.amazonaws.com": awsEC2Handler(awsEC2XMLTwoInstances, nil, nil, nil),
	})

	machines, err := NewAWS().Discover(context.Background(), map[string]any{
		"regions": []any{"us-east-1", "eu-west-1"},
	})
	require.NoError(t, err, "a failing region must not abort the scan")
	require.Len(t, machines, 2, "healthy region results must still be returned")
	assert.Equal(t, "eu-west-1", machines[0].Environment)
}

func TestAWSDiscover_NilConfigNoCredsSkips(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "")

	machines, err := NewAWS().Discover(context.Background(), nil)
	require.NoError(t, err)
	assert.Nil(t, machines)
}

func TestAWSDescribeInstances_MalformedXML(t *testing.T) {
	interceptHosts(t, hostRoutes{
		"ec2.us-east-1.amazonaws.com": http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`<broken`))
		}),
	})

	creds := awsCredentials{accessKey: "AK", secretKey: "SK"}
	_, err := NewAWS().describeInstances(context.Background(), creds, "us-east-1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parsing EC2 XML response")
}

func TestAWSAssumeRole_EmptyCredentials(t *testing.T) {
	emptyXML := `<?xml version="1.0"?>
<AssumeRoleResponse><AssumeRoleResult><Credentials></Credentials></AssumeRoleResult></AssumeRoleResponse>`
	interceptHosts(t, hostRoutes{
		"sts.us-west-2.amazonaws.com": http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(emptyXML))
		}),
	})

	creds := awsCredentials{accessKey: "AK", secretKey: "SK"}
	_, err := NewAWS().assumeRole(context.Background(), creds, "us-west-2", "arn:aws:iam::1:role/r")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty credentials")
}

func TestAWSAssumeRole_MalformedXML(t *testing.T) {
	interceptHosts(t, hostRoutes{
		"sts.us-west-2.amazonaws.com": http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`not xml at all`))
		}),
	})

	creds := awsCredentials{accessKey: "AK", secretKey: "SK"}
	_, err := NewAWS().assumeRole(context.Background(), creds, "us-west-2", "arn:aws:iam::1:role/r")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parsing STS response")
}

func TestAWSAssumeRole_Success(t *testing.T) {
	interceptHosts(t, hostRoutes{
		"sts.eu-west-1.amazonaws.com": http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(awsSTSXML))
		}),
	})

	creds := awsCredentials{accessKey: "AK", secretKey: "SK"}
	assumed, err := NewAWS().assumeRole(context.Background(), creds, "eu-west-1", "arn:aws:iam::1:role/r")
	require.NoError(t, err)
	assert.Equal(t, "ASIAASSUMED", assumed.accessKey)
	assert.Equal(t, "assumedSecret", assumed.secretKey)
	assert.Equal(t, "assumedSession", assumed.sessionToken)
	assert.Equal(t, "eu-west-1", assumed.region, "assumed credentials must carry the STS region")
}
