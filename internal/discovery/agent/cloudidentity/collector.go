package cloudidentity

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

// httpClient is the test seam — the production collector uses a
// short-timeout http.Client; tests inject a fake that satisfies the
// same interface.
type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// probeCollector runs the three IMDS probes serially. Order matters
// only when more than one probe responds — that shouldn't happen on a
// real cloud guest, but if it does we prefer in this order: AWS → Azure
// → GCP (alphabetical for determinism).
type probeCollector struct {
	client       httpClient
	awsMetaURL   string
	awsTokenURL  string
	azureURL     string
	gcpInstance  string
	gcpProjectID string
	timeout      time.Duration
}

// NewCollector returns the default cloud-identity probe collector with
// a 500ms per-probe timeout and the canonical link-local URLs.
func NewCollector() Collector {
	//#nosec G101 -- these are well-known cloud-provider instance-metadata URLs, not credentials
	return &probeCollector{
		client: &http.Client{
			Timeout: DefaultProbeTimeout,
		},
		awsMetaURL:   "http://169.254.169.254/latest/dynamic/instance-identity/document",
		awsTokenURL:  "http://169.254.169.254/latest/api/token",
		azureURL:     "http://169.254.169.254/metadata/instance?api-version=2023-07-01",
		gcpInstance:  "http://metadata.google.internal/computeMetadata/v1/instance/?recursive=true&alt=json",
		gcpProjectID: "http://metadata.google.internal/computeMetadata/v1/project/project-id",
		timeout:      DefaultProbeTimeout,
	}
}

func (c *probeCollector) Name() string { return "cloud-identity-probe" }

// Collect runs the AWS → Azure → GCP probe sequence and returns the
// first success. On-prem hosts return Info{CloudProvider:CloudNone}.
func (c *probeCollector) Collect(ctx context.Context) (Info, error) {
	if err := ctx.Err(); err != nil {
		return Info{}, fmt.Errorf("context cancelled: %w", err)
	}

	if info, ok := c.probeAWS(ctx); ok {
		return info, nil
	}
	if info, ok := c.probeAzure(ctx); ok {
		return info, nil
	}
	if info, ok := c.probeGCP(ctx); ok {
		return info, nil
	}
	return Info{
		CloudProvider: CloudNone,
		Source:        SourceNoProbe,
	}, nil
}

// probeAWS tries IMDSv2 first; falls back to IMDSv1 (unauthenticated
// GET against the same URL) when token issuance fails. The fallback
// itself is the IMDSv1-enabled signal — a host with IMDSv2-only mode
// returns 401 to the unauthenticated GET, which we treat as "no AWS".
func (c *probeCollector) probeAWS(ctx context.Context) (Info, bool) {
	body, ok, v2 := c.fetchAWS(ctx)
	if !ok {
		return Info{}, false
	}
	info, err := ParseAWSIdentityDocument(body)
	if err != nil {
		return Info{}, false
	}
	if v2 {
		info.Source = SourceAWSIMDSv2
		info.IMDSv2Required = true
	} else {
		info.Source = SourceAWSIMDSv1
		info.IMDSv2Required = false
	}
	return info, true
}

// fetchAWS returns (body, ok, v2). `v2=true` means the request was
// authenticated with a session token; `v2=false` means we fell back to
// the legacy unauthenticated path (and only succeeded because IMDSv1
// is still enabled — a security finding the audit pipeline flags).
func (c *probeCollector) fetchAWS(ctx context.Context) ([]byte, bool, bool) {
	// IMDSv2: PUT to get a session token.
	tokenReq, err := http.NewRequestWithContext(ctx, http.MethodPut, c.awsTokenURL, nil)
	if err == nil {
		tokenReq.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "21600")
		resp, terr := c.client.Do(tokenReq)
		if terr == nil {
			tokenBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<14))
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK && len(tokenBytes) > 0 {
				// IMDSv2 path with token.
				docReq, derr := http.NewRequestWithContext(ctx, http.MethodGet, c.awsMetaURL, nil)
				if derr == nil {
					docReq.Header.Set("X-aws-ec2-metadata-token", string(tokenBytes))
					if body, ok := c.do(docReq); ok {
						return body, true, true
					}
				}
			}
		}
	}
	// IMDSv1 fallback (unauthenticated GET).
	v1Req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.awsMetaURL, nil)
	if err != nil {
		return nil, false, false
	}
	if body, ok := c.do(v1Req); ok {
		return body, true, false
	}
	return nil, false, false
}

func (c *probeCollector) probeAzure(ctx context.Context) (Info, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.azureURL, nil)
	if err != nil {
		return Info{}, false
	}
	req.Header.Set("Metadata", "true")
	body, ok := c.do(req)
	if !ok {
		return Info{}, false
	}
	info, err := ParseAzureIMDS(body)
	if err != nil {
		return Info{}, false
	}
	return info, true
}

func (c *probeCollector) probeGCP(ctx context.Context) (Info, bool) {
	// Project-id first (small body, cheap probe).
	projReq, err := http.NewRequestWithContext(ctx, http.MethodGet, c.gcpProjectID, nil)
	if err != nil {
		return Info{}, false
	}
	projReq.Header.Set("Metadata-Flavor", "Google")
	projectBytes, ok := c.do(projReq)
	if !ok {
		return Info{}, false
	}
	instReq, err := http.NewRequestWithContext(ctx, http.MethodGet, c.gcpInstance, nil)
	if err != nil {
		return Info{}, false
	}
	instReq.Header.Set("Metadata-Flavor", "Google")
	body, ok := c.do(instReq)
	if !ok {
		return Info{}, false
	}
	info, err := ParseGCPMetadata(body, string(projectBytes))
	if err != nil {
		return Info{}, false
	}
	return info, true
}

// do executes a request and returns (body, ok). `ok=false` means the
// probe timed out, errored, or returned a non-2xx status. Body reads
// are bounded to 64 KiB.
func (c *probeCollector) do(req *http.Request) ([]byte, bool) {
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, false
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, false
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return nil, false
	}
	return body, true
}
