package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/vulnertrack/kite-collector/internal/model"
)

const osvBatchURL = "https://api.osv.dev/v1/querybatch"

// osvClient calls the OSV batch query API.
type osvClient struct {
	http    *http.Client
	baseURL string // overridable in tests
}

func newOSVClient(timeout time.Duration) *osvClient {
	return &osvClient{
		http:    &http.Client{Timeout: timeout},
		baseURL: osvBatchURL,
	}
}

// osvQuery is one entry in a batch request.
type osvQuery struct {
	Package osvPackage `json:"package"`
	Version string     `json:"version"`
}

type osvPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

// osvBatchRequest is the JSON body sent to /v1/querybatch.
type osvBatchRequest struct {
	Queries []osvQuery `json:"queries"`
}

// osvBatchResponse is the top-level response from /v1/querybatch.
type osvBatchResponse struct {
	Results []osvQueryResult `json:"results"`
}

type osvQueryResult struct {
	Vulns []osvVuln `json:"vulns"`
}

type osvVuln struct {
	DBSpec   map[string]any `json:"database_specific"`
	ID       string         `json:"id"`
	Summary  string         `json:"summary"`
	Aliases  []string       `json:"aliases"`
	Severity []osvSev       `json:"severity"`
	Affected []osvAffect    `json:"affected"`
}

type osvSev struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type osvAffect struct {
	Package osvPackage `json:"package"`
	Ranges  []osvRange `json:"ranges"`
}

type osvRange struct {
	Type   string     `json:"type"`
	Events []osvEvent `json:"events"`
}

type osvEvent struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
}

// QueryBatch sends up to len(deps) queries to OSV and returns one
// []osvVuln slice per dependency in the same order.
func (c *osvClient) QueryBatch(ctx context.Context, deps []Dependency) ([][]osvVuln, error) {
	if len(deps) == 0 {
		return nil, nil
	}

	queries := make([]osvQuery, len(deps))
	for i, d := range deps {
		queries[i] = osvQuery{
			Package: osvPackage{Name: d.Name, Ecosystem: d.Ecosystem},
			Version: d.Version,
		}
	}

	body, err := json.Marshal(osvBatchRequest{Queries: queries})
	if err != nil {
		return nil, fmt.Errorf("marshal osv request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build osv request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("osv api call: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("osv api returned %d", resp.StatusCode)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20)) // 10 MiB cap
	if err != nil {
		return nil, fmt.Errorf("read osv response: %w", err)
	}

	var result osvBatchResponse
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("parse osv response: %w", err)
	}

	// Align result length with query length; pad with empty slices on mismatch.
	out := make([][]osvVuln, len(deps))
	for i := range out {
		if i < len(result.Results) {
			out[i] = result.Results[i].Vulns
		}
	}
	return out, nil
}

// osvVulnSeverity maps an OSV vulnerability to a kite model.Severity using
// database_specific.severity first, then the CVSS v3 base score.
func osvVulnSeverity(v osvVuln) model.Severity {
	// Prefer the database-provided severity label.
	if ds, ok := v.DBSpec["severity"].(string); ok {
		switch strings.ToUpper(ds) {
		case "CRITICAL":
			return model.SeverityCritical
		case "HIGH":
			return model.SeverityHigh
		case "MODERATE", "MEDIUM":
			return model.SeverityMedium
		case "LOW":
			return model.SeverityLow
		}
	}

	// Fall back to CVSS v3 base score.
	for _, s := range v.Severity {
		if s.Type != "CVSS_V3" {
			continue
		}
		score := parseCVSSBaseScore(s.Score)
		switch {
		case score >= 9.0:
			return model.SeverityCritical
		case score >= 7.0:
			return model.SeverityHigh
		case score >= 4.0:
			return model.SeverityMedium
		default:
			return model.SeverityLow
		}
	}

	return model.SeverityMedium // default when no severity data
}

// parseCVSSBaseScore extracts the numeric base score from a CVSS v3 vector
// string ("CVSS:3.1/AV:N/AC:L/...") or a plain score string ("7.5").
func parseCVSSBaseScore(s string) float64 {
	// Plain score
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		return f
	}
	// Vector: the score is not embedded in the vector string itself.
	// OSV sometimes puts the plain score in the score field directly.
	return 0
}

// firstCVE returns the first CVE alias from an OSV vulnerability, or the OSV
// ID if no CVE alias exists.
func firstCVE(v osvVuln) string {
	for _, a := range v.Aliases {
		if strings.HasPrefix(a, "CVE-") {
			return a
		}
	}
	return v.ID
}

// fixedVersion returns the earliest "fixed" version from the affected ranges
// of a vulnerability, or an empty string if none is found.
func fixedVersion(v osvVuln) string {
	for _, a := range v.Affected {
		for _, r := range a.Ranges {
			for _, e := range r.Events {
				if e.Fixed != "" {
					return e.Fixed
				}
			}
		}
	}
	return ""
}
