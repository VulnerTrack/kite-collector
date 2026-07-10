// Package mdm provides discovery sources for Mobile Device Management and
// endpoint management platforms. Each source implements [discovery.Source]
// and enumerates managed devices as [model.Asset] values.
//
// Every connector in this package is built on
// [github.com/vulnertrack/kite-collector/internal/discovery/connectorkit]:
// the enabled gate (F3), credential loading with post-auth zeroing (R1),
// SSRF/TLS-validated HTTP clients (R3), and labelled pagination guarding.
package mdm

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/vulnertrack/kite-collector/internal/discovery/connectorkit"
)

const (
	// clientTimeout bounds every outbound request the test-override client
	// makes, matching the value connectorkit.SafeClient uses in production.
	clientTimeout = 30 * time.Second

	// maxResponseBody caps how many bytes are read from any single upstream
	// response, defending against a hostile or misbehaving API streaming an
	// unbounded body.
	maxResponseBody int64 = 10 << 20 // 10 MiB
)

// newValidatedClient returns the HTTP client and validated base URL a
// connector should use. When baseURL is non-empty (tests only) endpoint
// validation is skipped and a plain client is returned so httptest servers on
// http://127.0.0.1 are reachable — mirroring wazuh's baseURL override. In
// production baseURL is empty and connectorkit.SafeClient validates apiURL
// (rejecting non-HTTPS and, unless allowPrivate, private/loopback targets).
func newValidatedClient(sourceName, baseURL, apiURL string, allowPrivate bool) (*http.Client, *url.URL, error) {
	if baseURL != "" {
		u, err := url.Parse(baseURL)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", sourceName, err)
		}
		return &http.Client{Timeout: clientTimeout}, u, nil
	}
	client, u, err := connectorkit.SafeClient(sourceName, apiURL, allowPrivate)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", sourceName, err)
	}
	return client, u, nil
}

// normalizeUPN lowercases an MDM-reported primary user email/UPN and returns
// it only when it still contains "@" after trimming; malformed values are
// dropped (Section 6.3). Shared by the connectors that surface EnrolledUserUPN.
func normalizeUPN(email string) string {
	e := strings.ToLower(strings.TrimSpace(email))
	if strings.Contains(e, "@") {
		return e
	}
	return ""
}

// truncateBytes returns at most maxLen bytes from data as a string, appending
// an ellipsis when truncation occurred. Used to bound upstream error bodies
// echoed into wrapped errors.
func truncateBytes(data []byte, maxLen int) string {
	if len(data) <= maxLen {
		return string(data)
	}
	return string(data[:maxLen]) + "..."
}
