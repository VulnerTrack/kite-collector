// Package compositefingerprint orchestrates the per-mechanism
// fingerprint packages (tls, header, js, file, api) into one
// concurrent sweep against a single endpoint.
//
// Goal: a caller hands the package one (scheme, host, port) and
// receives back a CompositeResult with TLS / header / JS / file / API
// findings populated independently. Each mechanism runs in its own
// goroutine bounded by its own per-mechanism timeout, and the whole
// sweep honours a single ctx so the caller can cap total wall time
// regardless of how many mechanisms ran.
//
// Design notes:
//
//   - Sections are surfaced separately rather than merged. Cloudflare
//     might appear in tls (OCSP host), header (CF-Ray), and js
//     (some inline reference). Operators downstream consume the
//     unified Result and decide how to consolidate — the composite
//     scanner does not lose attribution by collapsing them.
//   - Disabling any mechanism is a single boolean on Options. Tests
//     and resource-constrained scans use that to skip the expensive
//     pieces (file probes, in particular, fan out to 60+ HTTP calls).
//   - TLS section is silently skipped when scheme != "https" — there
//     is nothing to probe on a plain HTTP endpoint.
//
// Read-only by inheritance: every underlying package is read-only by
// design, so this orchestrator inherits the same guarantee without
// extra effort.
package compositefingerprint

import (
	"github.com/vulnertrack/kite-collector/internal/discovery/network/apifingerprint"
	"github.com/vulnertrack/kite-collector/internal/discovery/network/filefingerprint"
	"github.com/vulnertrack/kite-collector/internal/discovery/network/headerfingerprint"
	"github.com/vulnertrack/kite-collector/internal/discovery/network/jsfingerprint"
	"github.com/vulnertrack/kite-collector/internal/discovery/network/tlsfingerprint"
)

// MechanismError pairs a per-mechanism failure with the section that
// produced it. Composite scans are best-effort: one mechanism's
// failure never blocks the others, but the caller can inspect Errors
// to understand what was incomplete.
type MechanismError struct {
	Mechanism string `json:"mechanism"`
	Message   string `json:"message"`
}

// CompositeResult collects per-mechanism outputs from one sweep. Any
// field can be nil when the mechanism was disabled, not applicable
// (TLS over plain HTTP), or failed; Errors carries the failure
// reasons for the latter so consumers can show "we tried but it
// timed out" rather than silently empty sections.
type CompositeResult struct {
	TLS      *tlsfingerprint.Result    `json:"tls,omitempty"`
	Header   *headerfingerprint.Result `json:"header,omitempty"`
	JS       *jsfingerprint.Result     `json:"js,omitempty"`
	File     *filefingerprint.Result   `json:"file,omitempty"`
	API      *apifingerprint.Result    `json:"api,omitempty"`
	Scheme   string                    `json:"scheme"`
	Host     string                    `json:"host"`
	Endpoint string                    `json:"endpoint"`
	Errors   []MechanismError          `json:"errors,omitempty"`
	Port     int                       `json:"port"`
}

// TotalFingerprints returns the sum of detections across all
// populated sections.
func (r *CompositeResult) TotalFingerprints() int {
	if r == nil {
		return 0
	}
	n := 0
	if r.TLS != nil {
		n += len(r.TLS.Fingerprints)
	}
	if r.Header != nil {
		n += len(r.Header.Fingerprints)
	}
	if r.JS != nil {
		n += len(r.JS.Fingerprints)
	}
	if r.File != nil {
		n += len(r.File.Findings)
	}
	if r.API != nil {
		n += len(r.API.Fingerprints)
	}
	return n
}
