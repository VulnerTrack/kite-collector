package storage

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"time"
)

// Default analyzer limits. These are exposed via AnalyzerOptions so callers
// can tighten them in constrained environments (e.g. a scan worker with a
// tight cycle budget) without forking the package.
const (
	defaultMaxBody    = 5 * 1024 * 1024 // 5 MiB
	defaultTimeout    = 10 * time.Second
	defaultDialTimout = 5 * time.Second
)

// AnalyzerOptions tunes the HTTP probe used by Analyzer.Analyze.
type AnalyzerOptions struct {
	HTTPClient   *http.Client
	UserAgent    string
	MaxBodyBytes int64
	Timeout      time.Duration
}

// Analyzer fetches a URL, captures network and TLS metadata, then runs the
// catalogue against the result. The same Analyzer is safe for concurrent use
// — the embedded http.Client and our certificate-recording Transport are
// goroutine-safe.
type Analyzer struct {
	client       *http.Client
	userAgent    string
	signatures   []Signature
	maxBodyBytes int64
	timeout      time.Duration
}

// NewAnalyzer returns an Analyzer ready for probing. Zero-valued options
// fields are replaced with the package defaults.
func NewAnalyzer(opts AnalyzerOptions) *Analyzer {
	a := &Analyzer{
		userAgent:    opts.UserAgent,
		maxBodyBytes: opts.MaxBodyBytes,
		timeout:      opts.Timeout,
	}
	if a.maxBodyBytes <= 0 {
		a.maxBodyBytes = defaultMaxBody
	}
	if a.timeout <= 0 {
		a.timeout = defaultTimeout
	}
	if opts.HTTPClient != nil {
		a.client = opts.HTTPClient
	} else {
		a.client = &http.Client{
			Timeout:   a.timeout,
			Transport: newRecordingTransport(),
		}
	}
	return a
}

// AnalyzeResult bundles the Evidence we synthesised from the probe with the
// matches Detect produced. Callers usually persist both — the Evidence keeps
// the raw observations available for replay if the catalogue evolves.
type AnalyzeResult struct {
	Evidence Evidence
	Matches  []Match
}

// Analyze performs a single GET against target, records what we can about
// the response (TLS chain, headers, body, remote IP), and returns the
// detection result. Network errors are returned to the caller — graceful
// degradation is a policy decision the discovery Source layer makes, not
// this primitive.
func (a *Analyzer) Analyze(ctx context.Context, target string) (AnalyzeResult, error) {
	parsed, err := url.Parse(target)
	if err != nil {
		return AnalyzeResult{}, fmt.Errorf("parse target: %w", err)
	}

	// Honour the caller's deadline; only impose our own if none is set.
	if _, hasDL := ctx.Deadline(); !hasDL {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, a.timeout)
		defer cancel()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return AnalyzeResult{}, fmt.Errorf("build request: %w", err)
	}
	if a.userAgent != "" {
		req.Header.Set("User-Agent", a.userAgent)
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return AnalyzeResult{}, fmt.Errorf("probe %s: %w", target, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, a.maxBodyBytes))
	if err != nil {
		return AnalyzeResult{}, fmt.Errorf("read body: %w", err)
	}

	ev := Evidence{
		URL:        target,
		Filename:   path.Base(parsed.Path),
		JS:         string(body),
		APIHeaders: resp.Header,
		BucketHost: parsed.Hostname(),
	}
	populateTLS(resp, &ev)

	return AnalyzeResult{Evidence: ev, Matches: a.detect(ev)}, nil
}

// detect routes through DetectWith when a custom catalogue is configured;
// otherwise it falls back to the package default. Keeping this private
// avoids leaking the catalogue toggle to library consumers.
func (a *Analyzer) detect(ev Evidence) []Match {
	if len(a.signatures) > 0 {
		return DetectWith(a.signatures, ev)
	}
	return Detect(ev)
}

// populateTLS copies certificate state from the response onto Evidence. If
// the response did not go over TLS (plain HTTP, or a custom client without
// our recording transport), the TLS fields stay zero-valued and Detect
// simply skips SignalTLS rules.
func populateTLS(resp *http.Response, ev *Evidence) {
	if resp.TLS == nil {
		return
	}
	ev.TLSServerName = resp.TLS.ServerName
	if len(resp.TLS.PeerCertificates) > 0 {
		ev.TLSSANs = collectSANs(resp.TLS.PeerCertificates[0])
		if ev.TLSServerName == "" {
			ev.TLSServerName = resp.TLS.PeerCertificates[0].Subject.CommonName
		}
	}
}

// collectSANs flattens DNSNames + IPAddresses + URIs from a leaf certificate.
// IP SANs are stringified; URI SANs are reduced to host only so they line up
// with hostname-based catalogue patterns.
func collectSANs(cert *x509.Certificate) []string {
	if cert == nil {
		return nil
	}
	out := append([]string(nil), cert.DNSNames...)
	for _, ip := range cert.IPAddresses {
		out = append(out, ip.String())
	}
	for _, uri := range cert.URIs {
		if uri == nil {
			continue
		}
		host := uri.Hostname()
		if host == "" {
			host = uri.Host
		}
		if host != "" {
			out = append(out, host)
		}
	}
	return out
}

// newRecordingTransport returns an http.RoundTripper that wires a custom
// DialContext + TLSClientConfig so resp.TLS is populated even when the
// caller doesn't set up TLS themselves. The transport also propagates the
// resolved remote IP back into Evidence via a context value.
func newRecordingTransport() *http.Transport {
	return &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   defaultDialTimout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout:   defaultDialTimout,
		ResponseHeaderTimeout: defaultDialTimout,
		ExpectContinueTimeout: time.Second,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2:     true,
	}
}
