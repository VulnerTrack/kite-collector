package intranetweb

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// DefaultProbeTimeout is the per-target wall-clock budget. We keep
// this small (LAN, not the wide internet) so a /24 sweep finishes
// in seconds rather than minutes.
const DefaultProbeTimeout = 2 * time.Second

// DefaultMaxBodyBytes caps the response body we read into memory for
// title + directory-listing sniffing. 64 KiB covers every Bootstrap
// landing page and most appliance UIs.
const DefaultMaxBodyBytes = 64 * 1024

// HTTPProbe issues GET / against a single target with the supplied
// scheme. Returns a populated Endpoint on success; (nil, err) when the
// connection failed entirely (caller will simply not record a row).
//
// The caller picks the scheme — the probe never falls back between
// http and https on its own (that would double the LAN traffic). To
// probe both, call this twice from the collector.
type HTTPProbe struct {
	// LookupAddr does reverse-DNS resolution when Target.Host is empty
	// (mDNS/SSDP/subnet-sweep discoveries that bypass /etc/hosts). When
	// nil the probe uses net.DefaultResolver.LookupAddr. Tests inject a
	// stub to avoid hitting real DNS. Return the first PTR record; the
	// probe strips the trailing dot.
	LookupAddr   func(ctx context.Context, ip string) ([]string, error)
	Timeout      time.Duration
	MaxBodyBytes int64
}

// DefaultReverseLookupTimeout caps reverse-DNS wall-clock budget so a
// stalled resolver can't bleed the per-probe budget. Reverse PTR is
// best-effort — we'd rather skip the lookup than block the probe.
const DefaultReverseLookupTimeout = 500 * time.Millisecond

// Probe runs the GET and returns the populated Endpoint.
func (p HTTPProbe) Probe(ctx context.Context, scheme Scheme, t Target) (Endpoint, error) {
	timeout := p.Timeout
	if timeout <= 0 {
		timeout = DefaultProbeTimeout
	}
	maxBody := p.MaxBodyBytes
	if maxBody <= 0 {
		maxBody = DefaultMaxBodyBytes
	}

	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	tr := &http.Transport{
		// InsecureSkipVerify is intentional: the whole point is to
		// inspect cert chains that browsers warn on. We never reuse
		// the connection for anything beyond fingerprinting.
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, //#nosec G402 -- intentional; collector inspects untrusted intranet certs
			MinVersion:         tls.VersionTLS10,
		},
		DialContext: (&net.Dialer{
			Timeout: timeout,
		}).DialContext,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		IdleConnTimeout:       time.Second,
		DisableKeepAlives:     true,
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			// Never follow redirects — the redirect target is a separate
			// endpoint that the resolver should have surfaced on its own.
			return http.ErrUseLastResponse
		},
	}
	defer client.CloseIdleConnections()

	// requestHost goes on the wire as the HTTP Host header so vhost
	// servers reply with their real banner. We can't use the
	// TLS-extracted hostname here (it's only available AFTER the
	// handshake) — IP is the safest cheap default.
	requestHost := t.Host
	if requestHost == "" {
		requestHost = t.IP
	}
	u := fmt.Sprintf("%s://%s/", scheme, net.JoinHostPort(t.IP, strconv.Itoa(t.Port)))
	req, err := http.NewRequestWithContext(probeCtx, http.MethodGet, u, nil)
	if err != nil {
		return Endpoint{}, fmt.Errorf("build request: %w", err)
	}
	req.Host = requestHost
	req.Header.Set("User-Agent", "kite-collector/intranet-web (read-only probe)")
	req.Header.Set("Accept", "text/html,*/*;q=0.5")

	resp, err := client.Do(req)
	if err != nil {
		return Endpoint{}, fmt.Errorf("probe %s: %w", u, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))

	ep := Endpoint{
		Scheme:          scheme,
		IP:              t.IP,
		Port:            t.Port,
		DiscoverySource: nonEmptySource(t.Source),
		StatusCode:      resp.StatusCode,
		ServerHeader:    truncate(resp.Header.Get("Server"), 256),
		ContentType:     truncate(resp.Header.Get("Content-Type"), 256),
		PoweredBy:       truncate(resp.Header.Get("X-Powered-By"), 256),
		AuthScheme:      authSchemeFrom(resp),
		Title:           truncate(extractTitle(body), 256),
		IsCleartext:     scheme == SchemeHTTP,
	}
	ep.IsDirectoryListing = IsDirectoryListingBody(body)
	ep.IsDefaultPage = IsDefaultLandingTitle(ep.Title)

	if scheme == SchemeHTTPS && resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		leaf := resp.TLS.PeerCertificates[0]
		ep.TLSSubject = truncate(leaf.Subject.String(), 512)
		ep.TLSIssuer = truncate(leaf.Issuer.String(), 512)
		ep.TLSNotAfter = leaf.NotAfter.UTC().Format(time.RFC3339)
		ep.TLSFingerprintSHA256 = fingerprint(leaf)
		ep.TLSSelfSigned = isSelfSigned(leaf)
		ep.TLSExpired = time.Now().After(leaf.NotAfter)
	}

	// Layered host derivation, in priority order:
	//   1. Target.Host  — explicit (hosts-file / mDNS PTR / manual).
	//   2. TLS cert SAN — protocol-grade name the server self-asserts.
	//   3. TLS cert CN  — fallback when SAN is empty (legacy certs).
	//   4. Reverse-DNS  — PTR record (best-effort, may stall).
	//   5. Target.IP    — guaranteed non-empty last resort.
	ep.Host = p.deriveHost(ctx, t, resp)

	ep.PageHash = HashPage(ep.StatusCode, ep.ServerHeader, ep.ContentType, ep.Title)
	return ep, nil
}

// HostSignal identifies *which* source produced an endpoint hostname.
// The order here is also the reliability ranking — the higher-tier
// signal wins when multiple sources are available.
//
// Reliability ranking (highest → lowest):
//
//  1. HostSignalExplicit   — operator-curated, no network round-trip.
//  2. HostSignalTLSSAN     — server self-asserted hostname, browser-trusted.
//  3. HostSignalTLSCN      — legacy cert hostname, pre-RFC-6125.
//  4. HostSignalReverseDNS — third-party PTR record, can lag / be wrong.
//  5. HostSignalIP         — synthetic fallback; not a hostname at all.
type HostSignal string

const (
	HostSignalExplicit   HostSignal = "explicit"
	HostSignalTLSSAN     HostSignal = "tls-san"
	HostSignalTLSCN      HostSignal = "tls-cn"
	HostSignalReverseDNS HostSignal = "reverse-dns"
	HostSignalIP         HostSignal = "ip-fallback"
)

// deriveHost picks the best hostname for an Endpoint following the
// HostSignal reliability ranking. Returns (host, signal) so callers
// can persist *why* this name was chosen.
func (p HTTPProbe) deriveHost(ctx context.Context, t Target, resp *http.Response) string {
	h, _ := p.deriveHostWithSignal(ctx, t, resp)
	return h
}

func (p HTTPProbe) deriveHostWithSignal(ctx context.Context, t Target, resp *http.Response) (string, HostSignal) {
	if h := strings.TrimSpace(t.Host); h != "" {
		return h, HostSignalExplicit
	}
	if h, sig := hostFromTLSResponseTier(resp, t.IP); h != "" {
		return h, sig
	}
	if h := p.reverseLookup(ctx, t.IP); h != "" {
		return h, HostSignalReverseDNS
	}
	return t.IP, HostSignalIP
}

// hostFromTLSResponseTier extracts the best protocol-asserted hostname
// from the leaf TLS certificate and tags it with the producing signal.
// SAN DNSNames win over CN per RFC 6125. Skip wildcards
// (`*.example.com`) — they don't name a single host. Skip values that
// equal the IP. Returns ("", "") when the response is not TLS or the
// cert carries no usable name.
func hostFromTLSResponseTier(resp *http.Response, ip string) (string, HostSignal) {
	if resp == nil || resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
		return "", ""
	}
	leaf := resp.TLS.PeerCertificates[0]
	for _, dns := range leaf.DNSNames {
		name := strings.TrimSpace(dns)
		if name == "" || strings.HasPrefix(name, "*") {
			continue
		}
		if name == ip {
			continue
		}
		return name, HostSignalTLSSAN
	}
	cn := strings.TrimSpace(leaf.Subject.CommonName)
	if cn == "" || strings.HasPrefix(cn, "*") || cn == ip {
		return "", ""
	}
	return cn, HostSignalTLSCN
}

// reverseLookup returns the first PTR record for ip, stripped of the
// trailing dot. Empty string when the IP doesn't parse, when no PTR
// record is published, or when the resolver times out. Reverse-DNS is
// best-effort: a stalled lookup must never block the probe.
func (p HTTPProbe) reverseLookup(ctx context.Context, ip string) string {
	if ip == "" || net.ParseIP(ip) == nil {
		return ""
	}
	lookup := p.LookupAddr
	if lookup == nil {
		lookup = net.DefaultResolver.LookupAddr
	}
	lookupCtx, cancel := context.WithTimeout(ctx, DefaultReverseLookupTimeout)
	defer cancel()
	names, err := lookup(lookupCtx, ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	name := strings.TrimSuffix(strings.TrimSpace(names[0]), ".")
	return name
}

func nonEmptySource(s DiscoverySource) DiscoverySource {
	if s == "" {
		return SourceUnknown
	}
	return s
}

func fingerprint(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return hex.EncodeToString(sum[:])
}

// isSelfSigned reports whether the cert lists itself as its issuer.
// We don't run a full chain verify because intranet PKI is wildly
// inconsistent — DN equality is the universal signal browsers also use.
func isSelfSigned(c *x509.Certificate) bool {
	if c == nil {
		return false
	}
	if c.Subject.String() != c.Issuer.String() {
		return false
	}
	// Belt-and-suspenders: confirm the signature actually verifies
	// against the public key inside the same cert. If CheckSignatureFrom
	// errors with an unsupported algorithm we still report self-signed
	// based on the DN match — better to flag than miss.
	if err := c.CheckSignatureFrom(c); err != nil &&
		!errors.Is(err, x509.ErrUnsupportedAlgorithm) {
		return false
	}
	return true
}

func authSchemeFrom(resp *http.Response) string {
	if resp.StatusCode != http.StatusUnauthorized {
		return ""
	}
	h := resp.Header.Get("WWW-Authenticate")
	if h == "" {
		return ""
	}
	// Take just the scheme keyword (e.g. "Basic", "Bearer").
	parts := strings.Fields(h)
	if len(parts) == 0 {
		return ""
	}
	return truncate(parts[0], 32)
}

// titleRE captures the inner text of the first <title> element. We use
// a deliberately permissive regex because intranet appliances ship
// quasi-HTML that often violates the spec.
var titleRE = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

func extractTitle(body []byte) string {
	m := titleRE.FindSubmatch(body)
	if len(m) < 2 {
		return ""
	}
	// Decode the most common entities we'll see in intranet banners.
	t := string(m[1])
	t = strings.ReplaceAll(t, "&amp;", "&")
	t = strings.ReplaceAll(t, "&lt;", "<")
	t = strings.ReplaceAll(t, "&gt;", ">")
	t = strings.ReplaceAll(t, "&quot;", `"`)
	t = strings.ReplaceAll(t, "&#39;", "'")
	t = strings.ReplaceAll(t, "\n", " ")
	t = strings.ReplaceAll(t, "\r", " ")
	t = strings.ReplaceAll(t, "\t", " ")
	// Collapse internal whitespace.
	for strings.Contains(t, "  ") {
		t = strings.ReplaceAll(t, "  ", " ")
	}
	return strings.TrimSpace(t)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
