package tlsfingerprint

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"
)

// DefaultDialTimeout is the per-Scan timeout if the operator does not
// supply one via ScanOptions.
const DefaultDialTimeout = 5 * time.Second

// Scanner connects to a (host, port) over TLS, captures the peer cert
// chain, and matches it against the supplied catalog. Concurrent
// callers safe — Scanner holds no per-call state.
type Scanner struct {
	signatures  []Signature
	dialTimeout time.Duration
}

// NewScanner returns a Scanner. Pass nil for signatures to use the
// DefaultCatalog().
func NewScanner(signatures []Signature) *Scanner {
	if signatures == nil {
		signatures = DefaultCatalog()
	}
	return &Scanner{signatures: signatures, dialTimeout: DefaultDialTimeout}
}

// ScanOptions tunes one Scan() call.
type ScanOptions struct {
	// SNI overrides the SNI server-name sent in the ClientHello.
	// Useful when the host parameter is an IP and the operator wants
	// to surface a cert for a specific virtual host.
	SNI string
	// InsecureSkipVerify is honoured — we do not validate the cert
	// chain because the scanner cares about the metadata, not the
	// trust path.
	InsecureSkipVerify bool
	// DialTimeout overrides DefaultDialTimeout for this Scan.
	DialTimeout time.Duration
}

// Scan dials host:port, completes a TLS handshake to the point of
// reading the server's certificate, then closes. Returns a Result
// with the cert summary plus any vendor matches; if the handshake
// fails the error is non-nil but a partial Result with whatever
// metadata was already captured is still returned.
func (s *Scanner) Scan(ctx context.Context, host string, port int, opts ScanOptions) (Result, error) {
	if host == "" {
		return Result{}, errors.New("tlsfingerprint: empty host")
	}
	if port <= 0 || port > 65535 {
		return Result{}, fmt.Errorf("tlsfingerprint: invalid port %d", port)
	}
	dialTimeout := opts.DialTimeout
	if dialTimeout <= 0 {
		dialTimeout = s.dialTimeout
	}
	dialer := &net.Dialer{Timeout: dialTimeout}
	addr := net.JoinHostPort(host, strconv.Itoa(port))

	sni := opts.SNI
	if sni == "" {
		sni = host
	}

	// We always set InsecureSkipVerify=true because the scanner's
	// purpose is metadata capture, not trust path validation; the
	// stdlib otherwise refuses to surface untrusted certs.
	tlsCfg := &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true, //#nosec G402 -- metadata capture, not auth
		MinVersion:         tls.VersionTLS12,
	}

	endpoint := "https://" + addr
	result := Result{Endpoint: endpoint, ClientJA3: ClientJA3String()}

	rawConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return result, fmt.Errorf("dial %s: %w", addr, err)
	}
	defer func() { _ = rawConn.Close() }()

	if dl, ok := ctx.Deadline(); ok {
		_ = rawConn.SetDeadline(dl)
	} else {
		_ = rawConn.SetDeadline(time.Now().Add(dialTimeout))
	}

	// Wrap the dialed conn so we capture every byte the server sends
	// during the handshake. After the handshake completes we parse
	// the recorded buffer to derive JA3S and JA4S.
	rec := newHandshakeRecorder(rawConn)
	tlsConn := tls.Client(rec, tlsCfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return result, fmt.Errorf("tls handshake: %w", err)
	}
	rec.Stop()
	defer func() { _ = tlsConn.Close() }()

	if sh, perr := parseServerHello(rec.snapshot()); perr == nil {
		result.ServerJA3S = JA3SDigest(sh)
		result.ServerJA4S = JA4SString(sh)
	}

	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return result, errors.New("tlsfingerprint: empty peer chain")
	}
	leaf := state.PeerCertificates[0]
	cs := SummariseCert(leaf)
	result.Cert = cs

	for _, sig := range s.signatures {
		fp, ok := s.matchSignature(sig, cs, endpoint)
		if ok {
			result.Fingerprints = append(result.Fingerprints, fp)
		}
	}
	SortFingerprints(result.Fingerprints)
	return result, nil
}

// matchSignature evaluates every Pattern of sig against cs and emits
// a Fingerprint when at least one hits. The strongest matched
// Pattern's confidence carries over.
func (s *Scanner) matchSignature(sig Signature, cs CertSummary, endpoint string) (Fingerprint, bool) {
	var evidence []string
	var best Confidence
	hit := false
	for _, p := range sig.Patterns {
		ok, ev := MatchPattern(p, cs)
		if !ok {
			continue
		}
		hit = true
		evidence = append(evidence, ev)
		best = stronger(best, p.Confidence)
	}
	if !hit {
		return Fingerprint{}, false
	}
	return Fingerprint{
		Vendor:     sig.Vendor,
		Product:    sig.Product,
		Category:   sig.Category,
		Endpoint:   endpoint,
		Evidence:   uniqueStrings(evidence),
		Confidence: best,
	}, true
}

// ClientJA3String returns the JA3 string for the ClientHello that
// Go's crypto/tls produces with the default settings used by this
// package (TLS 1.2+, default cipher suite list, default extensions).
// The output is the "version,ciphers,extensions,groups,formats"
// pre-image; operators MD5 it themselves if they want the 32-char
// digest form (the pre-image carries more diagnostic value).
//
// The string is intentionally hard-coded: Go's defaults change
// across versions, so this function is a self-test reference — the
// expected output a vendor pinning kite-collector should observe.
// Update when bumping Go major versions.
func ClientJA3String() string {
	// Go 1.22+ default ClientHello fingerprint pre-image, captured
	// from running tls.Dial against a controlled probe. Format:
	// SSLVersion,Ciphers,Extensions,SupportedGroups,EcPointFormats
	return "771," +
		"4865-4866-4867-49195-49199-49196-49200-52393-52392-49161-49171-49162-49172-156-157-47-53," +
		"0-23-65281-10-11-35-16-5-13-18-51-45-43-27-65037," +
		"29-23-24-25," +
		"0"
}
