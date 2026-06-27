package compositefingerprint

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vulnertrack/kite-collector/internal/discovery/network/apifingerprint"
	"github.com/vulnertrack/kite-collector/internal/discovery/network/filefingerprint"
	"github.com/vulnertrack/kite-collector/internal/discovery/network/headerfingerprint"
	"github.com/vulnertrack/kite-collector/internal/discovery/network/jsfingerprint"
	"github.com/vulnertrack/kite-collector/internal/discovery/network/tlsfingerprint"
)

// Options selects which mechanisms run and tunes their budgets. The
// zero value enables every mechanism — callers opt out, not in,
// because the typical use case is "find everything you can".
type Options struct {
	HTTPClient          *http.Client
	TLSSNI              string
	PerMechanismTimeout time.Duration
	DisableTLS          bool
	DisableHeader       bool
	DisableJS           bool
	DisableFile         bool
	DisableAPI          bool
	InsecureSkipVerify  bool
}

// DefaultPerMechanismTimeout is the timeout each mechanism gets when
// Options.PerMechanismTimeout is zero.
const DefaultPerMechanismTimeout = 15 * time.Second

// Scanner is the composite orchestrator. Reusing one Scanner across
// hosts is safe — all per-mechanism scanners and clients are
// goroutine-safe.
type Scanner struct {
	tls    *tlsfingerprint.Scanner
	header *headerfingerprint.Detector
	js     *jsfingerprint.Detector
	file   *filefingerprint.Scanner
	api    *apifingerprint.Detector
}

// NewScanner constructs a Scanner using each package's DefaultCatalog
// and default HTTP client.
func NewScanner() *Scanner {
	return &Scanner{
		tls:    tlsfingerprint.NewScanner(nil),
		header: headerfingerprint.NewDetector(nil, nil),
		js:     jsfingerprint.NewDetector(nil, nil),
		file:   filefingerprint.NewScanner(nil, nil),
		api:    apifingerprint.NewDetector(nil, nil),
	}
}

// NewScannerWithClient is the same as NewScanner but injects a shared
// http.Client into every HTTP-based mechanism. Use this when you have
// a custom Transport (proxy, mTLS, dial retries).
func NewScannerWithClient(client *http.Client) *Scanner {
	return &Scanner{
		tls:    tlsfingerprint.NewScanner(nil),
		header: headerfingerprint.NewDetector(client, nil),
		js:     jsfingerprint.NewDetector(client, nil),
		file:   filefingerprint.NewScanner(client, nil),
		api:    apifingerprint.NewDetector(client, nil),
	}
}

// CustomCatalogs bundles operator-supplied overlay signatures for any
// subset of the five surfaces. Empty slices are ignored. The composite
// scanner appends these to each underlying detector's DefaultCatalog
// so operators can extend detection without modifying Go code.
type CustomCatalogs struct {
	TLS    []tlsfingerprint.Signature
	Header []headerfingerprint.Signature
	JS     []jsfingerprint.Signature
	File   []filefingerprint.Probe
	API    []apifingerprint.Signature
}

// NewScannerWithCustomCatalogs constructs a Scanner where each
// underlying detector's catalog is `DefaultCatalog + custom`. Operators
// load the custom slices from a YAML overlay via
// internal/discovery/network/customcatalog.LoadFile, then pass them
// here so the composite sweep picks up internal vendors / products
// the default catalog does not know about.
func NewScannerWithCustomCatalogs(client *http.Client, custom CustomCatalogs) *Scanner {
	merge := func(a, b []apifingerprint.Signature) []apifingerprint.Signature {
		if len(b) == 0 {
			return a
		}
		out := make([]apifingerprint.Signature, 0, len(a)+len(b))
		return append(append(out, a...), b...)
	}
	mergeTLS := func(a, b []tlsfingerprint.Signature) []tlsfingerprint.Signature {
		if len(b) == 0 {
			return a
		}
		out := make([]tlsfingerprint.Signature, 0, len(a)+len(b))
		return append(append(out, a...), b...)
	}
	mergeHeader := func(a, b []headerfingerprint.Signature) []headerfingerprint.Signature {
		if len(b) == 0 {
			return a
		}
		out := make([]headerfingerprint.Signature, 0, len(a)+len(b))
		return append(append(out, a...), b...)
	}
	mergeJS := func(a, b []jsfingerprint.Signature) []jsfingerprint.Signature {
		if len(b) == 0 {
			return a
		}
		out := make([]jsfingerprint.Signature, 0, len(a)+len(b))
		return append(append(out, a...), b...)
	}
	mergeFile := func(a, b []filefingerprint.Probe) []filefingerprint.Probe {
		if len(b) == 0 {
			return a
		}
		out := make([]filefingerprint.Probe, 0, len(a)+len(b))
		return append(append(out, a...), b...)
	}

	return &Scanner{
		tls:    tlsfingerprint.NewScanner(mergeTLS(tlsfingerprint.DefaultCatalog(), custom.TLS)),
		header: headerfingerprint.NewDetector(client, mergeHeader(headerfingerprint.DefaultCatalog(), custom.Header)),
		js:     jsfingerprint.NewDetector(client, mergeJS(jsfingerprint.DefaultCatalog(), custom.JS)),
		file:   filefingerprint.NewScanner(client, mergeFile(filefingerprint.DefaultCatalog(), custom.File)),
		api:    apifingerprint.NewDetector(client, merge(apifingerprint.DefaultCatalog(), custom.API)),
	}
}

// Scan fans out across the five mechanisms in parallel against the
// supplied endpoint. Per-mechanism timeouts are independent; ctx
// cancellation aborts every in-flight mechanism.
//
// scheme is "http" or "https". host is the dial host (DNS name or IP).
// port is the TCP port number.
func (s *Scanner) Scan(ctx context.Context, scheme, host string, port int, opts Options) (CompositeResult, error) {
	scheme = strings.ToLower(scheme)
	if scheme != "http" && scheme != "https" {
		return CompositeResult{}, fmt.Errorf("compositefingerprint: unsupported scheme %q", scheme)
	}
	if host == "" {
		return CompositeResult{}, errors.New("compositefingerprint: empty host")
	}
	if port <= 0 || port > 65535 {
		return CompositeResult{}, fmt.Errorf("compositefingerprint: invalid port %d", port)
	}
	timeout := opts.PerMechanismTimeout
	if timeout <= 0 {
		timeout = DefaultPerMechanismTimeout
	}

	base := &url.URL{
		Scheme: scheme,
		Host:   host + ":" + strconv.Itoa(port),
	}
	endpoint := strings.TrimRight(base.String(), "/")

	result := CompositeResult{
		Scheme:   scheme,
		Host:     host,
		Port:     port,
		Endpoint: endpoint,
	}

	var (
		mu sync.Mutex
		wg sync.WaitGroup
	)
	addErr := func(mech string, err error) {
		if err == nil {
			return
		}
		mu.Lock()
		result.Errors = append(result.Errors, MechanismError{
			Mechanism: mech,
			Message:   err.Error(),
		})
		mu.Unlock()
	}

	// TLS — only when scheme=https.
	if !opts.DisableTLS && scheme == "https" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx2, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			r, err := s.tls.Scan(ctx2, host, port, tlsfingerprint.ScanOptions{
				SNI:                opts.TLSSNI,
				InsecureSkipVerify: opts.InsecureSkipVerify,
			})
			if err != nil {
				addErr("tls", err)
				// Even on handshake failure, surface whatever cert
				// metadata Scan captured before the error.
				if r.Endpoint != "" {
					mu.Lock()
					result.TLS = &r
					mu.Unlock()
				}
				return
			}
			mu.Lock()
			result.TLS = &r
			mu.Unlock()
		}()
	}

	// Header — single GET against root.
	if !opts.DisableHeader {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx2, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			r, err := s.header.Probe(ctx2, base)
			if err != nil {
				addErr("header", err)
				return
			}
			mu.Lock()
			result.Header = &r
			mu.Unlock()
		}()
	}

	// JS — fetch HTML + follow same-origin scripts + regex match.
	if !opts.DisableJS {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx2, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			r, err := s.js.Scan(ctx2, base)
			if err != nil {
				addErr("js", err)
				return
			}
			mu.Lock()
			result.JS = &r
			mu.Unlock()
		}()
	}

	// File — well-known path probes (highest fan-out).
	if !opts.DisableFile {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx2, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			r, err := s.file.Scan(ctx2, base)
			if err != nil {
				addErr("file", err)
				return
			}
			mu.Lock()
			result.File = &r
			mu.Unlock()
		}()
	}

	// API — REST/GraphQL/gRPC endpoint sweep.
	if !opts.DisableAPI {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx2, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			r, err := s.api.Probe(ctx2, base)
			if err != nil {
				addErr("api", err)
				return
			}
			mu.Lock()
			result.API = &r
			mu.Unlock()
		}()
	}

	wg.Wait()
	return result, nil
}
