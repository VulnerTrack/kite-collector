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
	DisableTLS    bool
	DisableHeader bool
	DisableJS     bool
	DisableFile   bool
	DisableAPI    bool

	// PerMechanismTimeout caps each mechanism's wall time
	// independently. Default 15s — long enough for the file probe
	// (~71 paths at 8x concurrency ≈ 9 round-trips) without giving
	// a hostile origin room to stall.
	PerMechanismTimeout time.Duration

	// TLSSNI overrides the SNI sent during the TLS handshake; empty
	// = use Host.
	TLSSNI string

	// HTTPClient overrides the shared client used by header / JS /
	// file / API mechanisms. Nil = each package's own default.
	HTTPClient *http.Client

	// InsecureSkipVerify forwards to TLS handshake. Used by the
	// header / JS / file / API mechanisms when scheme is https but
	// the operator wants to scan a self-signed origin.
	InsecureSkipVerify bool
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
		mu      sync.Mutex
		wg      sync.WaitGroup
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
