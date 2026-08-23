// Package servicefp wraps praetorian-inc/fingerprintx to give kite an
// nmap `-sV`-style service/version recogniser for non-HTTP ports (SSH, Redis,
// PostgreSQL, MySQL, MSSQL, RDP, SMB, LDAP, …). It complements the HTTP/TLS
// fingerprint engines under internal/discovery/network by naming the service
// speaking on an already-open TCP port.
//
// fingerprintx probes by connecting and speaking each protocol's handshake, so
// it is read-only in the same sense the other engines are: it never
// authenticates and never sends a mutating request.
package servicefp

import (
	"context"
	"net/netip"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	"github.com/praetorian-inc/fingerprintx/pkg/scan"
)

// DefaultTimeout bounds a single service handshake. fingerprintx answers in
// milliseconds against a live service; the cap exists for wedged or filtered
// ports that would otherwise hang the sweep.
const DefaultTimeout = 3 * time.Second

// Result is kite's flattened view of a recognised service.
type Result struct {
	Protocol  string // "ssh", "postgresql", "redis", "http", ...
	Version   string // free-form version banner, when the service reveals one
	Transport string // "tcp" / "udp"
	TLS       bool   // the service is wrapped in TLS
}

// Fingerprinter recognises services on open ports. The zero value is not
// usable; construct with New.
type Fingerprinter struct {
	cfg scan.Config
}

// New returns a Fingerprinter with the given per-probe timeout (0 uses
// DefaultTimeout).
func New(timeout time.Duration) *Fingerprinter {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	return &Fingerprinter{cfg: scan.Config{DefaultTimeout: timeout}}
}

// Identify fingerprints one open TCP port. It returns (nil, false) when the
// service is unrecognised or the probe fails — an unknown service is a normal
// outcome, not an error the caller must handle. The context is honoured for
// cancellation between probes; fingerprintx itself is bounded by the timeout.
func (f *Fingerprinter) Identify(ctx context.Context, ip netip.Addr, port uint16) (Result, bool) {
	if ctx.Err() != nil {
		return Result{}, false
	}
	svc, err := f.cfg.SimpleScanTarget(plugins.Target{
		Address: netip.AddrPortFrom(ip, port),
		Host:    ip.String(),
	})
	if err != nil || svc == nil || svc.Protocol == "" {
		return Result{}, false
	}
	return Result{
		Protocol:  svc.Protocol,
		Version:   svc.Version,
		Transport: svc.Transport,
		TLS:       svc.TLS,
	}, true
}
