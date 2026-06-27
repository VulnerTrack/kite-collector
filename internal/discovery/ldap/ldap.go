// Package ldap implements a discovery.Source that enumerates Windows
// Active Directory / generic LDAP computer accounts (and, optionally,
// users / groups / OUs) as kite assets per RFC-0121.
//
// The source binds to one or more configured domain controllers using
// ldaps:// (default), starttls, or plain LDAP, then runs paged searches
// against the requested object classes and emits model.Asset records
// tagged with the contract.AttrAD* attribute set declared in
// internal/telemetry/contract/v1.go. Findings are produced separately
// in finding.go (Phase 2).
package ldap

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"time"

	ldapv3 "github.com/go-ldap/ldap/v3"

	"github.com/vulnertrack/kite-collector/internal/model"
)

// SourceName is the stable identifier emitted on the
// security.asset.discovery.source attribute and the discover.<source>
// span suffix per RFC-0115.
const SourceName = "ldap"

// Computer object filter — RFC-0121 §5.6.1. Matches Active Directory
// and most generic LDAP "computer" object classes. Disabled accounts
// are still returned so the disabled-account finding (Phase 2) can fire.
const computerSearchFilter = "(&(objectCategory=computer)(objectClass=computer))"

// Computer attributes pulled per entry. Keep this list narrow — every
// extra attribute multiplies the wire payload across the whole domain.
var computerAttributes = []string{
	"distinguishedName",
	"sAMAccountName",
	"objectSid",
	"dnsHostName",
	"operatingSystem",
	"operatingSystemVersion",
	"userAccountControl",
	"lastLogonTimestamp",
	"pwdLastSet",
	"servicePrincipalName",
	"memberOf",
}

// directoryConn is the minimal subset of *ldapv3.Conn methods the source
// uses. Defining it as an interface lets the test suite swap in a fake
// connection without touching a real DC.
type directoryConn interface {
	Bind(username, password string) error
	StartTLS(config *tls.Config) error
	SearchWithPaging(req *ldapv3.SearchRequest, pagingSize uint32) (*ldapv3.SearchResult, error)
	Close() error
}

// dialFunc constructs a directoryConn for a given domain-controller
// endpoint. The default is dialDC; tests inject a fake.
type dialFunc func(ctx context.Context, conf *ldapConfig, dc dcEndpoint) (directoryConn, error)

// LDAP implements discovery.Source for Active Directory / LDAP.
type LDAP struct {
	dial dialFunc
	now  func() time.Time
}

// New returns a new LDAP discovery source with the production dialer.
func New() *LDAP {
	return &LDAP{
		dial: dialDC,
		now:  func() time.Time { return time.Now().UTC() },
	}
}

// Name returns the stable identifier for this source.
func (l *LDAP) Name() string { return SourceName }

// Discover binds to the first reachable configured domain controller,
// runs a paged LDAP search for computer accounts, converts the results
// to model.Asset values, and returns them. Failure to reach a single DC
// causes the next configured DC to be tried; if none respond the source
// returns an error, which the registry logs as a warning per
// discovery.Registry.DiscoverAll.
func (l *LDAP) Discover(ctx context.Context, cfg map[string]any) ([]model.Asset, error) {
	conf, err := parseConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("ldap: %w", err)
	}
	if !conf.enabled {
		slog.Debug("ldap: disabled by configuration")
		return nil, nil
	}

	bindPwd, err := readBindPassword(conf.bindPasswordEnvVar)
	if err != nil {
		return nil, err
	}
	defer zero(bindPwd)

	conn, dc, err := l.dialAny(ctx, conf)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	if bindErr := conn.Bind(conf.bindDN, string(bindPwd)); bindErr != nil {
		return nil, fmt.Errorf("ldap: bind to %s:%d failed: %w", dc.host, dc.port, bindErr)
	}
	slog.Info("ldap: bound to domain controller",
		"host", dc.host,
		"port", dc.port,
		"tls_mode", conf.tlsMode,
		"base_dn", conf.baseDN,
	)

	timeoutCtx, cancel := context.WithTimeout(ctx, time.Duration(conf.timeoutSeconds)*time.Second)
	defer cancel()

	result, err := searchPaged(timeoutCtx, conn, conf, computerSearchFilter, computerAttributes)
	if err != nil {
		return nil, fmt.Errorf("ldap: computer search failed: %w", err)
	}

	now := l.now()
	assets := make([]model.Asset, 0, len(result.Entries))
	for _, entry := range result.Entries {
		comp, exErr := extractComputer(entry, conf.baseDN)
		if exErr != nil {
			slog.Warn("ldap: skipping malformed entry", "dn", entry.DN, "error", exErr)
			continue
		}
		assets = append(assets, comp.toAsset(now))
		if len(assets) >= conf.maxObjects {
			slog.Warn("ldap: max_objects circuit breaker tripped — truncating",
				"max_objects", conf.maxObjects,
			)
			break
		}
	}

	slog.Info("ldap: discovery complete", "assets", len(assets), "dc", dc.host)
	return assets, nil
}

// dialAny tries every configured domain controller in order and returns
// the first successful connection. Errors are accumulated and returned
// together when all DCs fail.
func (l *LDAP) dialAny(ctx context.Context, conf *ldapConfig) (directoryConn, dcEndpoint, error) {
	var errs []error
	for _, dc := range conf.domainControllers {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, dcEndpoint{}, fmt.Errorf("ldap: dial cancelled: %w", ctxErr)
		}
		conn, err := l.dial(ctx, conf, dc)
		if err == nil {
			return conn, dc, nil
		}
		errs = append(errs, fmt.Errorf("%s:%d: %w", dc.host, dc.port, err))
		slog.Warn("ldap: dial failed, trying next DC",
			"host", dc.host,
			"port", dc.port,
			"error", err,
		)
	}
	return nil, dcEndpoint{}, fmt.Errorf("ldap: all domain controllers failed: %w", errors.Join(errs...))
}

// dialDC opens a connection to a single domain controller using the
// TLS mode and certificate-pinning options recorded in the config.
func dialDC(ctx context.Context, conf *ldapConfig, dc dcEndpoint) (directoryConn, error) {
	tlsCfg, err := buildTLSConfig(conf, dc.host)
	if err != nil {
		return nil, err
	}

	timeout := time.Duration(conf.timeoutSeconds) * time.Second
	netDialer := &net.Dialer{Timeout: timeout}

	switch conf.tlsMode {
	case "ldaps":
		url := fmt.Sprintf("ldaps://%s:%d", dc.host, dc.port)
		conn, dErr := ldapv3.DialURL(url,
			ldapv3.DialWithTLSConfig(tlsCfg),
			ldapv3.DialWithDialer(netDialer),
		)
		if dErr != nil {
			return nil, fmt.Errorf("ldaps dial: %w", dErr)
		}
		conn.SetTimeout(timeout)
		return conn, nil
	case "starttls":
		url := fmt.Sprintf("ldap://%s:%d", dc.host, dc.port)
		conn, dErr := ldapv3.DialURL(url, ldapv3.DialWithDialer(netDialer))
		if dErr != nil {
			return nil, fmt.Errorf("starttls dial: %w", dErr)
		}
		conn.SetTimeout(timeout)
		if sErr := conn.StartTLS(tlsCfg); sErr != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("starttls: %w", sErr)
		}
		return conn, nil
	case "none":
		url := fmt.Sprintf("ldap://%s:%d", dc.host, dc.port)
		conn, dErr := ldapv3.DialURL(url, ldapv3.DialWithDialer(netDialer))
		if dErr != nil {
			return nil, fmt.Errorf("ldap dial: %w", dErr)
		}
		conn.SetTimeout(timeout)
		return conn, nil
	default:
		return nil, fmt.Errorf("unknown tls_mode %q", conf.tlsMode)
	}
}

// buildTLSConfig assembles the *tls.Config used by ldaps / starttls.
// When tls_skip_verify is set we still set ServerName so SNI works for
// load-balanced DCs — only certificate verification is skipped.
func buildTLSConfig(conf *ldapConfig, host string) (*tls.Config, error) {
	cfg := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: conf.tlsSkipVerify, //#nosec G402 -- operator opt-in (RFC-0121 §5.4)
		MinVersion:         tls.VersionTLS12,
	}
	if conf.tlsCAFile != "" {
		pem, err := os.ReadFile(conf.tlsCAFile) //#nosec G304 -- operator-supplied CA bundle path
		if err != nil {
			return nil, fmt.Errorf("read tls_ca_file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("tls_ca_file %q: no certificates parsed", conf.tlsCAFile)
		}
		cfg.RootCAs = pool
	}
	return cfg, nil
}

// searchPaged runs an LDAP search with the Simple Paged Results control
// (RFC 2696) using the configured page size.
func searchPaged(ctx context.Context, conn directoryConn, conf *ldapConfig, filter string, attrs []string) (*ldapv3.SearchResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("ldap: search cancelled: %w", err)
	}
	req := ldapv3.NewSearchRequest(
		conf.baseDN,
		ldapv3.ScopeWholeSubtree,
		ldapv3.NeverDerefAliases,
		0, // size limit (0 == server default; pagination handles total)
		conf.timeoutSeconds,
		false,
		filter,
		attrs,
		nil,
	)
	result, err := conn.SearchWithPaging(req, conf.pageSize)
	if err != nil {
		return nil, fmt.Errorf("ldap: search with paging: %w", err)
	}
	return result, nil
}

// readBindPassword fetches the bind password from the configured
// environment variable. The byte slice can be wiped after use.
func readBindPassword(envVar string) ([]byte, error) {
	v := os.Getenv(envVar)
	if v == "" {
		return nil, fmt.Errorf("ldap: %s not set", envVar)
	}
	// Copy into a slice we own so we can zero it after Bind().
	out := make([]byte, len(v))
	copy(out, v)
	return out, nil
}

// zero overwrites the byte slice with zeros to avoid leaving the bind
// password in process memory longer than necessary.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
