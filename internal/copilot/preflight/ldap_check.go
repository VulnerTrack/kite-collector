package preflight

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

// Default ports for the three TLS modes the LDAP source supports
// (RFC-0121 §5.4). starttls and plain LDAP both ride on 389; ldaps on 636.
const (
	ldapPortLDAPS    = 636
	ldapPortPlain    = 389
	ldapDialTimeout  = 5 * time.Second
	ldapMinDNSegment = 1
)

// LDAPDCConnectChecker probes TCP reachability for every domain controller
// listed in the wizard answer. Each entry may be bare ("dc1.corp.acme.com")
// or "host:port"; bare hosts default to 636/389 based on the resolved
// tls_mode. The check fails on the first DC that doesn't accept a TCP
// connection within ldapDialTimeout — that's enough signal for the wizard
// to surface a hint, since LDAP discovery requires *all* DCs reachable for
// failover to work.
type LDAPDCConnectChecker struct{}

func (c *LDAPDCConnectChecker) Check(ctx context.Context, nodeID string, value any, resolved map[string]any) CheckResult {
	dcs := splitDCList(value)
	if len(dcs) == 0 {
		return CheckResult{NodeID: nodeID, Check: "ldap:dc:connect", Passed: true, Message: "no domain controllers configured"}
	}

	defaultPort := defaultLDAPPort(resolved)
	dialer := &net.Dialer{}

	for _, dc := range dcs {
		host, port, err := parseHostPort(dc, defaultPort)
		if err != nil {
			return CheckResult{
				NodeID:  nodeID,
				Check:   "ldap:dc:connect",
				Passed:  false,
				Message: fmt.Sprintf("invalid DC entry %q: %s", dc, err),
				Hint:    "Use the form host or host:port, e.g., dc1.corp.acme.com:636",
			}
		}
		dialCtx, cancel := context.WithTimeout(ctx, ldapDialTimeout)
		conn, err := dialer.DialContext(dialCtx, "tcp", net.JoinHostPort(host, fmt.Sprintf("%d", port)))
		cancel()
		if err != nil {
			return CheckResult{
				NodeID:  nodeID,
				Check:   "ldap:dc:connect",
				Passed:  false,
				Message: fmt.Sprintf("cannot reach %s:%d (%s)", host, port, err),
				Hint:    "Verify firewall rules, DNS, and that the DC is online",
			}
		}
		_ = conn.Close()
	}

	return CheckResult{
		NodeID:  nodeID,
		Check:   "ldap:dc:connect",
		Passed:  true,
		Message: fmt.Sprintf("%d domain controller(s) reachable", len(dcs)),
	}
}

// LDAPBindEnvChecker verifies that the environment variable named in the
// node's value is exported and non-empty. The LDAP source refuses to bind
// without a password, so a missing env var is a hard failure — the wizard
// should fail loudly here rather than have the first scan crash with
// "bind password not set".
type LDAPBindEnvChecker struct{}

func (c *LDAPBindEnvChecker) Check(_ context.Context, nodeID string, value any, _ map[string]any) CheckResult {
	envVar, ok := value.(string)
	if !ok || envVar == "" {
		return CheckResult{NodeID: nodeID, Check: "ldap:bind:env", Passed: true, Message: "no bind env var configured, skipping"}
	}
	if os.Getenv(envVar) == "" {
		return CheckResult{
			NodeID:  nodeID,
			Check:   "ldap:bind:env",
			Passed:  false,
			Message: fmt.Sprintf("env var %s is not set", envVar),
			Hint:    fmt.Sprintf("export %s=<bind-password>", envVar),
		}
	}
	return CheckResult{NodeID: nodeID, Check: "ldap:bind:env", Passed: true, Message: fmt.Sprintf("%s is set", envVar)}
}

// LDAPBaseDNChecker validates the syntactic shape of an AD base DN. The
// guard rail is intentionally loose — we don't need a strict RFC 4514
// parser, just enough to catch the common typos: missing DC components,
// unbalanced commas, stray quotes. AD without DC components is impossible
// (every domain has a DNS suffix that maps onto DC=...) so absence is the
// strongest signal of a bad value.
type LDAPBaseDNChecker struct{}

func (c *LDAPBaseDNChecker) Check(_ context.Context, nodeID string, value any, _ map[string]any) CheckResult {
	baseDN, ok := value.(string)
	if !ok || baseDN == "" {
		return CheckResult{NodeID: nodeID, Check: "ldap:base_dn:syntax", Passed: true, Message: "no base DN configured, skipping"}
	}
	parts := strings.Split(baseDN, ",")
	dcCount := 0
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			return CheckResult{
				NodeID:  nodeID,
				Check:   "ldap:base_dn:syntax",
				Passed:  false,
				Message: "base DN contains empty component (stray comma)",
				Hint:    "Example: DC=corp,DC=acme,DC=com",
			}
		}
		if strings.HasPrefix(strings.ToLower(p), "dc=") {
			dcCount++
		}
	}
	if dcCount < ldapMinDNSegment {
		return CheckResult{
			NodeID:  nodeID,
			Check:   "ldap:base_dn:syntax",
			Passed:  false,
			Message: fmt.Sprintf("base DN %q has no DC= components", baseDN),
			Hint:    "Active Directory base DNs must include the domain, e.g., DC=corp,DC=acme,DC=com",
		}
	}
	return CheckResult{
		NodeID:  nodeID,
		Check:   "ldap:base_dn:syntax",
		Passed:  true,
		Message: fmt.Sprintf("%d DC component(s) parsed", dcCount),
	}
}

// LDAPTLSModeChecker enforces the closed enum {ldaps, starttls, none}.
// The select widget already constrains the wizard, but operators editing
// kite-collector.yaml by hand can introduce typos like "tls" or "ssl"
// that the LDAP source rejects much later in the scan pipeline. Catching
// it during preflight gives a faster, friendlier error.
type LDAPTLSModeChecker struct{}

func (c *LDAPTLSModeChecker) Check(_ context.Context, nodeID string, value any, _ map[string]any) CheckResult {
	mode, ok := value.(string)
	if !ok || mode == "" {
		return CheckResult{NodeID: nodeID, Check: "ldap:tls_mode:valid", Passed: true, Message: "no TLS mode configured, skipping"}
	}
	switch mode {
	case "ldaps", "starttls", "none":
		return CheckResult{
			NodeID:  nodeID,
			Check:   "ldap:tls_mode:valid",
			Passed:  true,
			Message: fmt.Sprintf("tls_mode=%s", mode),
		}
	default:
		return CheckResult{
			NodeID:  nodeID,
			Check:   "ldap:tls_mode:valid",
			Passed:  false,
			Message: fmt.Sprintf("invalid tls_mode %q", mode),
			Hint:    "tls_mode must be one of: ldaps, starttls, none",
		}
	}
}

// splitDCList accepts the three shapes the wizard / config loader can
// produce for a DC list:
//
//	"dc1.corp,dc2.corp"  (comma-separated input)
//	[]string{"dc1.corp", "dc2.corp"}
//	[]any{"dc1.corp", "dc2.corp"} (JSON-decoded)
func splitDCList(v any) []string {
	switch x := v.(type) {
	case string:
		return splitTrim(x)
	case []string:
		return cleanList(x)
	case []any:
		out := make([]string, 0, len(x))
		for _, item := range x {
			if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
				out = append(out, strings.TrimSpace(s))
			}
		}
		return out
	default:
		return nil
	}
}

// splitTrim splits a comma-separated string and drops empty entries.
func splitTrim(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	raw := strings.Split(s, ",")
	out := make([]string, 0, len(raw))
	for _, r := range raw {
		r = strings.TrimSpace(r)
		if r != "" {
			out = append(out, r)
		}
	}
	return out
}

func cleanList(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// defaultLDAPPort picks the right default port based on the resolved
// discovery.ldap.tls_mode value. ldaps uses 636; starttls and plain
// LDAP both ride on 389 (StartTLS upgrades the same TCP connection).
func defaultLDAPPort(resolved map[string]any) int {
	mode, _ := resolved["discovery.ldap.tls_mode"].(string)
	if mode == "" || mode == "ldaps" {
		return ldapPortLDAPS
	}
	return ldapPortPlain
}

// parseHostPort accepts "host" or "host:port" and returns the components.
// On bare hosts it substitutes the supplied default port.
func parseHostPort(s string, defaultPort int) (string, int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", 0, fmt.Errorf("empty entry")
	}
	if !strings.Contains(s, ":") {
		return s, defaultPort, nil
	}
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return "", 0, err
	}
	if portStr == "" {
		return host, defaultPort, nil
	}
	port := 0
	for _, r := range portStr {
		if r < '0' || r > '9' {
			return "", 0, fmt.Errorf("invalid port %q", portStr)
		}
		port = port*10 + int(r-'0')
	}
	if port <= 0 || port > 65535 {
		return "", 0, fmt.Errorf("port %d out of range", port)
	}
	return host, port, nil
}
