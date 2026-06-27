// Package sshdconfig inventories the OpenSSH server configuration
// from /etc/ssh/sshd_config and every drop-in under
// /etc/ssh/sshd_config.d/. macOS uses the same paths; Windows OpenSSH
// lives under %ProgramData%\ssh\ and is deferred to a later iteration.
//
// sshd is the front door on practically every Linux server in
// existence. Whoever weakens its config is preparing the host for
// lateral movement (MITRE T1021.004 — Remote Services: SSH) or
// privilege-escalation (T1098 — Account Manipulation when PermitRootLogin
// flips on). CIS Linux Benchmark section 5.2 enumerates ~25 settings
// every credible audit must check; this collector parses them all into
// row form with pre-computed CWE/CIS flags.
//
// Every collector is **read-only by intent** — it parses sshd_config
// + drop-ins, never invokes sshd, systemctl, or sshd -t. Read-only is
// enforced by guideline 4.2 of the kite-collector project.
//
// Directive rows feed the audit pipeline:
//
//   - `finding_category='root-login-permitted'` flags PermitRootLogin=yes
//     (CIS 5.2.7; also `prohibit-password` is acceptable).
//   - `finding_category='password-auth-permitted'` flags
//     PasswordAuthentication=yes (CIS 5.2.16) — key-only auth is the
//     baseline.
//   - `finding_category='weak-cipher'` / `'weak-mac'` / `'weak-kex'`
//     enumerate every CWE-327 occurrence in Ciphers/MACs/KexAlgorithms.
//   - File hash drift on any sshd_config* file = the server-auth
//     posture was modified.
package sshdconfig

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"
)

// MaxSettings bounds per-scan output. A typical sshd_config has 30-50
// active directives; with drop-ins + Match blocks the 1024 ceiling
// covers heavyweight enterprise installs.
const MaxSettings = 1024

// Scope identifies whether the directive sits at file top-level
// (`global`) or inside a `Match` block (`match`). Pinned to the
// host_sshd_config.scope CHECK enum.
type Scope string

const (
	ScopeGlobal Scope = "global"
	ScopeMatch  Scope = "match"
)

// FindingCategory classifies why a setting is flagged. Pinned to
// host_sshd_config.finding_category.
type FindingCategory string

const (
	FindingRootLoginPermitted     FindingCategory = "root-login-permitted"
	FindingPasswordAuthPermitted  FindingCategory = "password-auth-permitted"
	FindingEmptyPasswordPermitted FindingCategory = "empty-password-permitted"
	FindingX11ForwardingEnabled   FindingCategory = "x11-forwarding-enabled"
	FindingAgentForwardingEnabled FindingCategory = "agent-forwarding-enabled"
	FindingTCPForwardingEnabled   FindingCategory = "tcp-forwarding-enabled"
	FindingHostBasedAuthEnabled   FindingCategory = "host-based-auth-enabled"
	FindingRhostsNotIgnored       FindingCategory = "rhosts-not-ignored"
	FindingExcessiveAuthAttempts  FindingCategory = "excessive-auth-attempts"
	FindingLongLoginGrace         FindingCategory = "long-login-grace"
	FindingWeakCipher             FindingCategory = "weak-cipher"
	FindingWeakMAC                FindingCategory = "weak-mac"
	FindingWeakKex                FindingCategory = "weak-kex"
	FindingProtocolV1             FindingCategory = "protocol-v1"
	FindingPermitUserEnvironment  FindingCategory = "permit-user-environment"
	FindingNoBanner               FindingCategory = "no-banner"
	FindingUnknown                FindingCategory = "unknown"
)

// Setting is the parsed record produced per non-comment line. Mirrors
// host_sshd_config's column shape exactly.
type Setting struct {
	Scope               Scope           `json:"scope"`
	MatchCriteria       string          `json:"match_criteria,omitempty"`
	Key                 string          `json:"key"`
	Value               string          `json:"value"`
	FindingCategory     FindingCategory `json:"finding_category,omitempty"`
	FilePath            string          `json:"file_path,omitempty"`
	FileHash            string          `json:"file_hash,omitempty"`
	RawLine             string          `json:"raw_line,omitempty"`
	LineNo              int             `json:"line_no"`
	IsSecurityCritical  bool            `json:"is_security_critical"`
	IsBaselineViolation bool            `json:"is_baseline_violation"`
}

// Collector is the read-only contract every per-OS implementation satisfies.
type Collector interface {
	Name() string
	Collect(ctx context.Context) ([]Setting, error)
}

// HashContents returns the SHA-256 hex of a sshd_config body. Drives
// drift detection between scans.
func HashContents(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// WeakCiphers is the curated set of cipher names CWE-327 considers
// broken under modern threat models. Drawn from Mozilla SSH Guidelines
// (Modern profile) and the OpenSSH 9.x deprecation list.
func WeakCiphers() []string {
	return []string{
		"3des-cbc",
		"aes128-cbc",
		"aes192-cbc",
		"aes256-cbc",
		"blowfish-cbc",
		"cast128-cbc",
		"arcfour",
		"arcfour128",
		"arcfour256",
		"rijndael-cbc@lysator.liu.se",
	}
}

// WeakMACs is the curated set of MAC names CWE-327 considers broken.
// All MD5-based MACs are out; non-ETM SHA-1 MACs are vulnerable to the
// known prepend-encrypt-then-mac timing attack.
func WeakMACs() []string {
	return []string{
		"hmac-md5",
		"hmac-md5-96",
		"hmac-md5-etm@openssh.com",
		"hmac-md5-96-etm@openssh.com",
		"hmac-sha1",
		"hmac-sha1-96",
		"umac-64@openssh.com",
		"umac-64-etm@openssh.com",
	}
}

// WeakKexAlgorithms is the curated set of broken/risky key-exchange
// algorithms. Drawn from RFC 8732 + Logjam-era guidance.
func WeakKexAlgorithms() []string {
	return []string{
		"diffie-hellman-group1-sha1",
		"diffie-hellman-group14-sha1",
		"diffie-hellman-group-exchange-sha1",
		"gss-gex-sha1-",
		"gss-group1-sha1-",
		"gss-group14-sha1-",
		"ecdh-sha2-nistp256", // NIST-curves — not "broken" but RFC 8732 deprecates
	}
}

// MaxRecommendedAuthTries is the CIS 5.2.4 ceiling for MaxAuthTries.
const MaxRecommendedAuthTries = 4

// MaxRecommendedLoginGraceSeconds is the CIS 5.2.21 ceiling for
// LoginGraceTime. Anything longer leaves an attacker more time to
// brute force interactive auth.
const MaxRecommendedLoginGraceSeconds = 60

// ClassifyDirective returns (finding, is_critical, is_violation) for
// a single (key, value) pair. The classification is conservative —
// any setting that weakens hardening is flagged so the audit pipeline
// can decide allow/deny.
func ClassifyDirective(key, value string) (FindingCategory, bool, bool) {
	k := normalizeKey(key)
	v := strings.ToLower(strings.TrimSpace(value))
	switch k {
	case "permitrootlogin":
		// `no` and `prohibit-password` are safe; everything else is a finding.
		if v != "no" && v != "prohibit-password" {
			return FindingRootLoginPermitted, true, true
		}
		return "", true, false
	case "passwordauthentication":
		if v == "yes" {
			return FindingPasswordAuthPermitted, true, true
		}
		return "", true, false
	case "permitemptypasswords":
		if v == "yes" {
			return FindingEmptyPasswordPermitted, true, true
		}
		return "", true, false
	case "x11forwarding":
		if v == "yes" {
			return FindingX11ForwardingEnabled, true, true
		}
		return "", true, false
	case "allowagentforwarding":
		if v == "yes" {
			return FindingAgentForwardingEnabled, true, true
		}
		return "", true, false
	case "allowtcpforwarding":
		if v == "yes" || v == "all" {
			return FindingTCPForwardingEnabled, true, true
		}
		return "", true, false
	case "hostbasedauthentication":
		if v == "yes" {
			return FindingHostBasedAuthEnabled, true, true
		}
		return "", true, false
	case "ignorerhosts":
		if v != "yes" {
			return FindingRhostsNotIgnored, true, true
		}
		return "", true, false
	case "maxauthtries":
		if n, err := strconv.Atoi(strings.TrimSpace(value)); err == nil &&
			n > MaxRecommendedAuthTries {
			return FindingExcessiveAuthAttempts, true, true
		}
		return "", true, false
	case "logingracetime":
		if isLongLoginGrace(value) {
			return FindingLongLoginGrace, true, true
		}
		return "", true, false
	case "ciphers":
		if listContainsAny(value, WeakCiphers()) {
			return FindingWeakCipher, true, true
		}
		return "", true, false
	case "macs":
		if listContainsAny(value, WeakMACs()) {
			return FindingWeakMAC, true, true
		}
		return "", true, false
	case "kexalgorithms":
		if listContainsAny(value, WeakKexAlgorithms()) {
			return FindingWeakKex, true, true
		}
		return "", true, false
	case "protocol":
		if strings.Contains(v, "1") {
			return FindingProtocolV1, true, true
		}
		return "", true, false
	case "permituserenvironment":
		if v == "yes" {
			return FindingPermitUserEnvironment, true, true
		}
		return "", true, false
	}
	return "", false, false
}

// normalizeKey lowercases the directive name. sshd treats directives
// case-insensitively but distros mix conventions (PermitRootLogin vs
// permitrootlogin) — normalising here keeps the audit join simple.
func normalizeKey(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// listContainsAny reports whether the comma-separated `list` contains
// any of the `wants` tokens. Comparison is case-insensitive on the
// element level.
func listContainsAny(list string, wants []string) bool {
	items := strings.FieldsFunc(list, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t'
	})
	have := make(map[string]bool, len(items))
	for _, it := range items {
		have[strings.ToLower(strings.TrimSpace(it))] = true
	}
	for _, w := range wants {
		if have[strings.ToLower(w)] {
			return true
		}
	}
	return false
}

// isLongLoginGrace parses LoginGraceTime. The value is either bare
// seconds, `Ns` (seconds), `Nm` (minutes), `Nh` (hours).
func isLongLoginGrace(value string) bool {
	v := strings.TrimSpace(value)
	if v == "" {
		return false
	}
	var mult int
	last := v[len(v)-1]
	switch last {
	case 's':
		mult = 1
	case 'm':
		mult = 60
	case 'h':
		mult = 3600
	default:
		// Bare integer = seconds.
		if n, err := strconv.Atoi(v); err == nil {
			return n > MaxRecommendedLoginGraceSeconds
		}
		return false
	}
	n, err := strconv.Atoi(v[:len(v)-1])
	if err != nil {
		return false
	}
	return n*mult > MaxRecommendedLoginGraceSeconds
}

// AnnotateSecurity sets the indexed booleans on a setting row from
// its already-populated key/value pair.
func AnnotateSecurity(s *Setting) {
	cat, crit, viol := ClassifyDirective(s.Key, s.Value)
	s.FindingCategory = cat
	s.IsSecurityCritical = crit
	s.IsBaselineViolation = viol
}

// SortSettings returns a deterministic ordering: file path, then line.
func SortSettings(ss []Setting) {
	sort.Slice(ss, func(i, j int) bool {
		if ss[i].FilePath != ss[j].FilePath {
			return ss[i].FilePath < ss[j].FilePath
		}
		return ss[i].LineNo < ss[j].LineNo
	})
}
