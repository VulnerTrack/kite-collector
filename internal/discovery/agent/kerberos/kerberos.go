// Package kerberos inventories Kerberos client configuration from
// /etc/krb5.conf and every drop-in under /etc/krb5.conf.d/.
//
// Kerberos is the universal authentication backbone for Active
// Directory and FreeIPA. The client config tells every workstation
// which KDCs to talk to, what crypto to accept, and how long tickets
// should remain valid. Tampering here is reconnaissance-and-evasion
// preparation:
//
//   - Pointing the host at an attacker-controlled KDC sets up
//     credential capture (T1558).
//   - Re-enabling `allow_weak_crypto=true` re-permits des-cbc tickets
//     (CWE-327) — known-plaintext attacks become practical again.
//   - Extending ticket_lifetime defeats credential-rotation controls
//     (CWE-521).
//   - Enabling `dns_lookup_realm=true` allows DNS-based realm spoofing
//     (T1568).
//
// Every collector is **read-only by intent** — it parses krb5.conf
// + drop-ins, never invokes kinit or modifies anything. Read-only is
// enforced by guideline 4.2 of the kite-collector project.
//
// Setting rows feed the audit pipeline:
//
//   - `is_kdc_or_admin=1` rows enumerate the attacker's recon target
//     set (realms, KDC IPs/hostnames, admin_server entries).
//   - `is_weak_crypto=1` flags allow_weak_crypto + permit-old-enctype
//     settings.
//   - `is_long_ticket_lifetime=1` flags lifetimes > 24h.
//   - File hash drift on any krb5.conf = realm trust topology
//     modification event.
package kerberos

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"time"
)

// MaxSettings bounds per-scan output. A typical multi-realm krb5.conf
// has ~50 directives; the 1024 ceiling covers heavyweight enterprise
// configs with dozens of trusted realms.
const MaxSettings = 1024

// Section identifies which top-level [section] the setting lives in.
// Pinned to the host_kerberos_config.section CHECK enum.
type Section string

const (
	SectionLibdefaults Section = "libdefaults"
	SectionRealms      Section = "realms"
	SectionDomainRealm Section = "domain_realm"
	SectionAppdefaults Section = "appdefaults"
	SectionCAPaths     Section = "capaths"
	SectionPlugins     Section = "plugins"
	SectionLogging     Section = "logging"
	SectionLogin       Section = "login"
	SectionUnknown     Section = "unknown"
)

// Setting is the parsed record produced per non-comment line. Mirrors
// host_kerberos_config's column shape exactly.
type Setting struct {
	FilePath             string  `json:"file_path,omitempty"`
	Realm                string  `json:"realm,omitempty"`
	Key                  string  `json:"key"`
	Value                string  `json:"value"`
	Section              Section `json:"section"`
	FileHash             string  `json:"file_hash,omitempty"`
	RawLine              string  `json:"raw_line,omitempty"`
	LineNo               int     `json:"line_no"`
	IsDefaultRealm       bool    `json:"is_default_realm"`
	IsWeakCrypto         bool    `json:"is_weak_crypto"`
	IsLongTicketLifetime bool    `json:"is_long_ticket_lifetime"`
	IsDNSLookupEnabled   bool    `json:"is_dns_lookup_enabled"`
	IsKDCOrAdmin         bool    `json:"is_kdc_or_admin"`
}

// Collector is the read-only contract every per-OS implementation satisfies.
type Collector interface {
	Name() string
	Collect(ctx context.Context) ([]Setting, error)
}

// HashContents returns the SHA-256 hex of a krb5.conf body. Drives
// drift detection between scans.
func HashContents(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// MaxRecommendedTicketLifetime is the longest ticket_lifetime we
// consider safe. MIT Kerberos defaults to 10h; 24h is the credential-
// rotation ceiling most enterprise policies use.
const MaxRecommendedTicketLifetime = 24 * time.Hour

// WeakCryptoSwitches is the curated set of krb5.conf keys / values
// that re-enable broken encryption families. Their presence flips
// `is_weak_crypto=1`.
func WeakCryptoSwitches() []string {
	return []string{
		"allow_weak_crypto",
		"permitted_enctypes",   // any value containing des-* or rc4
		"default_tkt_enctypes", // ditto
		"default_tgs_enctypes", // ditto
	}
}

// IsWeakCryptoSetting reports whether a (key, value) pair represents a
// weak-crypto switch. Both `allow_weak_crypto=true` and any
// `*_enctypes` line whose value mentions a known-broken algorithm
// trigger the flag.
func IsWeakCryptoSetting(key, value string) bool {
	k := strings.ToLower(strings.TrimSpace(key))
	v := strings.ToLower(strings.TrimSpace(value))
	if k == "allow_weak_crypto" {
		return v == "true" || v == "yes" || v == "1"
	}
	if k == "permitted_enctypes" || k == "default_tkt_enctypes" ||
		k == "default_tgs_enctypes" {
		for _, weak := range []string{"des-", "rc4-", "arcfour"} {
			if strings.Contains(v, weak) {
				return true
			}
		}
	}
	return false
}

// ParseTicketLifetime decodes the krb5 `30s` / `5m` / `10h` / `1d`
// duration shorthand into a Go time.Duration. Returns (0, false)
// when the input doesn't parse.
//
// The grammar (per krb5.conf(5)):
//
//	N[smhd]    — seconds, minutes, hours, days
//	HH:MM[:SS] — clock-style
//	N          — bare seconds
func ParseTicketLifetime(s string) (time.Duration, bool) {
	v := strings.TrimSpace(s)
	if v == "" {
		return 0, false
	}
	// Clock-style HH:MM[:SS].
	if strings.Contains(v, ":") {
		parts := strings.Split(v, ":")
		if len(parts) < 2 || len(parts) > 3 {
			return 0, false
		}
		var h, m, sec int
		if _, err := scan(parts[0], &h); err != nil {
			return 0, false
		}
		if _, err := scan(parts[1], &m); err != nil {
			return 0, false
		}
		if len(parts) == 3 {
			if _, err := scan(parts[2], &sec); err != nil {
				return 0, false
			}
		}
		return time.Duration(h)*time.Hour +
			time.Duration(m)*time.Minute +
			time.Duration(sec)*time.Second, true
	}
	// N[smhd].
	if n := len(v); n > 0 {
		last := v[n-1]
		var mult time.Duration
		switch last {
		case 's':
			mult = time.Second
		case 'm':
			mult = time.Minute
		case 'h':
			mult = time.Hour
		case 'd':
			mult = 24 * time.Hour
		}
		if mult != 0 {
			var n int
			if _, err := scan(v[:len(v)-1], &n); err == nil {
				return time.Duration(n) * mult, true
			}
			return 0, false
		}
	}
	// Bare integer seconds.
	var n int
	if _, err := scan(v, &n); err == nil {
		return time.Duration(n) * time.Second, true
	}
	return 0, false
}

// scan is a tiny strconv shim so the parser doesn't need a dependency
// import for one numeric conversion.
func scan(s string, out *int) (int, error) {
	var n, sign int
	sign = 1
	for i := 0; i < len(s); i++ {
		c := s[i]
		if i == 0 && c == '-' {
			sign = -1
			continue
		}
		if c < '0' || c > '9' {
			return 0, errBadNumber{}
		}
		n = n*10 + int(c-'0')
	}
	*out = sign * n
	return n, nil
}

type errBadNumber struct{}

func (errBadNumber) Error() string { return "not a number" }

// IsLongTicketLifetimeValue reports whether the lifetime exceeds
// MaxRecommendedTicketLifetime. Used for ticket_lifetime + renew_lifetime.
func IsLongTicketLifetimeValue(value string) bool {
	d, ok := ParseTicketLifetime(value)
	if !ok {
		return false
	}
	return d > MaxRecommendedTicketLifetime
}

// IsDNSLookupKey reports whether the key is one of the DNS-based-realm
// lookup switches. Used to flag `dns_lookup_realm=true` etc.
func IsDNSLookupKey(key string) bool {
	switch strings.ToLower(strings.TrimSpace(key)) {
	case "dns_lookup_realm", "dns_lookup_kdc", "dns_canonicalize_hostname":
		return true
	}
	return false
}

// IsDNSLookupEnabledSetting reports whether (key, value) flips DNS
// realm lookup on. True values are the krb5 boolean spellings.
func IsDNSLookupEnabledSetting(key, value string) bool {
	if !IsDNSLookupKey(key) {
		return false
	}
	v := strings.ToLower(strings.TrimSpace(value))
	return v == "true" || v == "yes" || v == "1"
}

// IsKDCOrAdminKey reports whether the key enumerates a KDC host. Used
// to mark realm-trust topology rows.
func IsKDCOrAdminKey(key string) bool {
	switch strings.ToLower(strings.TrimSpace(key)) {
	case "kdc", "admin_server", "master_kdc", "kpasswd_server":
		return true
	}
	return false
}

// AnnotateSecurity sets the indexed booleans on a setting row from
// its already-populated fields.
func AnnotateSecurity(s *Setting) {
	s.IsWeakCrypto = IsWeakCryptoSetting(s.Key, s.Value)
	s.IsDNSLookupEnabled = IsDNSLookupEnabledSetting(s.Key, s.Value)
	s.IsKDCOrAdmin = IsKDCOrAdminKey(s.Key)
	if strings.EqualFold(s.Key, "ticket_lifetime") ||
		strings.EqualFold(s.Key, "renew_lifetime") {
		s.IsLongTicketLifetime = IsLongTicketLifetimeValue(s.Value)
	}
	if strings.EqualFold(s.Key, "default_realm") {
		s.IsDefaultRealm = true
	}
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
