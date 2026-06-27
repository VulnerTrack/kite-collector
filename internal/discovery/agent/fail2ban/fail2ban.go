// Package fail2ban inventories fail2ban jail definitions from the
// canonical configuration chain: jail.conf (vendor defaults),
// jail.local (admin overrides), and jail.d/*.conf drop-ins.
//
// fail2ban is the standard Linux brute-force mitigation. Its
// failure modes are unusual — the tool itself rarely breaks; it's
// the *configuration* that erodes:
//
//   - The vendor default jail.conf ships every jail disabled
//     (`enabled = false`). Admins enable a few in jail.local and
//     the rest stay off — including jails that *would* protect a
//     service the host runs but the admin forgot about.
//   - `ignoreip` accumulates entries over time. A `10.0.0.0/8`
//     here, a `0.0.0.0/0` "just for this debug session" there;
//     eventually anyone is whitelisted.
//   - `maxretry` defaults to 5. Bumping to 10 or 20 makes online
//     brute force trivial.
//
// MITRE T1110 (Brute Force, defender side) and T1562.001 (Disable
// or Modify Tools). The audit pipeline alerts on the union of
// "fail2ban installed" (this table non-empty) AND
// "is_critical_jail_disabled=1" — meaning the operator chose to run
// fail2ban but turned off the jail that would actually help.
//
// Read-only by intent — we parse the .conf chain only, never invoke
// fail2ban-client. (Project guideline 4.2.)
package fail2ban

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
)

// MaxRows bounds per-scan output. A typical install ships 30-50
// jails defined in jail.conf, with a handful enabled in jail.local.
// The 512 ceiling covers heavily-customised deployments without
// bloating SQLite writes.
const MaxRows = 512

// DefaultLooseRetryThreshold is the policy ceiling for `maxretry`.
// Anything above this flags as `has_loose_threshold=1`. Five matches
// the upstream default; we treat seven and above as a regression.
const DefaultLooseRetryThreshold = 6

// DefaultMinBantimeSeconds is the policy floor for `bantime`.
// Bans shorter than 10 minutes can be brute-force-evaded by an
// attacker pacing requests.
const DefaultMinBantimeSeconds = 600

// SectionKind classifies a jail section. Pinned to the
// host_fail2ban_jails.section_kind CHECK enum.
type SectionKind string

const (
	SectionDefault SectionKind = "default"
	SectionJail    SectionKind = "jail"
	SectionUnknown SectionKind = "unknown"
)

// Jail mirrors host_fail2ban_jails' column shape exactly.
type Jail struct {
	IgnoreIP               string      `json:"ignore_ip,omitempty"`
	FileHash               string      `json:"file_hash"`
	SectionName            string      `json:"section_name"`
	SectionKind            SectionKind `json:"section_kind"`
	Enabled                string      `json:"enabled,omitempty"`
	Port                   string      `json:"port,omitempty"`
	FilterName             string      `json:"filter_name,omitempty"`
	LogPath                string      `json:"log_path,omitempty"`
	Backend                string      `json:"backend,omitempty"`
	Action                 string      `json:"action,omitempty"`
	FilePath               string      `json:"file_path"`
	FindTimeSeconds        int         `json:"find_time_seconds,omitempty"`
	BanTimeSeconds         int         `json:"ban_time_seconds,omitempty"`
	MaxRetry               int         `json:"max_retry,omitempty"`
	ActionCount            int         `json:"action_count,omitempty"`
	IsEnabled              bool        `json:"is_enabled"`
	IsCriticalJail         bool        `json:"is_critical_jail"`
	IsCriticalJailDisabled bool        `json:"is_critical_jail_disabled"`
	HasLooseThreshold      bool        `json:"has_loose_threshold"`
	HasShortBantime        bool        `json:"has_short_bantime"`
	IsPermanentBan         bool        `json:"is_permanent_ban"`
	IsIgnoreIPWorldExposed bool        `json:"is_ignoreip_world_exposed"`
}

// Collector is the read-only contract every implementation satisfies.
type Collector interface {
	Name() string
	Collect(ctx context.Context) ([]Jail, error)
}

// HashContents returns the SHA-256 hex of a config-file body.
func HashContents(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// NormalizeSectionKind maps a [section] header to our enum. fail2ban
// reserves [DEFAULT] for inheritance; everything else is a jail.
func NormalizeSectionKind(s string) SectionKind {
	name := strings.ToUpper(strings.TrimSpace(s))
	switch name {
	case "":
		return SectionUnknown
	case "DEFAULT", "INCLUDES":
		return SectionDefault
	}
	return SectionJail
}

// CriticalJails is the curated set of jail names whose disabled
// state is alert-worthy. These protect surfaces that almost every
// host exposes (or that should never be on the internet at all).
//
// The list deliberately uses the upstream jail names rather than
// service names — that way `sshd-ddos` flags too.
func CriticalJails() []string {
	return []string{
		"sshd", "sshd-ddos",
		"postfix", "postfix-sasl",
		"dovecot",
		"apache-auth", "apache-overflows", "apache-noscript",
		"nginx-http-auth", "nginx-limit-req",
		"vsftpd", "proftpd",
		"recidive",
	}
}

// IsCriticalJailName reports whether a section name is in the
// curated CriticalJails list. Case-insensitive.
func IsCriticalJailName(name string) bool {
	lower := strings.ToLower(strings.TrimSpace(name))
	for _, c := range CriticalJails() {
		if lower == c {
			return true
		}
	}
	return false
}

// IsBoolTrue maps fail2ban's boolean accent — true / false / yes /
// no / 1 / 0 — to Go bool. Empty input returns false.
func IsBoolTrue(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "true", "yes", "on", "1":
		return true
	}
	return false
}

// ParseDuration converts a fail2ban duration token into seconds.
// fail2ban accepts:
//
//	120          → seconds
//	10m          → 10 * 60
//	1h           → 3600
//	1d           → 86400
//	-1           → permanent ban (returns -1)
//
// Unknown forms return 0.
func ParseDuration(s string) int {
	t := strings.ToLower(strings.TrimSpace(s))
	if t == "" {
		return 0
	}
	if t == "-1" || strings.HasPrefix(t, "perm") {
		return -1
	}
	var multiplier int
	switch last := t[len(t)-1]; last {
	case 's':
		multiplier = 1
		t = t[:len(t)-1]
	case 'm':
		multiplier = 60
		t = t[:len(t)-1]
	case 'h':
		multiplier = 3600
		t = t[:len(t)-1]
	case 'd':
		multiplier = 86400
		t = t[:len(t)-1]
	case 'w':
		multiplier = 86400 * 7
		t = t[:len(t)-1]
	case 'y':
		multiplier = 86400 * 365
		t = t[:len(t)-1]
	default:
		multiplier = 1
	}
	n := 0
	for _, c := range strings.TrimSpace(t) {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	return n * multiplier
}

// IsIgnoreIPWorldExposed reports whether the `ignoreip` value
// whitelists the internet — i.e. contains a `/0` prefix or the
// `0.0.0.0/0` / `::/0` shorthand. fail2ban also accepts `0.0.0.0`
// (bare) which we treat the same way.
func IsIgnoreIPWorldExposed(ip string) bool {
	for _, tok := range strings.Fields(ip) {
		t := strings.ToLower(strings.TrimSpace(tok))
		if strings.HasSuffix(t, "/0") {
			return true
		}
		if t == "0.0.0.0" || t == "::" {
			return true
		}
	}
	return false
}

// AnnotateSecurity sets the derived booleans on a Jail that has its
// raw fields populated.
func AnnotateSecurity(j *Jail) {
	j.IsEnabled = IsBoolTrue(j.Enabled)
	j.IsCriticalJail = j.SectionKind == SectionJail && IsCriticalJailName(j.SectionName)
	j.IsCriticalJailDisabled = j.IsCriticalJail && !j.IsEnabled
	if j.MaxRetry > DefaultLooseRetryThreshold {
		j.HasLooseThreshold = true
	}
	switch {
	case j.BanTimeSeconds == -1:
		j.IsPermanentBan = true
		j.HasShortBantime = false
	case j.BanTimeSeconds > 0 && j.BanTimeSeconds < DefaultMinBantimeSeconds:
		j.HasShortBantime = true
	}
	j.IsIgnoreIPWorldExposed = IsIgnoreIPWorldExposed(j.IgnoreIP)
}

// SortJails returns a deterministic ordering by file path then
// section name.
func SortJails(js []Jail) {
	sort.Slice(js, func(i, j int) bool {
		if js[i].FilePath != js[j].FilePath {
			return js[i].FilePath < js[j].FilePath
		}
		return js[i].SectionName < js[j].SectionName
	})
}
