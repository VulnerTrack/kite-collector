// Package pkgrepo inventories every package-manager repository
// configured on a host across Linux (APT, yum/dnf, zypper, apk,
// pacman), language ecosystems (pip, npm, cargo, gem, go-module),
// macOS (brew taps), and Windows (winget, chocolatey).
//
// Repositories are the supply-chain attack surface (MITRE T1195 —
// Supply Chain Compromise). An attacker who controls a repo or who
// inserts a HTTP MitM hop on its update path can ship a malicious
// package on the host's next `apt upgrade`. This collector inventories
// every configured source; the audit pipeline correlates that against
// the host's expected baseline and flags drift.
//
// Every collector is **read-only by intent** — it parses repo files,
// never runs `apt-add-repository` or `dnf config-manager`. Read-only
// is enforced by guideline 4.2 of the kite-collector project.
//
// Repo rows feed the audit pipeline:
//
//   - T1195 — `is_third_party=1` flags repos that are NOT the canonical
//     OS mirror. PPAs/COPRs/external taps are common Linux delivery
//     channels for both legitimate software and malware.
//   - CWE-319 (Cleartext Transmission) — `is_https=0` flags HTTP-only
//     mirrors. MitM-able by any router on the path.
//   - CWE-345 (Insufficient Verification) — `gpg_check=0` flags repos
//     installed with signature verification disabled.
//   - Drift events — file_hash change on any repo file = the host's
//     update path was modified.
package pkgrepo

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"sort"
	"strings"
)

// MaxRepos bounds per-scan output. A typical Linux host has 5-15
// distro repos + a handful of PPAs + per-user language ecosystems.
// 512 covers heavyweight setups without bloating the SQLite write path.
const MaxRepos = 512

// Ecosystem identifies the package manager. Pinned to the
// host_package_repos.ecosystem CHECK enum.
type Ecosystem string

const (
	EcosystemAPT        Ecosystem = "apt"
	EcosystemYum        Ecosystem = "yum"
	EcosystemDNF        Ecosystem = "dnf"
	EcosystemZypper     Ecosystem = "zypper"
	EcosystemAPK        Ecosystem = "apk"
	EcosystemPacman     Ecosystem = "pacman"
	EcosystemBrew       Ecosystem = "brew"
	EcosystemPip        Ecosystem = "pip"
	EcosystemNPM        Ecosystem = "npm"
	EcosystemCargo      Ecosystem = "cargo"
	EcosystemGem        Ecosystem = "gem"
	EcosystemGoModule   Ecosystem = "go-module"
	EcosystemSnap       Ecosystem = "snap"
	EcosystemFlatpak    Ecosystem = "flatpak"
	EcosystemWinget     Ecosystem = "winget"
	EcosystemChocolatey Ecosystem = "chocolatey"
	EcosystemUnknown    Ecosystem = "unknown"
)

// Repo is the cross-ecosystem record. Mirrors host_package_repos'
// column shape exactly.
type Repo struct {
	UserScope     string    `json:"user_scope,omitempty"`
	Name          string    `json:"name"`
	URL           string    `json:"url"`
	Distribution  string    `json:"distribution,omitempty"`
	Ecosystem     Ecosystem `json:"ecosystem"`
	RawLine       string    `json:"raw_line,omitempty"`
	SignedBy      string    `json:"signed_by,omitempty"`
	FileHash      string    `json:"file_hash,omitempty"`
	FilePath      string    `json:"file_path,omitempty"`
	Components    []string  `json:"components,omitempty"`
	Architectures []string  `json:"architectures,omitempty"`
	LineNo        int       `json:"line_no"`
	IsThirdParty  bool      `json:"is_third_party"`
	IsSource      bool      `json:"is_source"`
	IsEnabled     bool      `json:"is_enabled"`
	GPGCheck      bool      `json:"gpg_check"`
	IsHTTPS       bool      `json:"is_https"`
}

// Collector is the read-only contract every per-OS implementation satisfies.
type Collector interface {
	Name() string
	Collect(ctx context.Context) ([]Repo, error)
}

// EncodeStringList returns a JSON array suitable for the *_json columns.
// Empty input always emits "[]" so the column is never NULL.
func EncodeStringList(ss []string) string {
	if len(ss) == 0 {
		return "[]"
	}
	b, err := json.Marshal(ss)
	if err != nil {
		return "[]"
	}
	return string(b)
}

// HashContents returns the SHA-256 hex of a repo definition file.
// Drives drift detection between scans.
func HashContents(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// CanonicalAPTHosts is the curated list of upstream Debian/Ubuntu
// mirrors. URLs matching these are NOT flagged as third-party.
// Anything else is third-party by definition.
func CanonicalAPTHosts() []string {
	return []string{
		"deb.debian.org",
		"archive.ubuntu.com",
		"security.ubuntu.com",
		"ports.ubuntu.com",
		"security.debian.org",
		"cdn-fastly.deb.debian.org",
		"www.deb.debian.org",
	}
}

// CanonicalYumHosts is the curated list of Fedora/RHEL/CentOS/Rocky/
// Alma upstream mirrors.
func CanonicalYumHosts() []string {
	return []string{
		"mirrors.fedoraproject.org",
		"download.fedoraproject.org",
		"mirror.centos.org",
		"vault.centos.org",
		"dl.rockylinux.org",
		"repo.almalinux.org",
		"cdn.redhat.com",
		"cdn-public.redhat.com",
	}
}

// IsCanonicalUpstream reports whether the URL points to a known
// upstream OS mirror for the given ecosystem.
func IsCanonicalUpstream(ecosystem Ecosystem, rawURL string) bool {
	host := hostOf(rawURL)
	if host == "" {
		return false
	}
	switch ecosystem {
	case EcosystemAPT:
		return containsHost(CanonicalAPTHosts(), host)
	case EcosystemYum, EcosystemDNF:
		return containsHost(CanonicalYumHosts(), host)
	case EcosystemPip:
		return host == "pypi.org" || host == "files.pythonhosted.org"
	case EcosystemNPM:
		return host == "registry.npmjs.org"
	case EcosystemCargo:
		return host == "crates.io" || host == "static.crates.io"
	case EcosystemGem:
		return host == "rubygems.org" || host == "api.rubygems.org"
	case EcosystemGoModule:
		return host == "proxy.golang.org" || host == "sum.golang.org"
	case EcosystemZypper, EcosystemAPK, EcosystemPacman, EcosystemBrew,
		EcosystemSnap, EcosystemFlatpak, EcosystemWinget,
		EcosystemChocolatey, EcosystemUnknown:
		// No curated upstream list for these (yet) — treat every URL
		// as third-party so the audit pipeline still flags it for review.
		return false
	}
	return false
}

func hostOf(rawURL string) string {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u == nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

func containsHost(haystack []string, want string) bool {
	for _, h := range haystack {
		if strings.EqualFold(h, want) {
			return true
		}
	}
	return false
}

// IsHTTPSURL reports whether the URL uses HTTPS transport. Empty
// or unparseable URLs return false (conservative).
func IsHTTPSURL(rawURL string) bool {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u == nil {
		return false
	}
	return strings.EqualFold(u.Scheme, "https")
}

// AnnotateSecurity sets the indexed booleans on a repo row from its
// already-populated fields. Centralised so the flags don't drift
// between sources.
func AnnotateSecurity(r *Repo) {
	r.IsHTTPS = IsHTTPSURL(r.URL)
	r.IsThirdParty = !IsCanonicalUpstream(r.Ecosystem, r.URL)
}

// SortRepos returns a deterministic ordering: ecosystem, name, url.
func SortRepos(rs []Repo) {
	sort.Slice(rs, func(i, j int) bool {
		if rs[i].Ecosystem != rs[j].Ecosystem {
			return rs[i].Ecosystem < rs[j].Ecosystem
		}
		if rs[i].Name != rs[j].Name {
			return rs[i].Name < rs[j].Name
		}
		return rs[i].URL < rs[j].URL
	})
}
