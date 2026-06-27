// Package wingithubcli audits the GitHub CLI's `hosts.yml`
// credential file across Windows, Linux, and macOS. `gh` stores
// a long-lived OAuth token per host in plain YAML; the token
// holds full repo write + workflow-trigger on every org it can
// reach, so a stolen `hosts.yml` is a textbook supply-chain
// pivot vector.
//
// File-based discovery is the deliberate design choice. `gh`
// reads exactly the same files (plus the `GH_CONFIG_DIR` env
// override), so anything `gh` uses, this collector inventories.
// The token VALUE is never persisted — the row records the
// host, the gh-user, and the token's 4-char family prefix
// (`ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_`) so the audit pipeline
// can correlate rotations without holding the secret.
//
// Headline finding shapes (MITRE T1552.001 — Credentials in
// Files, T1078.004 — Valid Cloud Accounts):
//
//   - `is_oauth_token_present=1` — `oauth_token:` row found.
//   - `is_unencrypted_token=1` — token present AND file is
//     world- or group-readable. The rolled-up immediate-incident
//     flag.
//   - `is_enterprise_host=1` — host is NOT `github.com`,
//     `api.github.com`, or `ghe.com`. Useful for blast-radius
//     scoping (one stolen GHES token usually reaches more
//     internal repos than a `github.com` PAT).
//   - `is_credential_exposure_risk=1` — alias kept for
//     cross-collector reporting parity.
//
// Read-only by intent — we walk hosts.yml only, never invoke
// `gh auth`. (Project guideline 4.2.)
package wingithubcli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
)

// MaxRows bounds per-scan output. A typical workstation has
// 1-3 hosts; the 256 ceiling covers shared dev bastions with
// many enterprise instances.
const MaxRows = 256

// Row mirrors host_gh_cli_hosts' column shape exactly.
type Row struct {
	GitProtocol              string `json:"git_protocol,omitempty"`
	FileHash                 string `json:"file_hash"`
	TokenFamily              string `json:"token_family,omitempty"`
	FilePath                 string `json:"file_path"`
	UserProfile              string `json:"user_profile,omitempty"`
	Host                     string `json:"host"`
	GhUser                   string `json:"gh_user,omitempty"`
	FileOwnerUID             int    `json:"file_owner_uid,omitempty"`
	FileMode                 int    `json:"file_mode,omitempty"`
	IsEnterpriseHost         bool   `json:"is_enterprise_host"`
	IsOAuthTokenPresent      bool   `json:"is_oauth_token_present"`
	IsWorldReadable          bool   `json:"is_world_readable"`
	IsGroupReadable          bool   `json:"is_group_readable"`
	IsUnencryptedToken       bool   `json:"is_unencrypted_token"`
	IsCredentialExposureRisk bool   `json:"is_credential_exposure_risk"`
}

// Collector is the read-only contract every implementation satisfies.
type Collector interface {
	Name() string
	Collect(ctx context.Context) ([]Row, error)
}

// HashContents returns the SHA-256 hex of the file body.
func HashContents(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// TokenFamilyPrefix returns the first 4 chars of a GitHub OAuth
// token so the audit pipeline can classify the family without
// retaining the secret. Empty input returns "".
func TokenFamilyPrefix(token string) string {
	t := strings.TrimSpace(token)
	if len(t) < 4 {
		return ""
	}
	return t[:4]
}

// FirstPartyHosts is the curated set of github.com-owned hosts.
// Anything NOT in this set flags is_enterprise_host=1.
func FirstPartyHosts() []string {
	return []string{
		"github.com",
		"api.github.com",
		"ghe.com",
	}
}

// IsFirstPartyHost reports whether `host` is in the curated
// first-party set. Case-insensitive.
func IsFirstPartyHost(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "" {
		return false
	}
	for _, t := range FirstPartyHosts() {
		if h == t {
			return true
		}
	}
	return false
}

// AnnotateSecurity sets the derived booleans on a Row that has
// its raw fields populated. The caller must set FileMode before
// calling.
func AnnotateSecurity(r *Row) {
	if r.FileMode != 0 {
		r.IsWorldReadable = r.FileMode&0o004 != 0
		r.IsGroupReadable = r.FileMode&0o040 != 0
	}
	r.IsEnterpriseHost = r.Host != "" && !IsFirstPartyHost(r.Host)
	if r.IsOAuthTokenPresent && (r.IsWorldReadable || r.IsGroupReadable) {
		r.IsUnencryptedToken = true
		r.IsCredentialExposureRisk = true
	}
}

// SortRows returns a deterministic ordering by file path, host,
// then user.
func SortRows(rs []Row) {
	sort.Slice(rs, func(i, j int) bool {
		if rs[i].FilePath != rs[j].FilePath {
			return rs[i].FilePath < rs[j].FilePath
		}
		if rs[i].Host != rs[j].Host {
			return rs[i].Host < rs[j].Host
		}
		return rs[i].GhUser < rs[j].GhUser
	})
}
