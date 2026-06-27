// Package winnpmrc audits `.npmrc` files across Windows, Linux,
// and macOS. An npm `_authToken` is a full-publish credential
// for any package the user can write to on the target registry;
// a stolen `~/.npmrc` is the textbook supply-chain compromise
// vector that enabled the 2022 `node-ipc`, `colors`, and `chalk`
// takeovers.
//
// File-based discovery is the deliberate design choice. The npm
// CLI walks the same files (plus `NPM_CONFIG_USERCONFIG` /
// `NPM_CONFIG_GLOBALCONFIG` env vars), so anything npm uses,
// this collector inventories. Tokens are NOT persisted — the row
// records the registry host and the token's first 4 chars
// (`npm_`/`oauth_`/etc) so the audit pipeline can correlate
// rotations without retaining the secret.
//
// Headline finding shapes (MITRE T1552.001 — Credentials in
// Files, T1195.002 — Compromise Software Supply Chain on token
// theft, T1565.002 — Transmitted Data Manipulation when
// `strict-ssl=false`):
//
//   - `is_auth_token=1` — `//registry/:_authToken=` row. Full
//     publish credential. Combined with a readable file =
//     immediate incident.
//   - `is_password_secret=1` — legacy basic-auth `_password=`
//     row (base64-encoded).
//   - `is_strict_ssl_disabled=1` — `strict-ssl=false` disables
//     TLS validation on every install (CWE-295 + T1565.002).
//   - `is_script_shell_override=1` — `script-shell` swapped to
//     a non-vendor binary; every `npm run` flows through it.
//   - `is_prefix_in_world_writable_dir=1` — `prefix` points at
//     a directory any local user can write (CWE-426 search-path
//     poisoning on `npm install -g`).
//
// Read-only by intent — we walk the .npmrc files only, never
// invoke `npm config`. (Project guideline 4.2.)
package winnpmrc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
)

// MaxEntries bounds per-scan output. A typical engineer carries
// 5-30 npmrc keys; the 4096 ceiling covers monorepos with many
// vendor registries.
const MaxEntries = 4096

// FileScope tags the file's role. Pinned to the
// host_npmrc_entries.file_scope CHECK enum.
type FileScope string

const (
	ScopeUser    FileScope = "user"
	ScopeGlobal  FileScope = "global"
	ScopeBuiltin FileScope = "builtin"
	ScopeProject FileScope = "project"
	ScopeUnknown FileScope = "unknown"
)

// EntryKind classifies each row. Pinned to the
// host_npmrc_entries.entry_kind CHECK enum.
type EntryKind string

const (
	EntryAuthToken     EntryKind = "auth-token"
	EntryPassword      EntryKind = "password"
	EntryUsername      EntryKind = "username"
	EntryRegistry      EntryKind = "registry"
	EntryScopeRegistry EntryKind = "scope-registry"
	EntrySetting       EntryKind = "setting"
	EntryUnknown       EntryKind = "unknown"
)

// Entry mirrors host_npmrc_entries' column shape exactly.
type Entry struct {
	Value                      string    `json:"value,omitempty"`
	Scope                      string    `json:"scope,omitempty"`
	FilePath                   string    `json:"file_path"`
	RegistryHost               string    `json:"registry_host,omitempty"`
	UserProfile                string    `json:"user_profile,omitempty"`
	FileScope                  FileScope `json:"file_scope"`
	EntryKind                  EntryKind `json:"entry_kind"`
	Key                        string    `json:"key"`
	FileHash                   string    `json:"file_hash"`
	FileMode                   int       `json:"file_mode,omitempty"`
	FileOwnerUID               int       `json:"file_owner_uid,omitempty"`
	IsAuthToken                bool      `json:"is_auth_token"`
	IsPasswordSecret           bool      `json:"is_password_secret"`
	IsStrictSSLDisabled        bool      `json:"is_strict_ssl_disabled"`
	IsScriptShellOverride      bool      `json:"is_script_shell_override"`
	IsPrefixInWorldWritableDir bool      `json:"is_prefix_in_world_writable_dir"`
	IsWorldReadable            bool      `json:"is_world_readable"`
	IsGroupReadable            bool      `json:"is_group_readable"`
	IsCredentialExposureRisk   bool      `json:"is_credential_exposure_risk"`
}

// Collector is the read-only contract every implementation satisfies.
type Collector interface {
	Name() string
	Collect(ctx context.Context) ([]Entry, error)
}

// HashContents returns the SHA-256 hex of the file body.
func HashContents(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// AuthTokenPrefix returns the first 4 chars of an npm auth-
// token so the audit pipeline can classify the family
// (`npm_`/`oauth`/`ghp_`) without retaining the secret. Empty
// input returns "".
func AuthTokenPrefix(token string) string {
	t := strings.TrimSpace(token)
	if len(t) < 4 {
		return ""
	}
	return t[:4]
}

// RegistryHostFromKey extracts the host from a registry-keyed
// line like `//registry.npmjs.org/:_authToken=...`. The leading
// `//` is stripped and the path-trailing `/` is dropped.
func RegistryHostFromKey(key string) string {
	k := strings.TrimSpace(key)
	if !strings.HasPrefix(k, "//") {
		return ""
	}
	k = strings.TrimPrefix(k, "//")
	// `host[:port]/path/:setting` → strip the `:setting` and the
	// trailing path. The first `:` after the host[:port] segment
	// marks the setting separator.
	host := k
	if i := strings.Index(host, "/:"); i >= 0 {
		host = host[:i]
	}
	if i := strings.IndexByte(host, '/'); i >= 0 {
		host = host[:i]
	}
	// Strip port.
	if u, err := url.Parse("https://" + host); err == nil && u.Host != "" {
		if h := u.Hostname(); h != "" {
			return h
		}
	}
	return host
}

// SettingFromKey returns the trailing `:setting` portion of a
// registry-keyed line (`_authToken` / `_password` / etc).
// Returns "" for non-registry keys.
func SettingFromKey(key string) string {
	k := strings.TrimSpace(key)
	if !strings.HasPrefix(k, "//") {
		return ""
	}
	if i := strings.LastIndex(k, "/:"); i >= 0 {
		return strings.TrimPrefix(k[i+1:], ":")
	}
	return ""
}

// WorldWritableDirRoots is the curated set of directory prefixes
// any local user can write into.
func WorldWritableDirRoots() []string {
	return []string{
		`c:\users\public\`,
		`c:\windows\temp\`,
		`c:\temp\`,
		`%temp%\`,
		`%public%\`,
		"/tmp/",
		"/var/tmp/",
	}
}

// IsWorldWritableDir reports whether `dir` resolves under one
// of the curated roots.
func IsWorldWritableDir(dir string) bool {
	v := strings.ToLower(strings.TrimSpace(dir))
	if v == "" {
		return false
	}
	cleaned := filepath.ToSlash(v)
	for _, root := range WorldWritableDirRoots() {
		r := strings.ToLower(filepath.ToSlash(root))
		if strings.HasPrefix(cleaned, r) {
			return true
		}
	}
	return false
}

// AnnotateSecurity sets the derived booleans on an Entry that
// has its raw fields populated. The caller must set FileMode
// before calling.
func AnnotateSecurity(e *Entry) {
	if e.FileMode != 0 {
		e.IsWorldReadable = e.FileMode&0o004 != 0
		e.IsGroupReadable = e.FileMode&0o040 != 0
	}
	switch e.EntryKind {
	case EntryAuthToken:
		e.IsAuthToken = true
		if e.IsWorldReadable || e.IsGroupReadable {
			e.IsCredentialExposureRisk = true
		}
	case EntryPassword:
		e.IsPasswordSecret = true
		if e.IsWorldReadable || e.IsGroupReadable {
			e.IsCredentialExposureRisk = true
		}
	case EntrySetting:
		switch strings.ToLower(e.Key) {
		case "strict-ssl":
			if isBoolFalse(e.Value) {
				e.IsStrictSSLDisabled = true
				e.IsCredentialExposureRisk = true
			}
		case "script-shell":
			if strings.TrimSpace(e.Value) != "" {
				e.IsScriptShellOverride = true
			}
		case "prefix":
			if IsWorldWritableDir(e.Value) {
				e.IsPrefixInWorldWritableDir = true
				e.IsCredentialExposureRisk = true
			}
		}
	case EntryUsername, EntryRegistry, EntryScopeRegistry, EntryUnknown:
		// no flag rollups
	}
}

func isBoolFalse(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "false", "no", "off", "0":
		return true
	}
	return false
}

// SortEntries returns a deterministic ordering by file path,
// kind, then key.
func SortEntries(es []Entry) {
	sort.Slice(es, func(i, j int) bool {
		if es[i].FilePath != es[j].FilePath {
			return es[i].FilePath < es[j].FilePath
		}
		if es[i].EntryKind != es[j].EntryKind {
			return es[i].EntryKind < es[j].EntryKind
		}
		return es[i].Key < es[j].Key
	})
}
