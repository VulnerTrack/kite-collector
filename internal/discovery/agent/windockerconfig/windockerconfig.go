// Package windockerconfig audits the per-user Docker CLI
// configuration at `~/.docker/config.json` across Windows, Linux,
// and macOS. The Docker CLI stores registry credentials,
// credential-helper bindings, HTTP proxies, and plugin directory
// extensions here; each surface has a distinct security shape.
//
// File-based discovery is the deliberate design choice. The
// Docker CLI walks the same file, so any registry credential the
// CLI can use, this collector inventories. Drift between scans
// captures credential rotations / additions / removals via the
// file's SHA-256.
//
// Headline finding shapes (MITRE T1552.001 — Credentials in
// Files, T1048 — Exfiltration Over Alternative Protocol for
// proxy redirects, T1574.005 — Hijack Execution Flow for plugin
// search paths):
//
//   - `entry_kind='auth'` + `has_inline_auth=1` — the
//     credential store contains base64(`username:password`) in
//     plaintext on disk. One readable file = registry
//     compromise.
//   - `entry_kind='cred-helper'` + `is_secure_credential_helper=0`
//     — the helper name isn't in the curated secure set; the
//     credential might live in plaintext.
//   - `entry_kind='proxy'` + `proxy_target_is_external=1` — the
//     proxy URL points outside the RFC1918 / localhost set;
//     potential exfil channel.
//   - `entry_kind='cli-plugin-dir'` + `is_world_writable_dir=1`
//     — CWE-426 search-path-poisoning; any user can drop a
//     binary that the next `docker` invocation will load.
//
// Read-only by intent — we parse the file only, never invoke
// `docker login` / `docker config`. (Project guideline 4.2.)
package windockerconfig

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"path/filepath"
	"sort"
	"strings"
)

// MaxEntries bounds per-scan output. A typical engineer carries
// 1-10 registry credentials; the 1024 ceiling covers CI hosts
// with many vendor-merged registries.
const MaxEntries = 1024

// EntryKind tags which top-level Docker-config section the row
// came from. Pinned to the host_docker_config.entry_kind CHECK
// enum.
type EntryKind string

const (
	EntryAuth         EntryKind = "auth"
	EntryCredHelper   EntryKind = "cred-helper"
	EntryProxy        EntryKind = "proxy"
	EntryCLIPluginDir EntryKind = "cli-plugin-dir"
	EntryCLIConfig    EntryKind = "cli-config"
	EntryUnknown      EntryKind = "unknown"
)

// Entry mirrors host_docker_config's column shape exactly.
type Entry struct {
	ProxyURL                 string    `json:"proxy_url,omitempty"`
	CredentialHelperName     string    `json:"credential_helper_name,omitempty"`
	CLIPluginDir             string    `json:"cli_plugin_dir,omitempty"`
	FilePath                 string    `json:"file_path"`
	UserProfile              string    `json:"user_profile,omitempty"`
	EntryKind                EntryKind `json:"entry_kind"`
	EntryName                string    `json:"entry_name"`
	RegistryHost             string    `json:"registry_host,omitempty"`
	FileHash                 string    `json:"file_hash"`
	FileOwnerUID             int       `json:"file_owner_uid,omitempty"`
	FileMode                 int       `json:"file_mode,omitempty"`
	HasInlineAuth            bool      `json:"has_inline_auth"`
	IsSecureCredentialHelper bool      `json:"is_secure_credential_helper"`
	HasIdentityToken         bool      `json:"has_identitytoken"`
	ProxyTargetIsExternal    bool      `json:"proxy_target_is_external"`
	IsWorldWritableDir       bool      `json:"is_world_writable_dir"`
	IsWorldReadable          bool      `json:"is_world_readable"`
	IsGroupReadable          bool      `json:"is_group_readable"`
	IsCredentialExposureRisk bool      `json:"is_credential_exposure_risk"`
}

// Collector is the read-only contract every implementation satisfies.
type Collector interface {
	Name() string
	Collect(ctx context.Context) ([]Entry, error)
}

// HashContents returns the SHA-256 hex of the config-file body.
func HashContents(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// SecureCredentialHelpers is the curated set of helper names the
// audit pipeline trusts to store credentials in OS-protected
// stores (keychain, DPAPI, libsecret, gpg-encrypted).
func SecureCredentialHelpers() []string {
	return []string{
		"osxkeychain",                      // macOS Keychain
		"wincred",                          // Windows Credential Manager
		"secretservice", "gnome-libsecret", // Linux Secret Service / GNOME Keyring
		"pass",      // gpg-encrypted password store
		"ecr-login", // AWS ECR helper (broker, not a store, but vetted)
		"gcloud",    // GCP Artifact Registry helper
		"acr-env",   // Azure Container Registry helper
		"desktop",   // Docker Desktop's vault
	}
}

// IsSecureCredentialHelperName reports whether `name` is in the
// curated secure set.
func IsSecureCredentialHelperName(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" {
		return false
	}
	// Helper names sometimes carry a `docker-credential-` prefix.
	n = strings.TrimPrefix(n, "docker-credential-")
	for _, h := range SecureCredentialHelpers() {
		if n == h {
			return true
		}
	}
	return false
}

// IsExternalProxyTarget reports whether `proxyURL` points at a
// host outside the curated private-network set (loopback,
// RFC1918, link-local). Empty URLs return false.
func IsExternalProxyTarget(proxyURL string) bool {
	u := strings.TrimSpace(proxyURL)
	if u == "" {
		return false
	}
	// Strip scheme + path.
	if i := strings.Index(u, "://"); i >= 0 {
		u = u[i+3:]
	}
	if i := strings.IndexAny(u, "/?"); i >= 0 {
		u = u[:i]
	}
	host := u
	if h, _, err := net.SplitHostPort(u); err == nil {
		host = h
	}
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if host == "" {
		return false
	}
	lower := strings.ToLower(host)
	if lower == "localhost" || lower == "localhost.localdomain" {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		return !ip.IsLoopback() && !ip.IsPrivate() && !ip.IsLinkLocalUnicast()
	}
	// Bare hostname — conservative: treat as external. Audit
	// pipeline can allowlist by hostname.
	return true
}

// WorldWritableDirRoots is the curated set of directory prefixes
// any local user can write into. CLI-plugin dirs starting with
// these flag is_world_writable_dir=1 (CWE-426 search-path
// poisoning).
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

// IsWorldWritableDir reports whether `dir` resolves under a
// curated world-writable root.
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
	case EntryAuth:
		// Headline: inline auth in a readable file = immediate
		// incident. Inline auth in a 0o600 file is still
		// concerning (audit pipeline alerts) but not headline.
		if e.HasInlineAuth && (e.IsWorldReadable || e.IsGroupReadable) {
			e.IsCredentialExposureRisk = true
		}
	case EntryCredHelper:
		e.IsSecureCredentialHelper = IsSecureCredentialHelperName(e.CredentialHelperName)
		if !e.IsSecureCredentialHelper {
			e.IsCredentialExposureRisk = true
		}
	case EntryProxy:
		e.ProxyTargetIsExternal = IsExternalProxyTarget(e.ProxyURL)
		if e.ProxyTargetIsExternal {
			e.IsCredentialExposureRisk = true
		}
	case EntryCLIPluginDir:
		e.IsWorldWritableDir = IsWorldWritableDir(e.CLIPluginDir)
		if e.IsWorldWritableDir {
			e.IsCredentialExposureRisk = true
		}
	case EntryCLIConfig, EntryUnknown:
		// No headline flag.
	}
}

// SortEntries returns a deterministic ordering by file path,
// entry kind, then entry name.
func SortEntries(es []Entry) {
	sort.Slice(es, func(i, j int) bool {
		if es[i].FilePath != es[j].FilePath {
			return es[i].FilePath < es[j].FilePath
		}
		if es[i].EntryKind != es[j].EntryKind {
			return es[i].EntryKind < es[j].EntryKind
		}
		return es[i].EntryName < es[j].EntryName
	})
}
