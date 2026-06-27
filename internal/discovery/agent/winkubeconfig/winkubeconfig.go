// Package winkubeconfig audits kubeconfig files across Windows,
// Linux, and macOS. A kubeconfig stores everything needed to
// talk to a Kubernetes API server — cluster URL + CA, plus user
// credentials (bearer tokens, client certs, exec-plugin commands).
// A single readable kubeconfig with a non-loopback `server` and an
// embedded `token` is full cluster compromise material; the
// defender side of the same primitive is exactly what this
// collector inventories.
//
// File-based discovery is the deliberate design choice — the
// kubectl client walks the same files (plus the `KUBECONFIG` env
// var), so anything kubectl can see, this collector sees.
//
// Headline finding shapes (MITRE T1552.001 — Credentials in
// Files, T1102 — Web Service for exec-plugin token brokers,
// T1078.004 — Cloud Accounts):
//
//   - `has_inline_token=1` — a long-lived bearer token sits in
//     plain YAML. Anyone with read access to the file gets
//     cluster credentials.
//   - `is_insecure_skip_tls_verify=1` — the cluster entry has
//     TLS validation off (CWE-295). Every API call (and the
//     transiting credentials) is MITM-able.
//   - `has_exec_plugin=1` — the user entry brokers its
//     credential through an external `command`. Legit for cloud
//     CLIs (`aws eks get-token`, `gcloud config config-helper`);
//     suspicious for vendor-unknown paths.
//   - `is_world_readable=1` / `is_group_readable=1` — file
//     permissions let non-owner accounts read the kubeconfig
//     (CWE-732). Combined with `has_inline_token` = local
//     privilege escalation to cluster-admin.
//
// Read-only by intent — we walk the kubeconfig files only, never
// invoke `kubectl`. (Project guideline 4.2.)
package winkubeconfig

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
// 5-30 contexts; the 4096 ceiling covers admins with vendor-
// merged kubeconfigs that span every cluster in the fleet.
const MaxEntries = 4096

// EntryKind tags which kubeconfig section the row came from.
// Pinned to the host_kubeconfig.entry_kind CHECK enum.
type EntryKind string

const (
	EntryCluster EntryKind = "cluster"
	EntryUser    EntryKind = "user"
	EntryContext EntryKind = "context"
)

// AuthKind classifies the user credential shape.
type AuthKind string

const (
	AuthToken        AuthKind = "token"
	AuthCert         AuthKind = "cert"
	AuthExec         AuthKind = "exec"
	AuthAuthProvider AuthKind = "auth-provider"
	AuthBasic        AuthKind = "basic"
	AuthNone         AuthKind = "none"
)

// Entry mirrors host_kubeconfig's column shape exactly.
type Entry struct {
	ExecCommand              string    `json:"exec_command,omitempty"`
	ContextUser              string    `json:"context_user,omitempty"`
	AuthProviderName         string    `json:"auth_provider_name,omitempty"`
	ContextNamespace         string    `json:"context_namespace,omitempty"`
	UserProfile              string    `json:"user_profile,omitempty"`
	EntryKind                EntryKind `json:"entry_kind"`
	EntryName                string    `json:"entry_name"`
	Server                   string    `json:"server,omitempty"`
	ContextCluster           string    `json:"context_cluster,omitempty"`
	FilePath                 string    `json:"file_path"`
	FileHash                 string    `json:"file_hash"`
	AuthKind                 AuthKind  `json:"auth_kind,omitempty"`
	FileOwnerUID             int       `json:"file_owner_uid,omitempty"`
	FileMode                 int       `json:"file_mode,omitempty"`
	HasInlineCertificate     bool      `json:"has_inline_certificate"`
	HasBasicAuth             bool      `json:"has_basic_auth"`
	HasExecPlugin            bool      `json:"has_exec_plugin"`
	HasInlineToken           bool      `json:"has_inline_token"`
	IsGroupReadable          bool      `json:"is_group_readable"`
	IsLoopbackServer         bool      `json:"is_loopback_server"`
	IsInsecureSkipTLSVerify  bool      `json:"is_insecure_skip_tls_verify"`
	IsCurrentContext         bool      `json:"is_current_context"`
	IsWorldReadable          bool      `json:"is_world_readable"`
	HasCertificateAuthority  bool      `json:"has_certificate_authority"`
	IsCredentialExposureRisk bool      `json:"is_credential_exposure_risk"`
}

// Collector is the read-only contract every implementation satisfies.
type Collector interface {
	Name() string
	Collect(ctx context.Context) ([]Entry, error)
}

// HashContents returns the SHA-256 hex of the kubeconfig body.
func HashContents(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// IsLoopbackURL reports whether the server URL host resolves to
// loopback. Empty/unparseable URLs return false (most likely a
// production cluster).
func IsLoopbackURL(server string) bool {
	s := strings.TrimSpace(server)
	if s == "" {
		return false
	}
	// Strip scheme (`https://`).
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	// Strip trailing path / query.
	if i := strings.IndexAny(s, "/?"); i >= 0 {
		s = s[:i]
	}
	host := s
	if h, _, err := net.SplitHostPort(s); err == nil {
		host = h
	}
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") || strings.EqualFold(host, "localhost.localdomain") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// AnnotateSecurity sets the derived booleans on an Entry that
// has its raw fields populated. The file-level booleans
// (IsWorldReadable, IsGroupReadable) must be set by the caller
// from the stat result; AnnotateSecurity only computes the
// rolled-up `IsCredentialExposureRisk`.
func AnnotateSecurity(e *Entry) {
	if e.FileMode != 0 {
		e.IsWorldReadable = e.FileMode&0o004 != 0
		e.IsGroupReadable = e.FileMode&0o040 != 0
	}
	e.IsLoopbackServer = IsLoopbackURL(e.Server)
	// Rolled-up alert: any kubeconfig with an inline token AND a
	// non-loopback server is immediate-incident shape. Adding
	// `is_world_readable` or `is_insecure_skip_tls_verify` makes
	// it worse but doesn't change the trigger.
	e.IsCredentialExposureRisk = (e.HasInlineToken && !e.IsLoopbackServer) ||
		e.IsInsecureSkipTLSVerify ||
		(e.HasInlineToken && e.IsWorldReadable) ||
		(e.HasInlineToken && e.IsGroupReadable)
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

// BaseLower returns the lowercased filename basename. Used so the
// collector doesn't need extra imports.
func BaseLower(p string) string {
	return strings.ToLower(filepath.Base(p))
}
