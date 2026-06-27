// Package wingit audits Git configuration + `~/.git-credentials`
// across Windows, Linux, and macOS. Git configs are particularly
// dangerous because routine `git fetch`/`git push`/`git commit`
// invocations transparently execute every command-override knob
// (`core.editor`, `core.pager`, `core.sshCommand`, `core.hooksPath`)
// AND honour URL rewrites (`url.<remote>.insteadOf`). An attacker
// with write access to a developer's gitconfig has a covert
// command-execution channel plus an MITM redirect on every
// outbound git operation.
//
// File-based discovery is the deliberate design choice — the git
// binary walks the same files, so anything git honours, this
// collector inventories. The `~/.git-credentials` file is the
// most concentrated leak surface: when `credential.helper=store`
// is configured, every successful push writes the URL + token to
// the file in plaintext.
//
// Headline finding shapes (MITRE T1552.001 — Credentials in
// Files, T1557 — Adversary-in-the-Middle, T1547.013 — Hooks,
// T1059 — Command and Scripting Interpreter):
//
//   - `is_plaintext_credential=1` — row came from a
//     `~/.git-credentials` file; URL + token in plaintext.
//   - `is_credential_store_helper=1` — `credential.helper=store`
//     means git WILL write plaintext credentials on next push.
//   - `is_url_rewrite=1` — `url.<X>.insteadOf` configured;
//     attacker can transparently redirect every git operation.
//   - `is_external_hookspath=1` — `core.hookspath` points at a
//     world-writable directory; every git op auto-runs hook
//     binaries from there.
//   - `has_command_override=1` — `core.editor` / `core.pager` /
//     `core.sshcommand` set. Often legitimate (vim, less, etc)
//     but audit pipeline cross-references against a known-good
//     allowlist.
//
// Read-only by intent — we walk the config + credentials files
// only, never invoke `git`. (Project guideline 4.2.)
package wingit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
)

// MaxRows bounds per-scan output. A typical engineer has 10-50
// gitconfig entries; the 4096 ceiling covers heavy-tier admins
// with many remote rewrites.
const MaxRows = 4096

// FileScope tags which canonical Git config file the row came
// from. Pinned to the host_git_config.file_scope CHECK enum.
type FileScope string

const (
	ScopeSystem      FileScope = "system"      // /etc/gitconfig
	ScopeGlobal      FileScope = "global"      // ~/.gitconfig
	ScopeXDG         FileScope = "xdg"         // ${XDG_CONFIG_HOME:-~/.config}/git/config
	ScopeCredentials FileScope = "credentials" // ~/.git-credentials (plaintext store)
	ScopeUnknown     FileScope = "unknown"
)

// EntryKind tags whether the row is a config setting or a
// plaintext-credential record. Pinned to the
// host_git_config.entry_kind CHECK enum.
type EntryKind string

const (
	EntryKindSetting          EntryKind = "setting"
	EntryKindCredentialRecord EntryKind = "credential-record" //#nosec G101 -- enum tag for host_git_config.entry_kind, not a credential value
	EntryKindUnknown          EntryKind = "unknown"
)

// Entry mirrors host_git_config's column shape exactly.
type Entry struct {
	Value                    string    `json:"value,omitempty"`
	FileHash                 string    `json:"file_hash"`
	FilePath                 string    `json:"file_path"`
	Subsection               string    `json:"subsection,omitempty"`
	UserProfile              string    `json:"user_profile,omitempty"`
	FileScope                FileScope `json:"file_scope"`
	EntryKind                EntryKind `json:"entry_kind"`
	Section                  string    `json:"section,omitempty"`
	Key                      string    `json:"key"`
	FileOwnerUID             int       `json:"file_owner_uid,omitempty"`
	FileMode                 int       `json:"file_mode,omitempty"`
	IsNoCredentialHelper     bool      `json:"is_no_credential_helper"`
	IsCredentialStoreHelper  bool      `json:"is_credential_store_helper"`
	IsURLRewrite             bool      `json:"is_url_rewrite"`
	IsExternalHooksPath      bool      `json:"is_external_hookspath"`
	HasCommandOverride       bool      `json:"has_command_override"`
	IsPlaintextCredential    bool      `json:"is_plaintext_credential"`
	IsWorldReadable          bool      `json:"is_world_readable"`
	IsGroupReadable          bool      `json:"is_group_readable"`
	IsCredentialExposureRisk bool      `json:"is_credential_exposure_risk"`
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

// CommandOverrideKeys is the curated set of git config keys that
// supply a command git will exec on routine operations. Any of
// these with a non-empty value flips has_command_override=1.
func CommandOverrideKeys() []string {
	return []string{
		"core.editor",
		"core.pager",
		"core.sshcommand",
		"sequence.editor",
		"diff.tool",
		"merge.tool",
	}
}

// WorldWritableDirRoots is the curated set of directory prefixes
// any local user can write into. `core.hookspath` matching these
// flags is_external_hookspath=1.
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

// IsWorldWritableDir reports whether `dir` sits under one of
// the curated world-writable roots.
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

// IsCommandOverrideKey reports whether `key` (already normalised
// as "section.subsection.name" or "section.name") is in the
// curated override set.
func IsCommandOverrideKey(key string) bool {
	k := strings.ToLower(strings.TrimSpace(key))
	for _, c := range CommandOverrideKeys() {
		if k == c {
			return true
		}
	}
	return false
}

// CredentialRecordHost extracts the host portion of a
// `~/.git-credentials` line (format:
// `https://user:token@host[/path]`). Used so the persisted row
// records WHERE the credential leaked without preserving the
// secret itself.
func CredentialRecordHost(line string) string {
	u, err := url.Parse(strings.TrimSpace(line))
	if err != nil || u.Host == "" {
		return ""
	}
	host := u.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.Trim(host, "[]")
}

// AnnotateSecurity sets the derived booleans on an Entry that
// has its raw fields populated. The caller must set FileMode
// before calling.
func AnnotateSecurity(e *Entry) {
	if e.FileMode != 0 {
		e.IsWorldReadable = e.FileMode&0o004 != 0
		e.IsGroupReadable = e.FileMode&0o040 != 0
	}
	key := strings.ToLower(strings.TrimSpace(e.Key))
	value := strings.TrimSpace(e.Value)

	switch e.EntryKind {
	case EntryKindCredentialRecord:
		e.IsPlaintextCredential = true
		e.IsCredentialExposureRisk = true
	case EntryKindSetting:
		switch {
		case key == "credential.helper":
			if value == "" {
				e.IsNoCredentialHelper = true
				e.IsCredentialExposureRisk = true
			}
			if strings.EqualFold(value, "store") {
				e.IsCredentialStoreHelper = true
				e.IsCredentialExposureRisk = true
			}
		case strings.HasPrefix(key, "url.") && strings.HasSuffix(key, ".insteadof"):
			e.IsURLRewrite = true
		case key == "core.hookspath":
			if IsWorldWritableDir(value) {
				e.IsExternalHooksPath = true
				e.IsCredentialExposureRisk = true
			}
		}
		if IsCommandOverrideKey(key) && value != "" {
			e.HasCommandOverride = true
		}
	case EntryKindUnknown:
		// no-op
	}
}

// SortEntries returns a deterministic ordering by file path,
// section, subsection, key.
func SortEntries(es []Entry) {
	sort.Slice(es, func(i, j int) bool {
		if es[i].FilePath != es[j].FilePath {
			return es[i].FilePath < es[j].FilePath
		}
		if es[i].Section != es[j].Section {
			return es[i].Section < es[j].Section
		}
		if es[i].Subsection != es[j].Subsection {
			return es[i].Subsection < es[j].Subsection
		}
		return es[i].Key < es[j].Key
	})
}
