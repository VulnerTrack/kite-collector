// Package shellinit enumerates shell-initialization files (rc files,
// profile files, login/logout scripts, drop-in fragments) across every
// user home plus the system-wide directories. Each file is parsed for
// aliases, exported environment variables, $PATH prepends, source/.
// statements, and dangerous patterns (eval, curl|sh).
//
// MITRE ATT&CK T1546.004 (Event-Triggered Execution: Unix Shell
// Configuration Modification) is the headline technique this collector
// inventories. Attackers reliably modify ~/.bashrc / ~/.zshrc to gain
// per-session persistence; the modification is invisible to most EDR
// tools because the file change is benign in isolation. This collector
// turns each file into a per-scan row whose file_hash drives drift
// detection.
//
// Every collector is **read-only** — it parses scripts, never executes
// them. The parser is a regex-based line walker (deliberately limited)
// because actually evaluating shell would mean importing the bash
// runtime semantics including command substitution and variable
// expansion — read-only is enforced by guideline 4.2.
//
// Rows feed the CWE/CAPEC + ATT&CK audit pipeline:
//
//   - T1546.004 — `has_shadow_alias=1` flags aliases that override
//     common binaries (ls, sudo, ssh, curl, git).
//   - CWE-426 (Untrusted Search Path) — `has_untrusted_path=1` flags
//     world-writable directories prepended to $PATH.
//   - Curl-pipe-bash — `contains_curl_pipe=1` flags inline
//     `curl … | sh` / `wget … | bash` patterns.
//   - Drift detection — every `file_hash` change between scans
//     emits a "shell init modified" audit event.
package shellinit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
)

// MaxFiles bounds per-scan output. A typical host has 5-20 shell init
// files per user × multiple users + system-wide. The 4096 ceiling
// protects the SQLite write path.
const MaxFiles = 4096

// MaxFileBytes caps how much of any one file we'll read into memory.
// Real .bashrc is < 100KB; anything bigger is suspicious or non-source
// (someone wrote a 10MB inline blob). We truncate rather than abort so
// drift detection still records a file_hash.
const MaxFileBytes = 1 << 20 // 1 MiB

// Shell identifies the shell that interprets this file. Pinned to the
// host_shell_inits.shell CHECK enum.
type Shell string

const (
	ShellBash       Shell = "bash"
	ShellZsh        Shell = "zsh"
	ShellFish       Shell = "fish"
	ShellSh         Shell = "sh"
	ShellDash       Shell = "dash"
	ShellCsh        Shell = "csh"
	ShellTcsh       Shell = "tcsh"
	ShellKsh        Shell = "ksh"
	ShellPowerShell Shell = "powershell"
	ShellUnknown    Shell = "unknown"
)

// Scope is system vs user. Pinned enum.
type Scope string

const (
	ScopeSystem Scope = "system"
	ScopeUser   Scope = "user"
)

// FileRole classifies what triggers the file. Pinned enum.
type FileRole string

const (
	RoleRC      FileRole = "rc"      // every interactive shell (.bashrc, .zshrc)
	RoleProfile FileRole = "profile" // login profile (.bash_profile, .profile)
	RoleLogin   FileRole = "login"   // explicit login (.bash_login, .zlogin)
	RoleLogout  FileRole = "logout"  // shell exit (.bash_logout, .zlogout)
	RoleEnv     FileRole = "env"     // env setup (.zshenv)
	RoleDropIn  FileRole = "drop-in" // fragment (/etc/profile.d/*.sh)
	RoleUnknown FileRole = "unknown"
)

// InitFile is the cross-shell record produced by the collector. Mirrors
// host_shell_inits' column shape.
type InitFile struct {
	Exports          map[string]string `json:"exports,omitempty"`
	Aliases          map[string]string `json:"aliases,omitempty"`
	Scope            Scope             `json:"scope"`
	FileRole         FileRole          `json:"file_role"`
	FilePath         string            `json:"file_path"`
	OwnerUser        string            `json:"owner_user,omitempty"`
	FileHash         string            `json:"file_hash"`
	Shell            Shell             `json:"shell"`
	PathPrepends     []string          `json:"path_prepends,omitempty"`
	SourcedFiles     []string          `json:"sourced_files,omitempty"`
	FileSizeBytes    int               `json:"file_size_bytes"`
	ContainsEval     bool              `json:"contains_eval"`
	ContainsCurlPipe bool              `json:"contains_curl_pipe"`
	HasUntrustedPath bool              `json:"has_untrusted_path"`
	HasShadowAlias   bool              `json:"has_shadow_alias"`
}

// Collector is the read-only contract every implementation satisfies.
type Collector interface {
	Name() string
	Collect(ctx context.Context) ([]InitFile, error)
}

// EncodeMap returns a JSON object suitable for *_json map columns.
// Empty input always emits "{}" so the column is never NULL.
func EncodeMap(m map[string]string) string {
	if len(m) == 0 {
		return "{}"
	}
	b, err := json.Marshal(m)
	if err != nil {
		return "{}"
	}
	return string(b)
}

// EncodeStringList returns a JSON array. Empty input emits "[]".
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

// HashContents returns the SHA-256 hex of a file's contents. Stable
// across rescans modulo file changes; the natural key for the
// host_shell_inits drift-detection index.
func HashContents(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// ShadowedBinaries returns the list of system-binary names worth
// alerting on when shell aliases redefine them. Conservative — the
// presence of any of these as an alias name is the T1546.004 signal.
func ShadowedBinaries() []string {
	return []string{
		"ls", "ll", "la",
		"cd", "rm", "mv", "cp",
		"cat", "less", "more",
		"sudo", "su", "doas",
		"ssh", "scp", "sftp", "ssh-add", "ssh-agent",
		"curl", "wget",
		"git", "kubectl", "docker",
		"python", "python3", "perl", "ruby",
		"chmod", "chown", "passwd",
	}
}

// IsShadowedBinary reports whether an alias name shadows a binary in
// ShadowedBinaries().
func IsShadowedBinary(aliasName string) bool {
	for _, b := range ShadowedBinaries() {
		if b == aliasName {
			return true
		}
	}
	return false
}

// IsUntrustedPathDir reports whether a $PATH entry is a classic
// attacker drop zone — world-writable on most Unix systems.
func IsUntrustedPathDir(dir string) bool {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return false
	}
	switch {
	case strings.HasPrefix(dir, "/tmp/"),
		dir == "/tmp",
		strings.HasPrefix(dir, "/var/tmp/"),
		dir == "/var/tmp",
		strings.HasPrefix(dir, "/dev/shm/"),
		dir == "/dev/shm",
		dir == ".":
		return true
	}
	return false
}

// SortInitFiles returns a deterministic ordering: scope, then file path.
func SortInitFiles(fs []InitFile) {
	sort.Slice(fs, func(i, j int) bool {
		if fs[i].Scope != fs[j].Scope {
			return fs[i].Scope < fs[j].Scope
		}
		return fs[i].FilePath < fs[j].FilePath
	})
}
