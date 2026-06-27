// Package gitrepos inventories every git working tree on the host.
// The collector walks a curated set of root directories looking for
// `.git/` markers, parses each repo's config, and surfaces the
// security-relevant fields (remote URLs, credential helpers, hook
// presence, file modes).
//
// Local git repositories are a triple-threat surface:
//
//   - MITRE T1213.003 (Code Repositories) — a checked-out internal
//     source tree on a non-developer host is unexpected exposure.
//   - MITRE T1552.004 (Unsecured Credentials) — remote URLs of the
//     shape `https://user:token@github.com/...` leak the embedded
//     personal-access token to anyone who can read .git/config (or
//     the shell history that ran the original `git clone`).
//   - MITRE T1546.005 (Trap) — git hooks under .git/hooks/ run with
//     the user's privileges on every commit/push. A pre-commit hook
//     dropped into the repo is a persistence primitive.
//
// Every collector is **read-only by intent** — it parses .git/config
// and stats hook files, never invokes git itself. Read-only is
// enforced by guideline 4.2 of the kite-collector project.
//
// Row shape:
//
//   - One row per remote (`origin`, `upstream`, ...). Repos without
//     remotes still emit a single row with empty remote_name/url so
//     the inventory captures the working tree's existence.
//   - is_credential_in_url=1, has_executable_hook=1, has_insteadof=1,
//     and has_ssh_command_override=1 are pre-computed indexed booleans.
//   - file_hash is the SHA-256 of .git/config — change detection
//     surfaces remote/credential reconfiguration between scans.
package gitrepos

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"sort"
	"strings"
)

// MaxRepos bounds per-scan output. A developer workstation typically
// has 20-150 cloned repos; the 4096 ceiling covers polyrepo monsters
// without bloating the SQLite write path.
const MaxRepos = 4096

// MaxRemotesPerRepo guards the per-repo remote count. A repo with
// hundreds of remotes is misuse; we cap at 32 to keep the join
// surface bounded.
const MaxRemotesPerRepo = 32

// Repo is the parsed record produced per (working_tree, remote) pair.
// Mirrors host_git_repos' column shape exactly.
type Repo struct {
	SSHCommand            string   `json:"ssh_command,omitempty"`
	CredentialHelper      string   `json:"credential_helper,omitempty"`
	FileHash              string   `json:"file_hash,omitempty"`
	HeadBranch            string   `json:"head_branch,omitempty"`
	RemoteName            string   `json:"remote_name"`
	RemoteURL             string   `json:"remote_url,omitempty"`
	RemoteHost            string   `json:"remote_host,omitempty"`
	UserEmail             string   `json:"user_email,omitempty"`
	UserName              string   `json:"user_name,omitempty"`
	FilePath              string   `json:"file_path,omitempty"`
	GitDir                string   `json:"git_dir"`
	RepoPath              string   `json:"repo_path"`
	InsteadOfPairs        []string `json:"insteadof_pairs,omitempty"`
	ExecutableHooks       []string `json:"executable_hooks,omitempty"`
	OwnerUID              int      `json:"owner_uid,omitempty"`
	ConfigMode            int      `json:"config_mode,omitempty"`
	IsCredentialInURL     bool     `json:"is_credential_in_url"`
	HasExecutableHook     bool     `json:"has_executable_hook"`
	HasInsteadOf          bool     `json:"has_insteadof"`
	HasSSHCommandOverride bool     `json:"has_ssh_command_override"`
	IsWorldReadable       bool     `json:"is_world_readable"`
	IsBare                bool     `json:"is_bare"`
}

// Collector is the read-only contract every per-OS implementation satisfies.
type Collector interface {
	Name() string
	Collect(ctx context.Context) ([]Repo, error)
}

// EncodeStringList returns a JSON array suitable for *_json columns.
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

// HashContents returns the SHA-256 hex of a .git/config body. Drives
// drift detection between scans.
func HashContents(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// DefaultHookNames is the curated set of hook filenames git ships
// with `.sample` suffixes. A repo with executable files matching one
// of these names (without the .sample suffix) has custom hooks
// installed and warrants audit attention.
func DefaultHookNames() []string {
	return []string{
		"applypatch-msg", "commit-msg", "fsmonitor-watchman",
		"post-update", "pre-applypatch", "pre-commit",
		"pre-merge-commit", "pre-push", "pre-rebase",
		"pre-receive", "prepare-commit-msg", "push-to-checkout",
		"sendemail-validate", "update", "post-checkout",
		"post-commit", "post-merge", "post-receive",
		"post-rewrite", "proc-receive", "reference-transaction",
	}
}

// IsDefaultHookName reports whether the given hook filename is one of
// the standard git-shipped templates (without the .sample suffix).
func IsDefaultHookName(name string) bool {
	want := strings.TrimSpace(name)
	for _, h := range DefaultHookNames() {
		if h == want {
			return true
		}
	}
	return false
}

// IsCredentialInURL reports whether a remote URL embeds userinfo
// (username:password / token). Returns false for ssh://user@host
// (the `user` there is the SSH login, not a credential).
//
// Caveats:
//   - We deliberately accept the case where only a username is set
//     (https://user@github.com) as suspicious too — that's almost
//     always a leftover after the password was rotated out.
//   - SCP-style `git@github.com:org/repo` has no userinfo per the
//     URL spec; we return false there.
func IsCredentialInURL(remoteURL string) bool {
	raw := strings.TrimSpace(remoteURL)
	if raw == "" {
		return false
	}
	// SCP-style URL: `user@host:path`. The `@` is present but it's
	// not a URL we can parse. Skip — the user portion is the SSH login.
	if !strings.Contains(raw, "://") {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || u == nil || u.User == nil {
		return false
	}
	scheme := strings.ToLower(u.Scheme)
	// SSH URLs frequently carry just a username (the SSH login) —
	// not a credential.
	if scheme == "ssh" || scheme == "git+ssh" || scheme == "git" {
		return false
	}
	// http(s), ftp(s), file: any userinfo is a credential.
	if u.User.Username() == "" {
		return false
	}
	_, hasPassword := u.User.Password()
	// Bare username on https = leftover; treat as suspicious.
	// Username + password = definitely a credential.
	return hasPassword || scheme == "https" || scheme == "http"
}

// HostOfURL returns the host component of a remote URL, handling both
// canonical URLs and SCP-style `git@github.com:org/repo`.
func HostOfURL(remoteURL string) string {
	raw := strings.TrimSpace(remoteURL)
	if raw == "" {
		return ""
	}
	// SCP-style.
	if !strings.Contains(raw, "://") {
		if i := strings.IndexByte(raw, '@'); i > 0 {
			rest := raw[i+1:]
			if j := strings.IndexByte(rest, ':'); j > 0 {
				return strings.ToLower(rest[:j])
			}
			return strings.ToLower(rest)
		}
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u == nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

// IsWorldReadableMode reports whether a Unix file mode grants read
// to "other" (low octal digit >= 4). Used to flag .git/config files
// any local user can read.
func IsWorldReadableMode(mode int) bool {
	return mode&0o4 != 0
}

// AnnotateSecurity sets the indexed booleans on a Repo from its
// already-populated fields.
func AnnotateSecurity(r *Repo) {
	r.IsCredentialInURL = IsCredentialInURL(r.RemoteURL)
	if r.RemoteURL != "" {
		r.RemoteHost = HostOfURL(r.RemoteURL)
	}
	r.HasInsteadOf = len(r.InsteadOfPairs) > 0
	r.HasSSHCommandOverride = strings.TrimSpace(r.SSHCommand) != ""
	r.HasExecutableHook = len(r.ExecutableHooks) > 0
	r.IsWorldReadable = IsWorldReadableMode(r.ConfigMode)
}

// SortRepos returns a deterministic ordering: repo path, then remote.
func SortRepos(rs []Repo) {
	sort.Slice(rs, func(i, j int) bool {
		if rs[i].RepoPath != rs[j].RepoPath {
			return rs[i].RepoPath < rs[j].RepoPath
		}
		return rs[i].RemoteName < rs[j].RemoteName
	})
}
