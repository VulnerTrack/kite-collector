// Package nfsexports inventories /etc/exports + /etc/exports.d/* —
// the NFS server-side configuration that says "which client gets to
// see which path with which options".
//
// `no_root_squash` is the single highest-impact option in the file:
// when set on a read-write share, a remote root process can write
// files owned by local root on the server. Combined with a wide
// client wildcard (`*` or `0.0.0.0/0`) it's a one-line root-equivalent
// container-escape primitive.
//
// MITRE T1135 (Network Share Discovery — defender side) +
// CWE-732 (Incorrect Permission Assignment) are the headline
// findings. The audit pipeline joins this against host_listeners
// to spot `nfsd` ports (2049, 111) actually answering.
//
// Every collector is **read-only by intent** — it parses
// /etc/exports + drop-ins, never invokes exportfs / mountd /
// systemctl. Read-only is enforced by guideline 4.2 of the
// kite-collector project.
package nfsexports

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
)

// MaxRows bounds per-scan output. A typical NFS server publishes
// 5-30 shares with 1-3 client tuples each; the 1024 ceiling covers
// heavyweight education/labs installs without bloating SQLite writes.
const MaxRows = 1024

// Row mirrors host_nfs_exports' column shape exactly.
type Row struct {
	Options        string   `json:"options,omitempty"`
	FileHash       string   `json:"file_hash"`
	FilePath       string   `json:"file_path"`
	RawLine        string   `json:"raw_line,omitempty"`
	ExportPath     string   `json:"export_path"`
	Client         string   `json:"client"`
	OptionsList    []string `json:"options_list,omitempty"`
	LineNo         int      `json:"line_no"`
	IsAllSquash    bool     `json:"is_all_squash"`
	IsNoRootSquash bool     `json:"is_no_root_squash"`
	IsReadWrite    bool     `json:"is_read_write"`
	IsAsync        bool     `json:"is_async"`
	IsInsecure     bool     `json:"is_insecure"`
	IsWorldExposed bool     `json:"is_world_exposed"`
	IsSubtreeCheck bool     `json:"is_subtree_check"`
}

// Collector is the read-only contract every implementation satisfies.
type Collector interface {
	Name() string
	Collect(ctx context.Context) ([]Row, error)
}

// EncodeStringList returns a JSON array suitable for options_json.
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

// HashContents returns the SHA-256 hex of an exports file body.
func HashContents(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// WorldExposedClients is the curated set of `client` tokens that mean
// "any host". exports(5) treats a bare `*` as the universal wildcard;
// some operators still write `0.0.0.0/0`.
func WorldExposedClients() []string {
	return []string{"*", "0.0.0.0/0", "::/0"}
}

// IsWorldExposedClient reports whether the client token grants access
// to any host on the internet.
func IsWorldExposedClient(client string) bool {
	v := strings.TrimSpace(client)
	if v == "" {
		// Bare empty token (file uses just an export path with no
		// client) → NFS exports the path to everyone.
		return true
	}
	for _, c := range WorldExposedClients() {
		if c == v {
			return true
		}
	}
	return false
}

// HasOption reports whether the option list (case-insensitive)
// contains `want`. Used for the boolean flag projections; `=`-
// valued options like `anonuid=0` are stripped to the bare key
// before the comparison.
func HasOption(opts []string, want string) bool {
	w := strings.ToLower(strings.TrimSpace(want))
	for _, o := range opts {
		key := strings.ToLower(strings.TrimSpace(o))
		if eq := strings.IndexByte(key, '='); eq > 0 {
			key = key[:eq]
		}
		if key == w {
			return true
		}
	}
	return false
}

// AnnotateSecurity sets the indexed booleans on a row from its
// already-populated client + options fields.
//
// Defaults (per exports(5)): when neither `rw` nor `ro` is given,
// NFS defaults to `ro`. When neither `sync` nor `async` is given,
// modern nfs-utils defaults to `sync`. When neither `root_squash`
// nor `no_root_squash` is given, NFS defaults to `root_squash`.
// Our flags reflect the explicit configuration — we don't infer
// defaults so the audit pipeline can distinguish "explicitly set" vs
// "implicitly default" if it wants to.
func AnnotateSecurity(r *Row) {
	r.IsReadWrite = HasOption(r.OptionsList, "rw")
	r.IsNoRootSquash = HasOption(r.OptionsList, "no_root_squash")
	r.IsAllSquash = HasOption(r.OptionsList, "all_squash")
	r.IsAsync = HasOption(r.OptionsList, "async")
	r.IsInsecure = HasOption(r.OptionsList, "insecure")
	r.IsSubtreeCheck = HasOption(r.OptionsList, "subtree_check")
	r.IsWorldExposed = IsWorldExposedClient(r.Client)
}

// SortRows returns a deterministic ordering: file path, line, client.
func SortRows(rs []Row) {
	sort.Slice(rs, func(i, j int) bool {
		if rs[i].FilePath != rs[j].FilePath {
			return rs[i].FilePath < rs[j].FilePath
		}
		if rs[i].LineNo != rs[j].LineNo {
			return rs[i].LineNo < rs[j].LineNo
		}
		return rs[i].Client < rs[j].Client
	})
}
