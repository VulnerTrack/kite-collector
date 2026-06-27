// Package winvscode inventories installed editor extensions for
// VSCode (`%USERPROFILE%\.vscode\extensions\`), VS Insiders
// (`.vscode-insiders\extensions\`), and Cursor
// (`.cursor\extensions\`). Each extension is a directory named
// `<publisher>.<name>-<version>` containing a `package.json`
// manifest.
//
// File-based discovery is the deliberate design choice — every
// extension lands on disk identically across platforms, and the
// audit pipeline can cross-reference the marketplace by
// `(publisher, extension_name, extension_version)` without
// querying the editor at runtime. Drift is captured via the
// manifest SHA-256 — supply-chain compromises (e.g. the 2023
// Liblab and 2024 ESLint extension takeovers) all manifested as
// hash changes on the deployed package.
//
// Headline finding shapes (MITRE T1195 — Supply Chain Compromise,
// plus T1059 — Command and Scripting Interpreter via
// debug/terminal contributes):
//
//   - `is_third_party_publisher=1` — publisher is NOT in the
//     curated Microsoft / official-vendor allowlist. Legitimate
//     but every entry expands the supply-chain surface.
//   - `contributes_terminal=1` / `contributes_debug=1` /
//     `contributes_tasks=1` — extension ships a code-execution
//     surface. Audit pipeline alerts on the union with
//     `is_third_party_publisher`.
//   - `has_wildcard_activation=1` — activation event includes `*`
//     or `onStartupFinished` (extension runs on every editor
//     launch). Common but expands the runtime attack surface.
//   - `is_workspace_trust_disabled=1` — extension explicitly
//     opts out of VSCode's Workspace Trust gate.
//   - `is_supply_chain_candidate=1` — rollup of
//     third-party-publisher AND any RCE-adjacent contributes
//     OR workspace-trust-disabled.
//
// Read-only by intent — we walk the extensions directory only,
// never invoke `code`/`code-insiders`/`cursor`.
// (Project guideline 4.2.)
package winvscode

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"sort"
	"strings"
)

// MaxExtensions bounds per-scan output. A heavy developer
// workstation has 50-200 extensions per editor; the 8192 ceiling
// covers shared dev hosts.
const MaxExtensions = 8192

// EditorKind tags which editor the extension belongs to. Pinned
// to the host_vscode_extensions.editor_kind CHECK enum.
type EditorKind string

const (
	EditorVSCode         EditorKind = "vscode"
	EditorVSCodeInsiders EditorKind = "vscode-insiders"
	EditorCursor         EditorKind = "cursor"
	EditorUnknown        EditorKind = "unknown"
)

// Extension mirrors host_vscode_extensions' column shape exactly.
type Extension struct {
	FilePath                 string     `json:"file_path"`
	FileHash                 string     `json:"file_hash"`
	ExtensionDir             string     `json:"extension_dir"`
	UserProfile              string     `json:"user_profile,omitempty"`
	EditorKind               EditorKind `json:"editor_kind"`
	Publisher                string     `json:"publisher"`
	ExtensionName            string     `json:"extension_name"`
	ExtensionVersion         string     `json:"extension_version,omitempty"`
	DisplayName              string     `json:"display_name,omitempty"`
	Description              string     `json:"description,omitempty"`
	MainEntry                string     `json:"main_entry,omitempty"`
	EngineVSCode             string     `json:"engine_vscode,omitempty"`
	ActivationEvents         []string   `json:"activation_events,omitempty"`
	Contributes              []string   `json:"contributes,omitempty"` // top-level keys
	IsThirdPartyPublisher    bool       `json:"is_third_party_publisher"`
	HasWildcardActivation    bool       `json:"has_wildcard_activation"`
	ContributesTerminal      bool       `json:"contributes_terminal"`
	ContributesDebug         bool       `json:"contributes_debug"`
	ContributesTasks         bool       `json:"contributes_tasks"`
	IsWorkspaceTrustDisabled bool       `json:"is_workspace_trust_disabled"`
	IsSupplyChainCandidate   bool       `json:"is_supply_chain_candidate"`
}

// Collector is the read-only contract every implementation satisfies.
type Collector interface {
	Name() string
	Collect(ctx context.Context) ([]Extension, error)
}

// HashContents returns the SHA-256 hex of a manifest body.
func HashContents(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// TrustedPublishers is the curated set of publishers the audit
// pipeline considers first-party / vetted. Anything NOT in this
// list flags is_third_party_publisher=1.
func TrustedPublishers() []string {
	return []string{
		"microsoft",
		"ms-vscode",
		"ms-vscode-remote",
		"ms-python",
		"ms-azuretools",
		"ms-dotnettools",
		"ms-toolsai",
		"github",
		"vscode",
		"redhat",
		"rust-lang",
		"vscjava",
		"golang",
		"google",
		"anthropic",
	}
}

// IsTrustedPublisher reports whether `publisher` is in the
// curated trusted set. Case-insensitive.
func IsTrustedPublisher(publisher string) bool {
	p := strings.ToLower(strings.TrimSpace(publisher))
	if p == "" {
		return false
	}
	for _, t := range TrustedPublishers() {
		if p == t {
			return true
		}
	}
	return false
}

// HasWildcardActivationEvent reports whether the activation list
// includes a wildcard (`*`) or the `onStartupFinished` event —
// both fire on every editor launch.
func HasWildcardActivationEvent(events []string) bool {
	for _, e := range events {
		t := strings.ToLower(strings.TrimSpace(e))
		if t == "*" || t == "onstartupfinished" {
			return true
		}
	}
	return false
}

// AnnotateSecurity sets the derived booleans on an Extension
// that has its raw fields populated.
func AnnotateSecurity(e *Extension) {
	e.IsThirdPartyPublisher = !IsTrustedPublisher(e.Publisher)
	e.HasWildcardActivation = HasWildcardActivationEvent(e.ActivationEvents)
	for _, c := range e.Contributes {
		switch strings.ToLower(strings.TrimSpace(c)) {
		case "terminal":
			e.ContributesTerminal = true
		case "debuggers":
			e.ContributesDebug = true
		case "taskdefinitions":
			e.ContributesTasks = true
		}
	}
	// Rolled-up alert: third-party + RCE-adjacent contributes OR
	// workspace-trust-disabled = audit-worthy supply-chain risk.
	rceAdjacent := e.ContributesTerminal || e.ContributesDebug || e.ContributesTasks
	e.IsSupplyChainCandidate = e.IsThirdPartyPublisher &&
		(rceAdjacent || e.IsWorkspaceTrustDisabled)
}

// SortExtensions returns a deterministic ordering by editor kind,
// publisher, extension name, then version.
func SortExtensions(es []Extension) {
	sort.Slice(es, func(i, j int) bool {
		if es[i].EditorKind != es[j].EditorKind {
			return es[i].EditorKind < es[j].EditorKind
		}
		if es[i].Publisher != es[j].Publisher {
			return es[i].Publisher < es[j].Publisher
		}
		if es[i].ExtensionName != es[j].ExtensionName {
			return es[i].ExtensionName < es[j].ExtensionName
		}
		return es[i].ExtensionVersion < es[j].ExtensionVersion
	})
}

// ParsePublisherAndName splits the `<publisher>.<name>` style
// extension identifier. Inputs like
// `microsoft.vscode-typescript-next` → ("microsoft",
// "vscode-typescript-next"). Inputs without a `.` return
// ("", input).
func ParsePublisherAndName(id string) (publisher, name string) {
	t := strings.TrimSpace(id)
	if i := strings.IndexByte(t, '.'); i > 0 {
		return t[:i], t[i+1:]
	}
	return "", t
}

// FilepathBaseLower returns filepath.Base(p) lowercased. Used so
// callers don't pull in extra imports.
func FilepathBaseLower(p string) string {
	return strings.ToLower(filepath.Base(p))
}
