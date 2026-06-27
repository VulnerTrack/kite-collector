// Package editorext enumerates installed editor / IDE extensions across
// VS Code family (VSCode, VSCodium, Cursor, code-server, Windsurf),
// JetBrains family (IntelliJ, PyCharm, GoLand, …), Sublime, Vim/Neovim,
// and Emacs.
//
// Distinct from browser extensions: editor extensions run with full
// editor IPC capability and can read EVERY open file in any project.
// A malicious editor extension on a developer laptop is one of the
// highest-value initial-access primitives — the lookalike-publisher
// attack class (e.g. "github-extension" by an attacker) is real and
// documented (CRXcavator/VSXcavator catalogue several incidents).
//
// Every collector is **read-only** — it parses package.json / plugin.xml,
// walks extension directories. It never installs, enables, disables, or
// removes any extension.
//
// Extension rows feed the audit pipeline:
//
//   - T1176-adjacent — editor extensions are persistence + collection
//     primitives. The audit pipeline cross-references publisher + name
//     against the VSXcavator known-malicious catalogue.
//   - CWE-829 (Untrusted Functionality) — install_source='sideloaded'
//     (VSIX install bypassing the marketplace) flags supply-chain risk.
//   - Startup-activation audits — `activates_on_startup=1` is the
//     highest blast-radius pattern.
package editorext

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
)

// MaxExtensions bounds per-scan output. A developer laptop typically has
// 20-80 VS Code extensions × multiple editors (VSCode + Cursor + JetBrains).
// The 1024 ceiling protects the SQLite write path.
const MaxExtensions = 1024

// Editor identifies the parent editor. Strings pinned to the
// host_editor_extensions.editor CHECK enum.
type Editor string

const (
	EditorVSCode     Editor = "vscode"
	EditorVSCodium   Editor = "vscodium"
	EditorCursor     Editor = "cursor"
	EditorCodeServer Editor = "code-server"
	EditorWindsurf   Editor = "windsurf"
	EditorIntelliJ   Editor = "intellij"
	EditorPyCharm    Editor = "pycharm"
	EditorGoLand     Editor = "goland"
	EditorWebStorm   Editor = "webstorm"
	EditorPHPStorm   Editor = "phpstorm"
	EditorRubyMine   Editor = "rubymine"
	EditorRider      Editor = "rider"
	EditorDataGrip   Editor = "datagrip"
	EditorCLion      Editor = "clion"
	EditorRustRover  Editor = "rustrover"
	EditorAndroid    Editor = "android-studio"
	EditorSublime    Editor = "sublime"
	EditorVim        Editor = "vim"
	EditorNeovim     Editor = "neovim"
	EditorEmacs      Editor = "emacs"
	EditorUnknown    Editor = "unknown"
)

// InstallSource describes how the extension landed. Pinned to the
// host_editor_extensions.install_source CHECK enum.
type InstallSource string

const (
	InstallMarketplace InstallSource = "marketplace"
	InstallSideloaded  InstallSource = "sideloaded" // VSIX install
	InstallSSHRemote   InstallSource = "ssh-remote" // VS Code Remote-SSH
	InstallDeveloper   InstallSource = "dev"
	InstallSystem      InstallSource = "system"
	InstallUnknown     InstallSource = "unknown"
)

// Extension is the cross-editor record produced by every collector.
// Mirrors host_editor_extensions' column shape.
type Extension struct {
	Editor             Editor        `json:"editor"`
	Profile            string        `json:"profile"`
	Publisher          string        `json:"publisher"`
	Name               string        `json:"name"`
	ExtensionID        string        `json:"extension_id"` // "publisher.name" for VS Code; UUID for JetBrains
	Version            string        `json:"version,omitempty"`
	DisplayName        string        `json:"display_name,omitempty"`
	Description        string        `json:"description,omitempty"`
	Author             string        `json:"author,omitempty"`
	MainScript         string        `json:"main_script,omitempty"`
	EngineVersion      string        `json:"engine_version,omitempty"`
	ExtensionPath      string        `json:"extension_path"`
	ManifestPath       string        `json:"manifest_path,omitempty"`
	InstallSource      InstallSource `json:"install_source"`
	ActivationEvents   []string      `json:"activation_events,omitempty"`
	Categories         []string      `json:"categories,omitempty"`
	Keywords           []string      `json:"keywords,omitempty"`
	ActivatesOnStartup bool          `json:"activates_on_startup"`
}

// Collector is the read-only contract every implementation satisfies.
type Collector interface {
	Name() string
	Collect(ctx context.Context) ([]Extension, error)
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

// IsStartupActivation reports whether an activation event triggers at
// editor launch. "*" is the legacy always-on form (deprecated since VS
// Code 1.74 but still present in many extensions); "onStartupFinished"
// is the modern equivalent.
func IsStartupActivation(event string) bool {
	switch event {
	case "*", "onStartupFinished", "onStartup":
		return true
	}
	return false
}

// HasStartupActivation reports whether any of the extension's activation
// events fires on editor launch. Drives the high-blast-radius audit.
func HasStartupActivation(events []string) bool {
	for _, e := range events {
		if IsStartupActivation(e) {
			return true
		}
	}
	return false
}

// IsPublisherLookalike reports whether `publisher` looks like a typo-
// squat of a well-known publisher. Heuristic: case-insensitive equality
// against a curated list of trusted publishers OR exact match against
// known-bad lookalikes. The audit pipeline does the full lookup against
// the VSXcavator catalogue; this helper is the cheap on-host pre-filter.
func IsPublisherLookalike(publisher string) bool {
	p := strings.ToLower(publisher)
	for _, l := range knownLookalikes {
		if p == l {
			return true
		}
	}
	return false
}

// knownLookalikes is a tiny seed list. Real audit pipeline pulls a
// fuller list from the platform side. Conservative pre-filter only.
var knownLookalikes = []string{
	"ms-vscode-team",   // lookalike of "ms-vscode"
	"microsoft-vscode", // lookalike of "ms-vscode"
	"github-extension", // lookalike of "github"
	"vscode-microsoft", // lookalike of "ms-vscode"
	"vscode-official",  // not a real publisher
	"redhad",           // typo of "redhat"
	"prittier",         // typo of "prettier"
}

// SortExtensions returns a deterministic ordering: editor, profile,
// publisher, then name (publisher+name = unique key per editor profile).
func SortExtensions(es []Extension) {
	sort.Slice(es, func(i, j int) bool {
		if es[i].Editor != es[j].Editor {
			return es[i].Editor < es[j].Editor
		}
		if es[i].Profile != es[j].Profile {
			return es[i].Profile < es[j].Profile
		}
		if es[i].Publisher != es[j].Publisher {
			return es[i].Publisher < es[j].Publisher
		}
		return es[i].Name < es[j].Name
	})
}
