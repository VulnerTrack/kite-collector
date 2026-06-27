// Package winnpm inventories globally-installed npm packages by
// walking the canonical `node_modules` roots on each OS:
//
//	Windows:        %APPDATA%\npm\node_modules\<pkg>\package.json
//	Linux:          /usr/lib/node_modules/<pkg>/package.json
//	macOS (brew):   /usr/local/lib/node_modules/<pkg>/package.json
//	macOS (arm):    /opt/homebrew/lib/node_modules/<pkg>/package.json
//	nvm everywhere: $HOME/.nvm/versions/node/*/lib/node_modules/<pkg>/package.json
//
// File-based discovery is the deliberate design choice. The audit
// pipeline cross-references `(name, version)` against the npm
// registry and the OSV CVE feed without needing `npm ls -g`.
// Manifest SHA-256 captures supply-chain drift between scans —
// the ua-parser-js / event-stream / chalk-takeover compromises
// all manifested as new versions of already-installed packages.
//
// Headline finding shapes (MITRE T1195.002 — Software Supply
// Chain Compromise, plus T1059.007 — JavaScript when install
// scripts run code):
//
//   - `has_install_scripts=1` — package declares any of
//     `preinstall`/`install`/`postinstall` in `scripts`. These
//     run at install time with the calling user's privileges
//     (often root via `sudo npm install -g`). CWE-1188.
//   - `has_bin_entries=1` — package declares `bin` mappings;
//     installs CLI commands the user can invoke straight from
//     the shell.
//   - `has_no_license=1` — package ships without a license
//     declaration. Rare on the public registry; common for
//     hand-rolled or private packages.
//   - `is_scoped_package=1` — `@scope/name` prefix. Useful
//     grouping for the audit report.
//
// Read-only by intent — we walk the node_modules directories
// only, never invoke `npm`. (Project guideline 4.2.)
package winnpm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
)

// MaxPackages bounds per-scan output. A loaded dev workstation
// has 30-150 global packages; the 8192 ceiling covers
// CI-runner-style installs.
const MaxPackages = 8192

// InstallScriptNames is the set of npm script keys that run
// arbitrary code as part of `npm install`. Any of these in the
// `scripts` map flips has_install_scripts=1.
func InstallScriptNames() []string {
	return []string{
		"preinstall",
		"install",
		"postinstall",
		"prepare",
	}
}

// Package mirrors host_npm_global_packages' column shape exactly.
type Package struct {
	RepositoryURL      string   `json:"repository_url,omitempty"`
	Author             string   `json:"author,omitempty"`
	PackageDir         string   `json:"package_dir"`
	InstallPrefix      string   `json:"install_prefix"`
	Name               string   `json:"name"`
	Version            string   `json:"version,omitempty"`
	Description        string   `json:"description,omitempty"`
	EngineNode         string   `json:"engine_node,omitempty"`
	MainEntry          string   `json:"main_entry,omitempty"`
	Homepage           string   `json:"homepage,omitempty"`
	FileHash           string   `json:"file_hash"`
	FilePath           string   `json:"file_path"`
	License            string   `json:"license,omitempty"`
	Dependencies       []string `json:"dependencies,omitempty"`
	BinEntries         []string `json:"bin_entries,omitempty"`
	InstallScriptNames []string `json:"install_script_names,omitempty"`
	DependencyCount    int      `json:"dependency_count"`
	IsScopedPackage    bool     `json:"is_scoped_package"`
	HasInstallScripts  bool     `json:"has_install_scripts"`
	HasBinEntries      bool     `json:"has_bin_entries"`
	HasNoLicense       bool     `json:"has_no_license"`
	HasNoHomepage      bool     `json:"has_no_homepage"`
	HasNoRepository    bool     `json:"has_no_repository"`
}

// Collector is the read-only contract every implementation satisfies.
type Collector interface {
	Name() string
	Collect(ctx context.Context) ([]Package, error)
}

// HashContents returns the SHA-256 hex of a manifest body.
func HashContents(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// IsScopedName reports whether `name` starts with `@`. npm scope
// packages are written `@scope/name`.
func IsScopedName(name string) bool {
	return strings.HasPrefix(strings.TrimSpace(name), "@")
}

// AnnotateSecurity sets the derived booleans on a Package that
// has its raw fields populated.
func AnnotateSecurity(p *Package) {
	p.IsScopedPackage = IsScopedName(p.Name)
	p.HasInstallScripts = len(p.InstallScriptNames) > 0
	p.HasBinEntries = len(p.BinEntries) > 0
	p.HasNoLicense = strings.TrimSpace(p.License) == ""
	p.HasNoHomepage = strings.TrimSpace(p.Homepage) == ""
	p.HasNoRepository = strings.TrimSpace(p.RepositoryURL) == ""
	p.DependencyCount = len(p.Dependencies)
}

// SortPackages returns a deterministic ordering by name then version.
func SortPackages(ps []Package) {
	sort.Slice(ps, func(i, j int) bool {
		if ps[i].Name != ps[j].Name {
			return ps[i].Name < ps[j].Name
		}
		return ps[i].Version < ps[j].Version
	})
}

// EncodeStringList returns a JSON array suitable for the *_json
// columns. Empty input always emits "[]".
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
