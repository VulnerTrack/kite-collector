package software

import (
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/google/uuid"

	"github.com/vulnertrack/kite-collector/internal/model"
)

// NpmScan is a NATIVE filesystem scanner for Node.js packages. Unlike the Npm
// collector (which runs `npm list -g` and therefore sees only global,
// top-level packages), NpmScan walks node_modules trees on disk and reads
// every package's package.json — the coverage osquery's npm_packages table
// provides, without depending on the npm binary or a running osqueryd.
//
// It emits ONE row per install location (osquery npm_packages semantics), so
// the same package installed in several projects yields several rows, each
// with its own install_path and depth. It never follows symlinks
// (filepath.WalkDir does not), so symlinked/hoisted node_modules cannot cause
// cycles, and it is bounded by MaxPackages and the scan context deadline.
//
// It captures the full npm_packages field set — name, version, author→vendor,
// description, license, homepage, install path, and nesting depth — all of
// which persist to installed_software.
type NpmScan struct {
	lookPath    func(string) (string, error)
	userHome    func() (string, error)
	statDir     func(string) bool
	roots       []string // explicit roots; empty → auto-detected
	maxPackages int
}

// NewNpmScan returns a filesystem npm scanner with production defaults.
func NewNpmScan() *NpmScan {
	return &NpmScan{
		lookPath:    exec.LookPath,
		userHome:    os.UserHomeDir,
		statDir:     dirExists,
		maxPackages: 50000,
	}
}

// Name returns the stable collector identifier. It reuses "npm" so the
// scanner is a drop-in replacement for the global-only Npm collector.
func (n *NpmScan) Name() string { return "npm" }

// Available reports whether this host looks like it uses Node.js, so the
// (potentially large) filesystem walk is skipped on hosts that don't. It
// deliberately does NOT require the npm binary on PATH — a filesystem scan
// works even when the service runs as a user without npm in its PATH.
func (n *NpmScan) Available() bool {
	if _, err := n.lookPath("node"); err == nil {
		return true
	}
	if _, err := n.lookPath("npm"); err == nil {
		return true
	}
	for _, d := range []string{"/usr/lib/node_modules", "/usr/local/lib/node_modules"} {
		if n.statDir(d) {
			return true
		}
	}
	if home, err := n.userHome(); err == nil {
		for _, d := range []string{".nvm", ".npm", ".node_modules"} {
			if n.statDir(filepath.Join(home, d)) {
				return true
			}
		}
	}
	return false
}

// Collect walks every root's node_modules trees and returns the distinct set
// of installed Node packages.
func (n *NpmScan) Collect(ctx context.Context) (*Result, error) {
	result := &Result{}
	seen := make(map[string]struct{})

	for _, root := range n.effectiveRoots() {
		if ctx.Err() != nil {
			break
		}
		if len(result.Items) >= n.maxPackages {
			break
		}
		n.scanRoot(ctx, root, result, seen)
	}

	result.Sort()
	return result, nil //nolint:nilerr // a canceled walk still reports the packages found so far
}

// effectiveRoots returns the directories to walk. Explicit roots (tests,
// future config) win; otherwise a curated set covering global installs
// (system + nvm) and the user's home (project node_modules).
func (n *NpmScan) effectiveRoots() []string {
	if len(n.roots) > 0 {
		return n.roots
	}
	var roots []string
	seen := map[string]struct{}{}
	add := func(p string) {
		if p == "" {
			return
		}
		if _, dup := seen[p]; dup || !n.statDir(p) {
			return
		}
		seen[p] = struct{}{}
		roots = append(roots, p)
	}
	add("/usr/lib/node_modules")
	add("/usr/local/lib/node_modules")
	if home, err := n.userHome(); err == nil {
		add(home) // covers ~/.nvm, ~/.npm, and every project node_modules
	}
	return roots
}

// scanRoot walks one root, reading the manifest of each installed package.
func (n *NpmScan) scanRoot(ctx context.Context, root string, result *Result, seen map[string]struct{}) {
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr // unreadable dir (permissions) — skip, don't abort
		}
		if ctx.Err() != nil || len(result.Items) >= n.maxPackages {
			return filepath.SkipAll
		}
		if d.IsDir() || d.Name() != "package.json" {
			return nil
		}
		dir := filepath.Dir(path)
		if !isNodeModulesPackageDir(dir) {
			return nil // a package.json not at an installed-package root
		}
		data, rerr := os.ReadFile(path) //#nosec G304 G122 -- path from WalkDir under scanned root; read-only inventory, a TOCTOU swap yields at worst a bogus manifest
		if rerr != nil {
			return nil //nolint:nilerr // unreadable manifest — skip this package, keep walking
		}
		m, ok := parseNpmManifest(data)
		if !ok {
			return nil
		}
		// Key on the install directory: each install LOCATION is its own row
		// (osquery npm_packages semantics), so the same package installed in
		// several projects is faithfully represented. seen only guards against
		// re-visiting a path when configured roots overlap.
		if _, dup := seen[dir]; dup {
			return nil
		}
		seen[dir] = struct{}{}
		result.Items = append(result.Items, model.InstalledSoftware{
			ID:             uuid.Must(uuid.NewV7()),
			SoftwareName:   m.Name,
			Vendor:         m.Author,
			Version:        m.Version,
			PackageManager: "npm",
			CPE23:          BuildCPE23WithTargetSW("", m.Name, m.Version, "node.js"),
			Description:    m.Description,
			License:        m.License,
			Homepage:       m.Homepage,
			InstallPath:    dir,
			Depth:          nodeModulesDepth(dir),
		})
		return nil
	})
}

// nodeModulesDepth returns the package's nesting depth: 0 for a direct
// install (node_modules/<pkg>), 1 for a package nested inside another
// package's node_modules, and so on — matching osquery npm_packages.depth.
func nodeModulesDepth(dir string) int {
	n := 0
	for _, seg := range strings.Split(filepath.ToSlash(dir), "/") {
		if seg == "node_modules" {
			n++
		}
	}
	if n <= 1 {
		return 0
	}
	return n - 1
}

// isNodeModulesPackageDir reports whether dir is the root directory of an
// installed package — i.e. node_modules/<pkg> or node_modules/@scope/<pkg>.
// This rejects the stray package.json files that packages ship inside their
// own subtrees (used for "exports"/types resolution), which are not separate
// installed packages and would otherwise inflate the count.
func isNodeModulesPackageDir(dir string) bool {
	parent := filepath.Base(filepath.Dir(dir))
	if parent == "node_modules" {
		return true
	}
	// Scoped: node_modules/@scope/<pkg>.
	if strings.HasPrefix(parent, "@") &&
		filepath.Base(filepath.Dir(filepath.Dir(dir))) == "node_modules" {
		return true
	}
	return false
}

// npmManifest is the parsed, normalized view of a package.json. It captures
// the full npm_packages field set even though only Name/Version/Author are
// persisted today.
type npmManifest struct {
	Name        string
	Version     string
	Description string
	Author      string
	License     string
	Homepage    string
}

// rawManifest mirrors the package.json fields we read. Author and License are
// polymorphic in npm (string OR object OR — for license — a deprecated array),
// so they are decoded from json.RawMessage.
type rawManifest struct {
	Name        string          `json:"name"`
	Version     string          `json:"version"`
	Description string          `json:"description"`
	Homepage    string          `json:"homepage"`
	Author      json.RawMessage `json:"author"`
	License     json.RawMessage `json:"license"`
}

// parseNpmManifest parses a package.json byte slice. It returns ok=false when
// the JSON is invalid or the manifest has no name (a private/nameless
// package.json is not an installed package we can key on).
func parseNpmManifest(data []byte) (npmManifest, bool) {
	var raw rawManifest
	if err := json.Unmarshal(data, &raw); err != nil {
		return npmManifest{}, false
	}
	if strings.TrimSpace(raw.Name) == "" {
		return npmManifest{}, false
	}
	return npmManifest{
		Name:        raw.Name,
		Version:     raw.Version,
		Description: raw.Description,
		Homepage:    raw.Homepage,
		Author:      normalizeNpmPerson(raw.Author),
		License:     normalizeNpmLicense(raw.License),
	}, true
}

// normalizeNpmPerson extracts a display name from npm's "person" field, which
// is either a string ("Name <email> (url)") or an object {name,email,url}.
func normalizeNpmPerson(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		// Trim the "<email>" and "(url)" decorations from the string form.
		if i := strings.IndexAny(s, "<("); i > 0 {
			s = s[:i]
		}
		return strings.TrimSpace(s)
	}
	var obj struct {
		Name string `json:"name"`
	}
	if json.Unmarshal(raw, &obj) == nil {
		return strings.TrimSpace(obj.Name)
	}
	return ""
}

// normalizeNpmLicense extracts an SPDX id from npm's "license" field: a string
// ("MIT"), an object ({"type":"MIT"}), or the deprecated array of such objects.
func normalizeNpmLicense(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return strings.TrimSpace(s)
	}
	var obj struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(raw, &obj) == nil && obj.Type != "" {
		return strings.TrimSpace(obj.Type)
	}
	var arr []struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(raw, &arr) == nil && len(arr) > 0 {
		return strings.TrimSpace(arr[0].Type)
	}
	return ""
}

// dirExists reports whether path is an existing directory.
func dirExists(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.IsDir()
}

// Compile-time interface check.
var _ Collector = (*NpmScan)(nil)
