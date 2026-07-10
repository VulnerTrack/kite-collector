package winnpm

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// DefaultGlobalRoots is the curated set of `node_modules` paths
// where npm installs global packages across Windows, Linux and
// macOS. NVM-managed installs land under
// $HOME/.nvm/versions/node/*/lib/node_modules and are discovered
// at construction time via the HOME env var.
func DefaultGlobalRoots() []string {
	roots := []string{
		`C:\Program Files\nodejs\node_modules`,
		`C:\Program Files (x86)\nodejs\node_modules`,
		"/usr/lib/node_modules",
		"/usr/local/lib/node_modules",
		"/opt/homebrew/lib/node_modules",
	}
	if appData := os.Getenv("APPDATA"); appData != "" {
		roots = append(roots, filepath.Join(appData, "npm", "node_modules"))
	}
	if home := os.Getenv("HOME"); home != "" {
		// Direct user-level prefix.
		roots = append(
			roots,
			filepath.Join(home, ".npm-global", "lib", "node_modules"),
			filepath.Join(home, "node_modules"),
		)
	}
	return roots
}

// fileCollector walks node_modules trees from a configurable seed
// list. Test seam swaps readFile / readDir.
type fileCollector struct {
	readFile func(string) ([]byte, error)
	readDir  func(string) ([]os.DirEntry, error)
	roots    []string
}

// NewCollector returns a Collector wired to the canonical
// per-OS roots. Missing roots are silently skipped.
func NewCollector() Collector {
	return &fileCollector{
		roots:    DefaultGlobalRoots(),
		readFile: os.ReadFile,
		readDir:  os.ReadDir,
	}
}

func (c *fileCollector) Name() string { return "winnpm" }

func (c *fileCollector) Collect(_ context.Context) ([]Package, error) {
	out := make([]Package, 0, 64)
	for _, root := range c.roots {
		c.harvestRoot(root, &out)
		if len(out) >= MaxPackages {
			break
		}
	}
	if len(out) > MaxPackages {
		out = out[:MaxPackages]
	}
	SortPackages(out)
	return out, nil
}

// harvestRoot lists `root`'s immediate subdirectories. Each
// directory is either a package (contains package.json) or an
// `@scope/` parent whose children are scoped packages.
func (c *fileCollector) harvestRoot(root string, out *[]Package) {
	entries, err := c.readDir(root)
	if err != nil {
		// Missing root (fs.ErrNotExist) and permission errors both
		// resolve to "no rows from this root" — the audit pipeline
		// notices the absence on its own.
		return
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name() < entries[j].Name()
	})
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}
		dir := filepath.Join(root, name)
		if strings.HasPrefix(name, "@") {
			// Scoped parent — walk children.
			c.harvestScope(root, name, out)
			continue
		}
		c.parsePackageDir(dir, root, out)
		if len(*out) >= MaxPackages {
			return
		}
	}
}

// harvestScope walks the contents of `<root>/<scope>/`. Each
// child is a scoped package `@scope/name`.
func (c *fileCollector) harvestScope(root, scope string, out *[]Package) {
	scopeDir := filepath.Join(root, scope)
	entries, err := c.readDir(scopeDir)
	if err != nil {
		return
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name() < entries[j].Name()
	})
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}
		dir := filepath.Join(scopeDir, name)
		c.parsePackageDir(dir, root, out)
		if len(*out) >= MaxPackages {
			return
		}
	}
}

// parsePackageDir reads package.json from `pkgDir` and emits a
// row. `prefix` is the top-level node_modules root that produced
// this package (used to populate InstallPrefix).
func (c *fileCollector) parsePackageDir(pkgDir, prefix string, out *[]Package) {
	manifest := filepath.Join(pkgDir, "package.json")
	body, err := c.readFile(manifest)
	if err != nil {
		return
	}
	pkg, err := ParseManifest(body)
	if err != nil {
		return
	}
	pkg.FilePath = manifest
	pkg.FileHash = HashContents(body)
	pkg.PackageDir = pkgDir
	pkg.InstallPrefix = prefix
	// If the manifest didn't carry `name`, fall back to the dir
	// hierarchy. Scoped packages: `node_modules/@scope/name`.
	if pkg.Name == "" {
		pkg.Name = inferName(pkgDir, prefix)
	}
	AnnotateSecurity(&pkg)
	*out = append(*out, pkg)
}

// inferName recovers a package name from `pkgDir` relative to
// `prefix`. `node_modules/foo` → `foo`; `node_modules/@s/bar` →
// `@s/bar`.
func inferName(pkgDir, prefix string) string {
	rel, err := filepath.Rel(prefix, pkgDir)
	if err != nil {
		return ""
	}
	rel = filepath.ToSlash(rel)
	parts := strings.Split(rel, "/")
	if len(parts) == 0 {
		return ""
	}
	if strings.HasPrefix(parts[0], "@") && len(parts) >= 2 {
		return parts[0] + "/" + parts[1]
	}
	return parts[0]
}
