package chocolatey

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// DefaultLibRoot is the canonical Chocolatey lib directory on every
// modern Windows install. The parser is OS-agnostic, so the collector
// is build-tag-agnostic — on non-Windows hosts the root doesn't
// exist and Collect returns an empty slice.
const DefaultLibRoot = `C:\ProgramData\chocolatey\lib`

// fileCollector walks the chocolatey lib directory from a configurable
// root. Test seam swaps readFile / readDir.
type fileCollector struct {
	readFile func(string) ([]byte, error)
	readDir  func(string) ([]os.DirEntry, error)
	root     string
}

// NewCollector returns a Collector wired to the canonical lib root.
// Missing root → empty slice (Chocolatey not installed).
func NewCollector() Collector {
	return &fileCollector{
		root:     DefaultLibRoot,
		readFile: os.ReadFile,
		readDir:  os.ReadDir,
	}
}

func (c *fileCollector) Name() string { return "chocolatey" }

func (c *fileCollector) Collect(_ context.Context) ([]Package, error) {
	entries, err := c.readDir(c.root)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	// Lexical order for deterministic output across scans.
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name() < entries[j].Name()
	})

	out := make([]Package, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}
		// The canonical nuspec lives at lib/<pkg>/<pkg>.nuspec; try
		// that first, then fall back to any *.nuspec in the dir for
		// non-standard installers.
		pkgDir := filepath.Join(c.root, name)
		path := filepath.Join(pkgDir, name+".nuspec")
		body, err := c.readFile(path)
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				continue
			}
			body, path, err = readAnyNuspec(c, pkgDir)
			if err != nil {
				continue
			}
		}
		pkg, err := ParseNuspec(body, path)
		if err != nil {
			continue
		}
		out = append(out, pkg)
		if len(out) >= MaxPackages {
			break
		}
	}
	SortPackages(out)
	return out, nil
}

// readAnyNuspec returns the first *.nuspec file the collector finds
// inside `dir`, alongside the resolved path. Returns ErrNotExist if
// none is found so the caller can skip the directory.
func readAnyNuspec(c *fileCollector, dir string) ([]byte, string, error) {
	entries, err := c.readDir(dir)
	if err != nil {
		return nil, "", err
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name() < entries[j].Name()
	})
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if !strings.HasSuffix(strings.ToLower(e.Name()), ".nuspec") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		body, err := c.readFile(path)
		if err != nil {
			continue
		}
		return body, path, nil
	}
	return nil, "", fs.ErrNotExist
}
