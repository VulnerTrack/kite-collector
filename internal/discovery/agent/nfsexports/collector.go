package nfsexports

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// fileCollector reads /etc/exports + every drop-in under
// /etc/exports.d/. The drop-in directory is processed in lexical
// order — same convention exportfs uses when re-reading the union.
type fileCollector struct {
	readFile  func(string) ([]byte, error)
	readDir   func(string) ([]os.DirEntry, error)
	mainFile  string
	dropInDir string
}

// NewCollector returns the default exports walker.
func NewCollector() Collector {
	return &fileCollector{
		mainFile:  "/etc/exports",
		dropInDir: "/etc/exports.d",
		readFile:  func(p string) ([]byte, error) { return os.ReadFile(p) }, //#nosec G304 -- fixed system paths
		readDir:   func(p string) ([]os.DirEntry, error) { return os.ReadDir(p) },
	}
}

func (c *fileCollector) Name() string { return "nfs-exports-files" }

func (c *fileCollector) Collect(ctx context.Context) ([]Row, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context cancelled: %w", err)
	}
	var out []Row

	// Main /etc/exports.
	if data, err := c.readFile(c.mainFile); err == nil {
		out = append(out, Parse(data, c.mainFile)...)
	}

	// Drop-ins (lexical order for stable diffs).
	for _, p := range c.lexicalFiles(c.dropInDir, ".exports") {
		if err := ctx.Err(); err != nil {
			return out, fmt.Errorf("context cancelled mid-walk: %w", err)
		}
		data, err := c.readFile(p)
		if err != nil {
			continue
		}
		out = append(out, Parse(data, p)...)
		if len(out) >= MaxRows {
			break
		}
	}

	if len(out) > MaxRows {
		out = out[:MaxRows]
	}
	SortRows(out)
	return out, nil
}

// lexicalFiles returns the lexically-sorted absolute paths of files
// in `dir` ending in `suffix`. Backup/swap variants are filtered out.
func (c *fileCollector) lexicalFiles(dir, suffix string) []string {
	entries, err := c.readDir(dir)
	if err != nil {
		return nil
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, suffix) {
			continue
		}
		if strings.HasPrefix(name, ".") ||
			strings.HasSuffix(name, "~") ||
			strings.HasSuffix(name, ".bak") ||
			strings.HasSuffix(name, ".dpkg-old") ||
			strings.HasSuffix(name, ".rpmsave") ||
			strings.HasSuffix(name, ".swp") {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]string, 0, len(names))
	for _, n := range names {
		out = append(out, filepath.Join(dir, n))
	}
	return out
}
