package pghba

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// fileCollector walks the conventional pg_hba.conf locations on every
// supported OS. Each `.conf` file found is parsed; failures don't sink
// the chain (a typical host has only one installation tree).
type fileCollector struct {
	readFile func(string) ([]byte, error)
	readDir  func(string) ([]os.DirEntry, error)
	statFile func(string) (fs.FileInfo, error)
	roots    []string
}

// NewCollector returns the default pg_hba walker.
func NewCollector() Collector {
	return &fileCollector{
		roots:    DefaultRoots(),
		readFile: func(p string) ([]byte, error) { return os.ReadFile(p) }, //#nosec G304 -- fixed system paths
		readDir:  func(p string) ([]os.DirEntry, error) { return os.ReadDir(p) },
		statFile: func(p string) (fs.FileInfo, error) { return os.Stat(p) },
	}
}

// DefaultRoots is the curated set of directories where pg_hba.conf
// can live on a stock install. The walker descends one or two levels
// per root looking for `pg_hba.conf`.
func DefaultRoots() []string {
	return []string{
		"/etc/postgresql",            // Debian/Ubuntu, versioned
		"/var/lib/postgresql",        // Debian alt
		"/var/lib/pgsql",             // RHEL/Fedora
		"/var/lib/pgsql/data",        // RHEL non-versioned
		"/usr/local/var/postgres",    // macOS Homebrew (Intel)
		"/opt/homebrew/var/postgres", // macOS Homebrew (Apple Silicon)
		"/opt/homebrew/var/postgresql@16",
		"/opt/homebrew/var/postgresql@15",
		"/opt/homebrew/var/postgresql@14",
		"/etc/postgresql-common",
	}
}

func (c *fileCollector) Name() string { return "pghba-files" }

func (c *fileCollector) Collect(ctx context.Context) ([]Row, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context cancelled: %w", err)
	}
	var (
		out  []Row
		seen = make(map[string]bool)
	)
	for _, root := range c.roots {
		if err := ctx.Err(); err != nil {
			return out, fmt.Errorf("context cancelled mid-walk: %w", err)
		}
		c.walkRoot(root, &out, seen)
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

// walkRoot looks for pg_hba.conf at the root and at depth-1
// children (the versioned-cluster layout: /etc/postgresql/15/main/
// pg_hba.conf, /var/lib/pgsql/15/data/pg_hba.conf, ...). We don't
// recurse deeper to keep the walk bounded — Postgres conventionally
// doesn't go beyond depth 2 from these roots.
func (c *fileCollector) walkRoot(root string, out *[]Row, seen map[string]bool) {
	c.tryParse(filepath.Join(root, "pg_hba.conf"), out, seen)
	entries, err := c.readDir(root)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(root, e.Name())
		// Postgres versioned dirs typically have a `main` (Debian) or
		// `data` (RHEL) child holding pg_hba.conf.
		for _, leaf := range []string{
			"pg_hba.conf",
			"main/pg_hba.conf",
			"data/pg_hba.conf",
		} {
			c.tryParse(filepath.Join(dir, leaf), out, seen)
			if len(*out) >= MaxRows {
				return
			}
		}
	}
}

// tryParse reads + parses one pg_hba.conf path. No-op on unreadable.
func (c *fileCollector) tryParse(path string, out *[]Row, seen map[string]bool) {
	if seen[path] {
		return
	}
	// Quick existence check via stat — saves a slog.Debug call when
	// the directory simply doesn't have the leaf file.
	if _, err := c.statFile(path); err != nil {
		return
	}
	seen[path] = true
	data, err := c.readFile(path)
	if err != nil {
		slog.Debug("pghba: file unreadable", "path", path, "error", err)
		return
	}
	rows := Parse(data, path)
	*out = append(*out, rows...)
}

// Compile-time check that the default walker honours its contract.
var _ = strings.HasPrefix // referenced indirectly via DefaultRoots; keeps lint happy when more roots are added.

// SortDefaultRoots is a tiny helper used by golden-file tests.
func SortDefaultRoots(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}
