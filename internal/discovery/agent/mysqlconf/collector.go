package mysqlconf

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// DefaultSeedPaths is the canonical set of my.cnf files across the
// major Linux distros + macOS Homebrew. The collector follows
// !include / !includedir directives from each seed and dedupes by
// resolved path so cycles don't loop.
func DefaultSeedPaths() []string {
	return []string{
		"/etc/my.cnf",
		"/etc/mysql/my.cnf",
		"/etc/mysql/mariadb.cnf",
		"/usr/etc/my.cnf",
		"/opt/homebrew/etc/my.cnf",
	}
}

// DefaultUserPath returns ~/.my.cnf for the active HOME, or "" if
// HOME isn't set. The per-user cnf is where cleartext passwords
// typically leak.
func DefaultUserPath() string {
	if home := os.Getenv("HOME"); home != "" {
		return filepath.Join(home, ".my.cnf")
	}
	return ""
}

// fileCollector parses every my.cnf reachable from a configured seed
// list and follows !include / !includedir chains. Test seam swaps
// readFile and readDir.
type fileCollector struct {
	readFile func(string) ([]byte, error)
	readDir  func(string) ([]os.DirEntry, error)
	seeds    []string
}

// NewLinuxCollector returns a Collector wired to the canonical
// my.cnf chain plus ~/.my.cnf.
func NewLinuxCollector() Collector {
	seeds := DefaultSeedPaths()
	if u := DefaultUserPath(); u != "" {
		seeds = append(seeds, u)
	}
	return &fileCollector{
		seeds:    seeds,
		readFile: os.ReadFile,
		readDir:  os.ReadDir,
	}
}

func (c *fileCollector) Name() string { return "mysqlconf" }

func (c *fileCollector) Collect(_ context.Context) ([]Row, error) {
	visited := make(map[string]struct{})
	out := make([]Row, 0, len(c.seeds))

	var walk func(path string)
	walk = func(path string) {
		cleaned := filepath.Clean(path)
		if _, dup := visited[cleaned]; dup {
			return
		}
		visited[cleaned] = struct{}{}
		body, err := c.readFile(cleaned)
		if err != nil {
			return
		}
		res := Parse(body, cleaned)
		out = append(out, res.Rows...)
		// Resolve relative includes against the parent file's dir.
		parent := filepath.Dir(cleaned)
		for _, inc := range res.Includes {
			if !strings.HasPrefix(inc, "/") {
				inc = filepath.Join(parent, inc)
			}
			walk(inc)
		}
		for _, dir := range res.IncludeDirs {
			if !strings.HasPrefix(dir, "/") {
				dir = filepath.Join(parent, dir)
			}
			entries, err := c.readDir(dir)
			if err != nil {
				continue
			}
			sort.Slice(entries, func(i, j int) bool {
				return entries[i].Name() < entries[j].Name()
			})
			for _, e := range entries {
				if e.IsDir() {
					continue
				}
				name := e.Name()
				if !strings.HasSuffix(strings.ToLower(name), ".cnf") {
					continue
				}
				walk(filepath.Join(dir, name))
			}
		}
	}

	for _, seed := range c.seeds {
		walk(seed)
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
