package systemdunits

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// DefaultUnitDirs is the canonical systemd unit-search path. The
// collector walks these in the same order systemd resolves overrides
// (etc → run → usr/lib → lib) so the audit pipeline gets a stable
// view, even though we currently store one row per *file*, not per
// effective-unit.
func DefaultUnitDirs() []string {
	return []string{
		"/etc/systemd/system",
		"/run/systemd/system",
		"/usr/lib/systemd/system",
		"/lib/systemd/system",
	}
}

// fileCollector walks unit files from configurable directories.
// Test seam swaps readFile / readDir.
type fileCollector struct {
	readFile func(string) ([]byte, error)
	readDir  func(string) ([]os.DirEntry, error)
	dirs     []string
}

// NewLinuxCollector returns a Collector wired to the canonical
// systemd unit directories.
func NewLinuxCollector() Collector {
	return &fileCollector{
		dirs:     DefaultUnitDirs(),
		readFile: os.ReadFile,
		readDir:  os.ReadDir,
	}
}

func (c *fileCollector) Name() string { return "systemdunits" }

func (c *fileCollector) Collect(_ context.Context) ([]Unit, error) {
	out := make([]Unit, 0, 256)
	for _, dir := range c.dirs {
		entries, err := c.readDir(dir)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			return nil, err
		}
		sort.Slice(entries, func(i, j int) bool {
			return entries[i].Name() < entries[j].Name()
		})
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			name := e.Name()
			if !isUnitFile(name) {
				continue
			}
			path := filepath.Join(dir, name)
			body, err := c.readFile(path)
			if err != nil {
				continue
			}
			out = append(out, Parse(body, path))
			if len(out) >= MaxUnits {
				break
			}
		}
		if len(out) >= MaxUnits {
			break
		}
	}
	SortUnits(out)
	return out, nil
}

// isUnitFile reports whether a filename names a systemd unit. We
// match the standard suffixes systemd recognises.
func isUnitFile(name string) bool {
	if strings.HasPrefix(name, ".") {
		return false
	}
	lower := strings.ToLower(name)
	for _, ext := range []string{
		".service", ".socket", ".timer", ".mount", ".path", ".target",
	} {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}
