package wireguard

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// DefaultConfigDirs is the canonical set of directories holding
// WireGuard tunnel configs across Linux distros + macOS Homebrew.
func DefaultConfigDirs() []string {
	return []string{
		"/etc/wireguard",
		"/usr/local/etc/wireguard",
		"/opt/homebrew/etc/wireguard",
	}
}

// fileCollector walks .conf files from configurable directories.
// The test seam swaps readFile / readDir / statFile.
type fileCollector struct {
	readFile func(string) ([]byte, error)
	readDir  func(string) ([]os.DirEntry, error)
	statFile func(string) (os.FileInfo, error)
	dirs     []string
}

// NewLinuxCollector returns a Collector wired to the canonical
// WireGuard directories. Missing directories are silently skipped.
func NewLinuxCollector() Collector {
	return &fileCollector{
		dirs:     DefaultConfigDirs(),
		readFile: os.ReadFile,
		readDir:  os.ReadDir,
		statFile: os.Stat,
	}
}

func (c *fileCollector) Name() string { return "wireguard" }

func (c *fileCollector) Collect(_ context.Context) ([]Tunnel, error) {
	out := make([]Tunnel, 0, 8)
	for _, dir := range c.dirs {
		entries, err := c.readDir(dir)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			return nil, err
		}
		// Lexical order for deterministic output across scans.
		sort.Slice(entries, func(i, j int) bool {
			return entries[i].Name() < entries[j].Name()
		})
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			name := e.Name()
			if !strings.HasSuffix(strings.ToLower(name), ".conf") {
				continue
			}
			if strings.HasPrefix(name, ".") {
				continue
			}
			path := filepath.Join(dir, name)
			body, err := c.readFile(path)
			if err != nil {
				continue
			}
			rows := Parse(body, path)
			// Stamp file-mode and owner onto every row so the audit
			// pipeline can hit `has_private_key_exposed` without an
			// extra join.
			if fi, statErr := c.statFile(path); statErr == nil {
				mode := int(fi.Mode().Perm())
				for i := range rows {
					rows[i].FileMode = mode
					populateOwner(&rows[i], fi)
					AnnotateSecurity(&rows[i])
				}
			}
			out = append(out, rows...)
			if len(out) >= MaxRows {
				break
			}
		}
		if len(out) >= MaxRows {
			break
		}
	}
	SortTunnels(out)
	return out, nil
}
