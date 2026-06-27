package launchd

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// DefaultSystemRoots is the set of directories walked on macOS hosts.
// Per-user agent directories (~/Library/LaunchAgents) are added by
// NewDarwinCollector at construction time when HOME is set.
func DefaultSystemRoots() []string {
	return []string{
		"/Library/LaunchDaemons",
		"/Library/LaunchAgents",
		"/System/Library/LaunchDaemons",
		"/System/Library/LaunchAgents",
	}
}

// fileCollector walks plist directories from a configurable list.
// The test seam swaps readFile/readDir/statFile.
type fileCollector struct {
	readFile func(string) ([]byte, error)
	readDir  func(string) ([]os.DirEntry, error)
	statFile func(string) (os.FileInfo, error)
	roots    []string
}

// NewDarwinCollector returns a Collector wired to the canonical
// launchd plist directories. On non-Darwin OSes the same collector
// runs harmlessly — no /Library directory exists, every root returns
// fs.ErrNotExist and the Collect call yields an empty slice.
func NewDarwinCollector() Collector {
	roots := DefaultSystemRoots()
	if home := os.Getenv("HOME"); home != "" {
		roots = append(roots, filepath.Join(home, "Library", "LaunchAgents"))
	}
	return &fileCollector{
		roots:    roots,
		readFile: os.ReadFile,
		readDir:  os.ReadDir,
		statFile: os.Stat,
	}
}

func (c *fileCollector) Name() string { return "launchd" }

func (c *fileCollector) Collect(_ context.Context) ([]Service, error) {
	out := make([]Service, 0, 256)
	for _, root := range c.roots {
		entries, err := c.readDir(root)
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
			if !strings.HasSuffix(strings.ToLower(name), ".plist") {
				continue
			}
			if strings.HasPrefix(name, ".") {
				continue
			}
			path := filepath.Join(root, name)
			body, err := c.readFile(path)
			if err != nil {
				continue
			}
			svc, err := ParsePlist(body)
			if err != nil {
				continue
			}
			svc.FilePath = path
			svc.FileHash = HashContents(body)
			svc.PlistScope = PlistScopeFromPath(path)
			if fi, statErr := c.statFile(path); statErr == nil {
				svc.FileMode = int(fi.Mode().Perm())
				populateOwner(&svc, fi)
			}
			AnnotateSecurity(&svc)
			out = append(out, svc)
			if len(out) >= MaxServices {
				break
			}
		}
		if len(out) >= MaxServices {
			break
		}
	}
	SortServices(out)
	return out, nil
}
