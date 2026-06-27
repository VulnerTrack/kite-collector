package rsyslog

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// DefaultSeedPaths is the canonical set of rsyslog top-level
// config files across the major Linux distros + macOS Homebrew.
func DefaultSeedPaths() []string {
	return []string{
		"/etc/rsyslog.conf",
		"/usr/local/etc/rsyslog.conf",
		"/opt/homebrew/etc/rsyslog.conf",
	}
}

// DefaultDropInDirs is the canonical set of drop-in directories.
func DefaultDropInDirs() []string {
	return []string{
		"/etc/rsyslog.d",
		"/usr/local/etc/rsyslog.d",
		"/opt/homebrew/etc/rsyslog.d",
	}
}

// fileCollector walks rsyslog configs from a configurable seed list
// + drop-in directories. Test seam swaps readFile / readDir.
type fileCollector struct {
	readFile   func(string) ([]byte, error)
	readDir    func(string) ([]os.DirEntry, error)
	seeds      []string
	dropInDirs []string
}

// NewLinuxCollector returns a Collector wired to the canonical
// rsyslog configuration paths.
func NewLinuxCollector() Collector {
	return &fileCollector{
		seeds:      DefaultSeedPaths(),
		dropInDirs: DefaultDropInDirs(),
		readFile:   os.ReadFile,
		readDir:    os.ReadDir,
	}
}

func (c *fileCollector) Name() string { return "rsyslog" }

func (c *fileCollector) Collect(_ context.Context) ([]Forwarder, error) {
	out := make([]Forwarder, 0, 8)
	visited := make(map[string]struct{})

	parse := func(path string) {
		cleaned := filepath.Clean(path)
		if _, dup := visited[cleaned]; dup {
			return
		}
		visited[cleaned] = struct{}{}
		body, err := c.readFile(cleaned)
		if err != nil {
			return
		}
		out = append(out, Parse(body, cleaned)...)
	}

	for _, seed := range c.seeds {
		parse(seed)
		if len(out) >= MaxRows {
			break
		}
	}

	for _, dir := range c.dropInDirs {
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
			if !strings.HasSuffix(strings.ToLower(name), ".conf") {
				continue
			}
			if strings.HasPrefix(name, ".") {
				continue
			}
			parse(filepath.Join(dir, name))
			if len(out) >= MaxRows {
				break
			}
		}
		if len(out) >= MaxRows {
			break
		}
	}

	if len(out) > MaxRows {
		out = out[:MaxRows]
	}
	SortForwarders(out)
	return out, nil
}
