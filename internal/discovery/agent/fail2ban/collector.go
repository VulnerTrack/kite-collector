package fail2ban

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// DefaultSeedPaths is the canonical set of fail2ban configuration
// files across the major Linux distros + macOS Homebrew. The
// collector also walks the jail.d drop-in directory (lexical order
// for deterministic output).
func DefaultSeedPaths() []string {
	return []string{
		"/etc/fail2ban/jail.conf",
		"/etc/fail2ban/jail.local",
		"/usr/local/etc/fail2ban/jail.conf",
		"/usr/local/etc/fail2ban/jail.local",
		"/opt/homebrew/etc/fail2ban/jail.conf",
		"/opt/homebrew/etc/fail2ban/jail.local",
	}
}

// DefaultDropInDirs is the canonical set of jail.d drop-in
// directories. Each `.conf` file under these is parsed in lexical
// order.
func DefaultDropInDirs() []string {
	return []string{
		"/etc/fail2ban/jail.d",
		"/usr/local/etc/fail2ban/jail.d",
		"/opt/homebrew/etc/fail2ban/jail.d",
	}
}

// fileCollector walks fail2ban configs from a configurable seed list
// + drop-in directories. Test seam swaps readFile / readDir.
type fileCollector struct {
	readFile   func(string) ([]byte, error)
	readDir    func(string) ([]os.DirEntry, error)
	seeds      []string
	dropInDirs []string
}

// NewLinuxCollector returns a Collector wired to the canonical
// fail2ban configuration paths.
func NewLinuxCollector() Collector {
	return &fileCollector{
		seeds:      DefaultSeedPaths(),
		dropInDirs: DefaultDropInDirs(),
		readFile:   os.ReadFile,
		readDir:    os.ReadDir,
	}
}

func (c *fileCollector) Name() string { return "fail2ban" }

func (c *fileCollector) Collect(_ context.Context) ([]Jail, error) {
	out := make([]Jail, 0, 16)
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
	SortJails(out)
	return out, nil
}
