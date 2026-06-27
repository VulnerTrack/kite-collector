package sudoers

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
)

// fileCollector reads /etc/sudoers and every file under /etc/sudoers.d/
// (lexically sorted, matching how sudo itself orders includes). On
// macOS the path is the same. Windows has no sudoers — the collector
// returns empty there.
type fileCollector struct {
	readFile  func(string) ([]byte, error)
	readDir   func(string) ([]os.DirEntry, error)
	mainFile  string
	dropInDir string
}

// NewCollector returns the default sudoers file walker.
func NewCollector() Collector {
	return &fileCollector{
		mainFile:  "/etc/sudoers",
		dropInDir: "/etc/sudoers.d",
		readFile:  func(p string) ([]byte, error) { return os.ReadFile(p) }, //#nosec G304 -- fixed system paths
		readDir:   func(p string) ([]os.DirEntry, error) { return os.ReadDir(p) },
	}
}

func (c *fileCollector) Name() string { return "sudoers-files" }

func (c *fileCollector) Collect(ctx context.Context) ([]Entry, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context cancelled: %w", err)
	}
	var out []Entry

	// Main /etc/sudoers.
	if data, err := c.readFile(c.mainFile); err == nil {
		out = append(out, Parse(data, c.mainFile)...)
	} else {
		slog.Debug("sudoers: main file unreadable",
			"path", c.mainFile, "error", err)
	}

	// Drop-in directory, processed in lexical order to match sudo's own
	// include sequence (also makes diff output stable across scans).
	entries, err := c.readDir(c.dropInDir)
	if err == nil {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			names = append(names, e.Name())
		}
		sort.Strings(names)
		for _, name := range names {
			// sudo itself skips backup files (ending in `~`) and files
			// containing `.`. We mirror those rules to avoid recording
			// vim swap files as "sudoers fragments".
			if !sudoIncludesFile(name) {
				continue
			}
			path := filepath.Join(c.dropInDir, name)
			data, ferr := c.readFile(path)
			if ferr != nil {
				continue
			}
			out = append(out, Parse(data, path)...)
			if len(out) >= MaxEntries {
				break
			}
		}
	}

	if len(out) > MaxEntries {
		out = out[:MaxEntries]
	}
	SortEntries(out)
	return out, nil
}

// sudoIncludesFile mirrors sudo's own include rules. Per sudoers(5):
//   - Files containing `.` or ending in `~` are skipped.
//   - Hidden files (`.foo`) are skipped (caught by the dot rule).
func sudoIncludesFile(name string) bool {
	if name == "" {
		return false
	}
	if name[len(name)-1] == '~' {
		return false
	}
	for i := 0; i < len(name); i++ {
		if name[i] == '.' {
			return false
		}
	}
	return true
}
