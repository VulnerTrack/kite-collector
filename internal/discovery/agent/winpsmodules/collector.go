package winpsmodules

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// DefaultModulePathRoots is the canonical set of PSModulePath
// directories on Windows. The collector walks each root
// recursively and parses every `*.psd1` file it finds.
func DefaultModulePathRoots() []string {
	roots := []string{
		`C:\Program Files\PowerShell\7\Modules`,
		`C:\Program Files\PowerShell\Modules`,
		`C:\Program Files\WindowsPowerShell\Modules`,
		`C:\Program Files (x86)\WindowsPowerShell\Modules`,
		`C:\Windows\System32\WindowsPowerShell\v1.0\Modules`,
		`C:\Windows\SysWOW64\WindowsPowerShell\v1.0\Modules`,
	}
	// Per-user paths under %USERPROFILE%.
	if up := os.Getenv("USERPROFILE"); up != "" {
		roots = append(roots,
			filepath.Join(up, "Documents", "PowerShell", "Modules"),
			filepath.Join(up, "Documents", "WindowsPowerShell", "Modules"),
		)
	}
	return roots
}

// fileCollector walks PSModulePath roots from a configurable list.
// Test seam swaps readFile / readDir.
type fileCollector struct {
	readFile func(string) ([]byte, error)
	readDir  func(string) ([]os.DirEntry, error)
	roots    []string
}

// NewCollector returns a Collector wired to the canonical
// PSModulePath roots. Missing roots are silently skipped.
func NewCollector() Collector {
	return &fileCollector{
		roots:    DefaultModulePathRoots(),
		readFile: os.ReadFile,
		readDir:  os.ReadDir,
	}
}

func (c *fileCollector) Name() string { return "winpsmodules" }

func (c *fileCollector) Collect(_ context.Context) ([]Module, error) {
	out := make([]Module, 0, 256)
	var walk func(path string) error
	walk = func(path string) error {
		entries, err := c.readDir(path)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		sort.Slice(entries, func(i, j int) bool {
			return entries[i].Name() < entries[j].Name()
		})
		for _, e := range entries {
			name := e.Name()
			if strings.HasPrefix(name, ".") {
				continue
			}
			full := filepath.Join(path, name)
			if e.IsDir() {
				if err := walk(full); err != nil {
					return err
				}
				if len(out) >= MaxModules {
					return nil
				}
				continue
			}
			if !strings.EqualFold(filepath.Ext(name), ".psd1") {
				continue
			}
			body, err := c.readFile(full)
			if err != nil {
				continue
			}
			mod, err := ParsePSD1(body, full)
			if err != nil {
				continue
			}
			out = append(out, mod)
			if len(out) >= MaxModules {
				return nil
			}
		}
		return nil
	}
	for _, root := range c.roots {
		if err := walk(root); err != nil {
			return nil, err
		}
		if len(out) >= MaxModules {
			break
		}
	}
	SortModules(out)
	return out, nil
}
