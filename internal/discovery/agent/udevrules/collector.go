package udevrules

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// fileCollector walks the four well-known udev rule directories.
// They're listed in priority order so the audit pipeline can see
// which file ultimately defined a behaviour (admin > runtime > vendor).
type fileCollector struct {
	readFile   func(string) ([]byte, error)
	readDir    func(string) ([]os.DirEntry, error)
	adminDir   string
	runtimeDir string
	vendorDirs []string
}

// NewCollector returns the default udev rule walker.
func NewCollector() Collector {
	return &fileCollector{
		adminDir:   "/etc/udev/rules.d",
		runtimeDir: "/run/udev/rules.d",
		vendorDirs: []string{
			"/usr/lib/udev/rules.d",
			"/lib/udev/rules.d",
		},
		readFile: func(p string) ([]byte, error) { return os.ReadFile(p) }, //#nosec G304 -- fixed system paths
		readDir:  func(p string) ([]os.DirEntry, error) { return os.ReadDir(p) },
	}
}

func (c *fileCollector) Name() string { return "udev-rules-files" }

func (c *fileCollector) Collect(ctx context.Context) ([]Rule, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context cancelled: %w", err)
	}
	var out []Rule

	for _, p := range c.lexicalFiles(c.adminDir, ".rules") {
		if err := ctx.Err(); err != nil {
			return out, fmt.Errorf("context cancelled mid-walk: %w", err)
		}
		data, err := c.readFile(p)
		if err != nil {
			continue
		}
		out = append(out, Parse(data, p, ScopeAdmin)...)
		if len(out) >= MaxRules {
			break
		}
	}

	for _, p := range c.lexicalFiles(c.runtimeDir, ".rules") {
		data, err := c.readFile(p)
		if err != nil {
			continue
		}
		out = append(out, Parse(data, p, ScopeRuntime)...)
		if len(out) >= MaxRules {
			break
		}
	}

	for _, dir := range c.vendorDirs {
		for _, p := range c.lexicalFiles(dir, ".rules") {
			data, err := c.readFile(p)
			if err != nil {
				continue
			}
			out = append(out, Parse(data, p, ScopeVendor)...)
			if len(out) >= MaxRules {
				break
			}
		}
		if len(out) >= MaxRules {
			break
		}
	}

	if len(out) > MaxRules {
		out = out[:MaxRules]
	}
	SortRules(out)
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
			strings.HasSuffix(name, ".dpkg-new") ||
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
