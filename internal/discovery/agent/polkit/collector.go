package polkit

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// fileCollector walks the three polkit policy locations: action-policy
// XML under /usr/share/polkit-1/actions/, vendor JS rules under
// /usr/share/polkit-1/rules.d/, and local JS overrides under
// /etc/polkit-1/rules.d/.
type fileCollector struct {
	readFile       func(string) ([]byte, error)
	readDir        func(string) ([]os.DirEntry, error)
	actionsDir     string
	vendorRulesDir string
	localRulesDir  string
}

// NewCollector returns the default polkit file walker.
func NewCollector() Collector {
	return &fileCollector{
		actionsDir:     "/usr/share/polkit-1/actions",
		vendorRulesDir: "/usr/share/polkit-1/rules.d",
		localRulesDir:  "/etc/polkit-1/rules.d",
		readFile:       func(p string) ([]byte, error) { return os.ReadFile(p) }, //#nosec G304 -- fixed system paths
		readDir:        func(p string) ([]os.DirEntry, error) { return os.ReadDir(p) },
	}
}

func (c *fileCollector) Name() string { return "polkit-files" }

func (c *fileCollector) Collect(ctx context.Context) ([]Rule, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context cancelled: %w", err)
	}
	var out []Rule

	// Action-policy XML.
	for _, p := range c.lexicalFiles(c.actionsDir, ".policy") {
		if err := ctx.Err(); err != nil {
			return out, fmt.Errorf("context cancelled mid-walk: %w", err)
		}
		data, err := c.readFile(p)
		if err != nil {
			continue
		}
		out = append(out, ParseActionPolicy(data, p)...)
		if len(out) >= MaxRules {
			break
		}
	}

	// Local JS rules (override priority — read first for stable diff).
	for _, p := range c.lexicalFiles(c.localRulesDir, ".rules") {
		data, err := c.readFile(p)
		if err != nil {
			continue
		}
		out = append(out, ParseJSRules(data, p, SourceLocalRules)...)
		if len(out) >= MaxRules {
			break
		}
	}

	// Vendor JS rules.
	for _, p := range c.lexicalFiles(c.vendorRulesDir, ".rules") {
		data, err := c.readFile(p)
		if err != nil {
			continue
		}
		out = append(out, ParseJSRules(data, p, SourceVendorRules)...)
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
// in `dir` ending with `suffix`. Backup/swap variants are filtered out.
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
			strings.HasSuffix(name, ".rpmsave") {
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
