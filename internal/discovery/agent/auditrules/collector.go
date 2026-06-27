package auditrules

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// fileCollector reads /etc/audit/audit.rules and every drop-in under
// /etc/audit/rules.d/. The drop-in directory is processed in lexical
// order — the same order augenrules(8) folds them when generating
// the final audit.rules. macOS and Windows have no equivalent rule
// language; the collector returns empty there.
type fileCollector struct {
	readFile func(string) ([]byte, error)
	readDir  func(string) ([]os.DirEntry, error)
	mainFile string
	rulesDir string
}

// NewCollector returns the default audit-rules file walker.
func NewCollector() Collector {
	return &fileCollector{
		mainFile: "/etc/audit/audit.rules",
		rulesDir: "/etc/audit/rules.d",
		readFile: func(p string) ([]byte, error) { return os.ReadFile(p) }, //#nosec G304 -- fixed system paths
		readDir:  func(p string) ([]os.DirEntry, error) { return os.ReadDir(p) },
	}
}

func (c *fileCollector) Name() string { return "auditrules-files" }

func (c *fileCollector) Collect(ctx context.Context) ([]Rule, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context cancelled: %w", err)
	}
	var out []Rule

	// Main audit.rules (compiled output of augenrules).
	if data, err := c.readFile(c.mainFile); err == nil {
		out = append(out, Parse(data, c.mainFile)...)
	} else {
		slog.Debug("auditrules: main file unreadable",
			"path", c.mainFile, "error", err)
	}

	// rules.d drop-ins, in lexical order to mirror augenrules.
	for _, p := range c.lexicalFiles(c.rulesDir, ".rules") {
		if err := ctx.Err(); err != nil {
			return out, fmt.Errorf("context cancelled mid-walk: %w", err)
		}
		data, err := c.readFile(p)
		if err != nil {
			continue
		}
		out = append(out, Parse(data, p)...)
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

// lexicalFiles returns the absolute paths of files in `dir` whose
// name ends with `suffix`, lexically sorted.
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
		if !strings.HasSuffix(e.Name(), suffix) {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)
	out := make([]string, 0, len(names))
	for _, n := range names {
		out = append(out, filepath.Join(dir, n))
	}
	return out
}
