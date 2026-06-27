package macpolicies

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// fileCollector reads /etc/selinux/config, every profile under
// /etc/apparmor.d/ (recursively, depth 2 — abstractions live in
// /etc/apparmor.d/abstractions and tunables live in /etc/apparmor.d/
// tunables), and /sys/kernel/security/lsm.
type fileCollector struct {
	readFile    func(string) ([]byte, error)
	readDir     func(string) ([]os.DirEntry, error)
	selinuxConf string
	apparmorDir string
	lsmListPath string
}

// NewCollector returns the default MAC file walker.
func NewCollector() Collector {
	return &fileCollector{
		selinuxConf: "/etc/selinux/config",
		apparmorDir: "/etc/apparmor.d",
		lsmListPath: "/sys/kernel/security/lsm",
		readFile:    func(p string) ([]byte, error) { return os.ReadFile(p) }, //#nosec G304 -- fixed system paths
		readDir:     func(p string) ([]os.DirEntry, error) { return os.ReadDir(p) },
	}
}

func (c *fileCollector) Name() string { return "macpolicies-files" }

func (c *fileCollector) Collect(ctx context.Context) ([]Policy, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context cancelled: %w", err)
	}
	var out []Policy

	// SELinux.
	if data, err := c.readFile(c.selinuxConf); err == nil {
		out = append(out, ParseSELinuxConfig(data, c.selinuxConf)...)
	} else {
		slog.Debug("macpolicies: selinux config unreadable",
			"path", c.selinuxConf, "error", err)
	}

	// AppArmor profiles. We only walk the top level; sub-directories
	// abstractions/, tunables/, local/ contain shared snippets rather
	// than complete profiles.
	for _, p := range c.topLevelFiles(c.apparmorDir) {
		if err := ctx.Err(); err != nil {
			return out, fmt.Errorf("context cancelled mid-walk: %w", err)
		}
		data, err := c.readFile(p)
		if err != nil {
			continue
		}
		out = append(out, ParseAppArmorProfile(data, p)...)
		if len(out) >= MaxPolicies {
			break
		}
	}

	// Loaded LSM list.
	if data, err := c.readFile(c.lsmListPath); err == nil {
		out = append(out, ParseLSMList(data, c.lsmListPath)...)
	}

	if len(out) > MaxPolicies {
		out = out[:MaxPolicies]
	}
	SortPolicies(out)
	return out, nil
}

// topLevelFiles returns the lexically-sorted absolute paths of regular
// files (not subdirs) directly under `dir`. AppArmor's abstractions/,
// tunables/, local/ subdirs hold shared snippets and are intentionally
// skipped — they aren't complete profiles.
func (c *fileCollector) topLevelFiles(dir string) []string {
	entries, err := c.readDir(dir)
	if err != nil {
		return nil
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		// Skip dpkg-old / .bak / swap files.
		name := e.Name()
		if strings.HasSuffix(name, ".bak") ||
			strings.HasSuffix(name, ".dpkg-old") ||
			strings.HasSuffix(name, ".dpkg-new") ||
			strings.HasSuffix(name, ".dpkg-dist") ||
			strings.HasSuffix(name, ".rpmnew") ||
			strings.HasSuffix(name, ".rpmsave") ||
			strings.HasSuffix(name, ".swp") ||
			strings.HasSuffix(name, "~") ||
			strings.HasPrefix(name, ".") {
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
