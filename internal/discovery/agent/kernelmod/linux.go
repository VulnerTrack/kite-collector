//go:build linux

package kernelmod

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// linuxCollector is the production wiring for Linux: read
// /proc/modules then enrich each row with whatever /sys/module
// exposes (file path, version, signer DN from .modinfo, current
// taint letters).
type linuxCollector struct {
	readFile    func(string) ([]byte, error)
	readDir     func(string) ([]os.DirEntry, error)
	readLink    func(string) (string, error)
	procModules string
	sysModule   string
}

// NewCollector returns the Linux kernel-module walker.
func NewCollector() Collector {
	return &linuxCollector{
		procModules: "/proc/modules",
		sysModule:   "/sys/module",
		readFile:    func(p string) ([]byte, error) { return os.ReadFile(p) }, //#nosec G304 -- fixed system paths
		readDir:     func(p string) ([]os.DirEntry, error) { return os.ReadDir(p) },
		readLink:    func(p string) (string, error) { return os.Readlink(p) },
	}
}

func (c *linuxCollector) Name() string { return "kernelmod-linux" }

func (c *linuxCollector) Collect(ctx context.Context) ([]Module, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context cancelled: %w", err)
	}
	raw, err := c.readFile(c.procModules)
	if err != nil {
		// On some hardened distros /proc/modules is non-readable
		// for non-root. Log + return empty rather than fail the
		// whole agent scan.
		slog.Debug("kernelmod: /proc/modules unreadable",
			"path", c.procModules, "error", err)
		return nil, nil //nolint:nilerr // intentional: empty result on unreadable file
	}
	mods := ParseProcModules(raw)

	// Enrich from /sys/module/<name>/.
	sysfs := make(map[string]SysfsExtras, len(mods))
	for i := range mods {
		if err := ctx.Err(); err != nil {
			return mods, fmt.Errorf("context cancelled mid-walk: %w", err)
		}
		sysfs[mods[i].Name] = c.readSysfsExtras(mods[i].Name)
	}
	mods = MergeSysfs(mods, sysfs)

	SortModules(mods)
	return mods, nil
}

// readSysfsExtras gathers every per-module fact /sys/module/<name>/
// can give us. None of these reads are fatal — kernel builds vary,
// some files are root-only, and at least one (sections/) varies by
// kallsyms config. We collect what we can and move on.
func (c *linuxCollector) readSysfsExtras(name string) SysfsExtras {
	out := SysfsExtras{}
	base := filepath.Join(c.sysModule, name)

	// Version: /sys/module/<name>/version, present when CONFIG_MODVERSIONS=y.
	if v, err := c.readFile(filepath.Join(base, "version")); err == nil {
		out.Version = strings.TrimSpace(string(v))
	}

	// Taint flags: /sys/module/<name>/taint — single letters or empty.
	if t, err := c.readFile(filepath.Join(base, "taint")); err == nil {
		out.Taints = strings.TrimSpace(string(t))
	}

	// File path resolution: /sys/module/<name>/srcversion is not the
	// file path. The file isn't directly linked from sysfs; we resolve
	// it by walking the known module tree.
	out.FilePath = c.resolveModuleFile(name)

	// Signer + signature presence: read /sys/module/<name>/sections/
	// only if file path resolution succeeded.
	if out.FilePath != "" {
		out.SignatureChecked = true
		// We don't currently read the signer DN from .modinfo —
		// that requires PKCS#7 parsing of the trailing signature
		// blob. Leaving out.Signer="" + SignatureChecked=true is
		// the conservative "we looked; nothing trusted" answer,
		// which sets IsUnsigned via the merger.
		//
		// A future iteration can lift the modinfo parser from
		// scripts/sign-file in the kernel source tree.
	}

	return out
}

// resolveModuleFile walks /lib/modules/<release>/ to find the .ko
// matching the module name. This is the canonical Linux convention —
// `modinfo <name>` does the same lookup. We probe just the well-known
// roots; an attacker who loads an out-of-tree module won't have it
// here, which is exactly what flags IsOutOfTree=true.
func (c *linuxCollector) resolveModuleFile(name string) string {
	// Try /sys/module/<name>/srcversion first — when present it
	// signals the module exists at all and helps confirm the name.
	for _, root := range []string{
		"/lib/modules",
		"/usr/lib/modules",
	} {
		path := c.scanModuleRoot(root, name)
		if path != "" {
			return path
		}
	}
	return ""
}

// scanModuleRoot walks /lib/modules looking for <name>.ko or
// <name>.ko.{xz,zst,gz}. Hits depth-3 max (kernel/<subsystem>/<file>)
// so the walk stays bounded.
func (c *linuxCollector) scanModuleRoot(root, name string) string {
	releases, err := c.readDir(root)
	if err != nil {
		return ""
	}
	wantPrefixes := []string{
		name + ".ko",
		strings.ReplaceAll(name, "_", "-") + ".ko",
	}
	for _, rel := range releases {
		if !rel.IsDir() {
			continue
		}
		// Walk /lib/modules/<release>/kernel/ + /extra/ + /updates/.
		for _, sub := range []string{"kernel", "extra", "updates", "weak-updates"} {
			path := c.findInTree(filepath.Join(root, rel.Name(), sub), wantPrefixes)
			if path != "" {
				return path
			}
		}
	}
	return ""
}

// findInTree walks a directory tree looking for a file whose basename
// starts with one of the given prefixes. We cap the recursion at a
// reasonable depth so a sysfs-misuse symlink loop can't run away.
func (c *linuxCollector) findInTree(root string, wantPrefixes []string) string {
	type frame struct {
		path  string
		depth int
	}
	stack := []frame{{root, 0}}
	const maxDepth = 6
	for len(stack) > 0 {
		f := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if f.depth > maxDepth {
			continue
		}
		entries, err := c.readDir(f.path)
		if err != nil {
			continue
		}
		for _, e := range entries {
			full := filepath.Join(f.path, e.Name())
			if e.IsDir() {
				stack = append(stack, frame{full, f.depth + 1})
				continue
			}
			for _, want := range wantPrefixes {
				if strings.HasPrefix(e.Name(), want) {
					return full
				}
			}
		}
	}
	return ""
}
