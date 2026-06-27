package sysctl

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// fileCollector reads every sysctl config the sysctl(8) loader
// consumes: /etc/sysctl.conf, /etc/sysctl.d/*.conf, /usr/lib/sysctl.d/*,
// /run/sysctl.d/*. Drop-in directories are walked in lexical order to
// mirror sysctl --system. The /proc/sys live read is optional and
// gated by enableProcSys.
type fileCollector struct {
	readFile      func(string) ([]byte, error)
	readDir       func(string) ([]os.DirEntry, error)
	sysctlConf    string
	procSys       string
	dropInDirs    []dropInSource
	enableProcSys bool
}

// dropInSource pairs a directory with its Source enum value so we
// can pass the right `source` field into Parse per location.
type dropInSource struct {
	dir    string
	source Source
}

// NewCollector returns the default file walker. The /proc/sys live
// read is disabled by default to keep the collector fast on hosts
// with thousands of net.* interfaces; enable via NewCollectorWith.
func NewCollector() Collector {
	return &fileCollector{
		sysctlConf: "/etc/sysctl.conf",
		dropInDirs: []dropInSource{
			{"/etc/sysctl.d", SourceEtcSysctlD},
			{"/usr/lib/sysctl.d", SourceUsrLibSysctlD},
			{"/run/sysctl.d", SourceRunSysctlD},
		},
		procSys:       "/proc/sys",
		enableProcSys: false,
		readFile:      func(p string) ([]byte, error) { return os.ReadFile(p) }, //#nosec G304 -- fixed system paths
		readDir:       func(p string) ([]os.DirEntry, error) { return os.ReadDir(p) },
	}
}

// NewCollectorWith returns a file walker with the /proc/sys live read
// toggled. Useful for audit pipelines that want the drift comparison.
func NewCollectorWith(enableProcSys bool) Collector {
	c, _ := NewCollector().(*fileCollector)
	c.enableProcSys = enableProcSys
	return c
}

func (c *fileCollector) Name() string { return "sysctl-files" }

func (c *fileCollector) Collect(ctx context.Context) ([]Setting, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context cancelled: %w", err)
	}
	var out []Setting

	if data, err := c.readFile(c.sysctlConf); err == nil {
		out = append(out, Parse(data, SourceEtcSysctlConf, c.sysctlConf)...)
	}
	for _, src := range c.dropInDirs {
		for _, p := range c.lexicalFiles(src.dir, ".conf") {
			if err := ctx.Err(); err != nil {
				return out, fmt.Errorf("context cancelled mid-walk: %w", err)
			}
			data, err := c.readFile(p)
			if err != nil {
				continue
			}
			out = append(out, Parse(data, src.source, p)...)
			if len(out) >= MaxSettings {
				break
			}
		}
	}

	// Optionally enrich with live /proc/sys values + drift annotations.
	if c.enableProcSys {
		out = c.enrichWithProcSys(ctx, out)
	}

	if len(out) > MaxSettings {
		out = out[:MaxSettings]
	}
	SortSettings(out)
	return out, nil
}

// enrichWithProcSys overlays the live kernel values onto the configured
// settings. The strategy:
//
//  1. For every configured key, read /proc/sys/<path>; if the value
//     differs from CurrentValue, set IsDriftFromDisk=1 on the existing
//     row (the configured row keeps its value; the audit query joins
//     against the proc-sys row when present).
//  2. For every key in the security baseline that ISN'T already
//     configured, read /proc/sys/<path> and emit a proc-sys-sourced
//     Setting so the row exists for the audit join.
//
// We don't walk all of /proc/sys/* — that's thousands of nodes most of
// which aren't security-relevant. The baseline-coverage policy keeps
// the row count bounded.
func (c *fileCollector) enrichWithProcSys(ctx context.Context, in []Setting) []Setting {
	out := in
	seen := make(map[string]bool, len(in))
	for i := range out {
		if ctx.Err() != nil {
			return out
		}
		key := NormalizeKey(out[i].Key)
		seen[key] = true
		live, ok := c.readProcSys(key)
		if !ok {
			continue
		}
		if strings.TrimSpace(live) != strings.TrimSpace(out[i].CurrentValue) {
			out[i].IsDriftFromDisk = true
		}
	}
	// Cover every baseline key not yet present.
	for key := range SecurityBaseline() {
		if seen[key] {
			continue
		}
		if ctx.Err() != nil {
			return out
		}
		live, ok := c.readProcSys(key)
		if !ok {
			continue
		}
		s := Setting{
			Source:       SourceProcSys,
			Key:          key,
			CurrentValue: strings.TrimSpace(live),
		}
		AnnotateSecurity(&s)
		out = append(out, s)
		if len(out) >= MaxSettings {
			break
		}
	}
	return out
}

// readProcSys reads /proc/sys/<dotted-key-as-slashes>.
func (c *fileCollector) readProcSys(key string) (string, bool) {
	path := filepath.Join(c.procSys, strings.ReplaceAll(key, ".", "/"))
	data, err := c.readFile(path)
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(data)), true
}

// lexicalFiles returns absolute paths of files in `dir` ending in
// `suffix`, lexically sorted to mirror sysctl --system order.
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
