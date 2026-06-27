package kernelcmdline

import (
	"context"
	"fmt"
	"os"
)

// fileCollector reads /proc/cmdline (live) and /etc/default/grub
// (configured). The audit pipeline correlates the two via the
// (key, value) join key to surface boot-time drift.
type fileCollector struct {
	readFile    func(string) ([]byte, error)
	procCmdline string
	grubDefault string
}

// NewCollector returns the default kernel-cmdline file walker.
func NewCollector() Collector {
	return &fileCollector{
		procCmdline: "/proc/cmdline",
		grubDefault: "/etc/default/grub",
		readFile:    func(p string) ([]byte, error) { return os.ReadFile(p) }, //#nosec G304 -- fixed system paths
	}
}

func (c *fileCollector) Name() string { return "kernel-cmdline-files" }

func (c *fileCollector) Collect(ctx context.Context) ([]Param, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context cancelled: %w", err)
	}
	var out []Param

	if data, err := c.readFile(c.procCmdline); err == nil {
		out = append(out, ParseProcCmdline(data, c.procCmdline)...)
	}
	if data, err := c.readFile(c.grubDefault); err == nil {
		out = append(out, ParseGrubDefault(data, c.grubDefault)...)
	}

	// Annotate drift: any (key, value) from proc-cmdline that is NOT
	// present in grub-default with the same value means the running
	// kernel saw a parameter the bootloader config doesn't declare.
	// That's either a kernel cmdline overlay (initramfs, dracut) or
	// a manually-edited boot.
	if len(out) > 0 {
		annotateDrift(out)
	}

	if len(out) > MaxParams {
		out = out[:MaxParams]
	}
	SortParams(out)
	return out, nil
}

// annotateDrift sets IsDriftFromDisk=true on every proc-cmdline row
// whose (key, value) pair has no matching grub-default row.
func annotateDrift(params []Param) {
	configured := make(map[string]string, len(params))
	for _, p := range params {
		if p.Source == SourceGrubDefault {
			configured[p.Key] = p.Value
		}
	}
	for i := range params {
		if params[i].Source != SourceProcCmdline {
			continue
		}
		want, ok := configured[params[i].Key]
		if !ok {
			// The bootloader didn't declare this key at all. We only
			// flag drift when /etc/default/grub IS present (avoid
			// false positives on systems using other bootloaders).
			if len(configured) > 0 {
				params[i].IsDriftFromDisk = true
			}
			continue
		}
		if want != params[i].Value {
			params[i].IsDriftFromDisk = true
		}
	}
}
