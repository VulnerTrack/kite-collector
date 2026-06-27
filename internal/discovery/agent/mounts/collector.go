package mounts

import (
	"context"
	"fmt"
	"log/slog"
	"os"
)

// fileCollector reads /etc/fstab and /proc/self/mountinfo. Both feeds
// are recorded so the audit pipeline can spot drift between declared
// (boot-time) and live (runtime) configuration.
type fileCollector struct {
	readFile      func(string) ([]byte, error)
	fstab         string
	procMountinfo string
	procMounts    string
}

// NewCollector returns the default mount file walker.
func NewCollector() Collector {
	return &fileCollector{
		fstab:         "/etc/fstab",
		procMountinfo: "/proc/self/mountinfo",
		procMounts:    "/proc/mounts",
		readFile:      func(p string) ([]byte, error) { return os.ReadFile(p) }, //#nosec G304 -- fixed system paths
	}
}

func (c *fileCollector) Name() string { return "mounts-files" }

func (c *fileCollector) Collect(ctx context.Context) ([]Mount, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context cancelled: %w", err)
	}
	var out []Mount

	// /etc/fstab — declared mounts.
	if data, err := c.readFile(c.fstab); err == nil {
		out = append(out, ParseFstab(data, c.fstab)...)
	} else {
		slog.Debug("mounts: fstab unreadable",
			"path", c.fstab, "error", err)
	}

	// /proc/self/mountinfo — preferred live source; falls back to
	// /proc/mounts on older kernels.
	live, livePath := c.readMountinfo()
	if live != nil {
		out = append(out, ParseProcMounts(live, livePath)...)
	}

	if len(out) > MaxMounts {
		out = out[:MaxMounts]
	}
	SortMounts(out)
	return out, nil
}

// readMountinfo prefers /proc/self/mountinfo and falls back to
// /proc/mounts. Returns (nil, "") when neither is readable.
func (c *fileCollector) readMountinfo() ([]byte, string) {
	if data, err := c.readFile(c.procMountinfo); err == nil {
		return data, c.procMountinfo
	}
	if data, err := c.readFile(c.procMounts); err == nil {
		return data, c.procMounts
	}
	return nil, ""
}
