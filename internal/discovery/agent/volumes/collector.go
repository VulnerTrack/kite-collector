package volumes

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	gops "github.com/shirou/gopsutil/v4/disk"
)

// diskSource is the test seam: gopsutil's `disk.Partitions` + `disk.Usage`.
// Production uses the real adapter; tests inject a synthetic source.
type diskSource interface {
	Partitions(ctx context.Context, all bool) ([]Partition, error)
	Usage(ctx context.Context, mount string) (Usage, error)
}

// Partition is the projected subset of gopsutil's PartitionStat we use.
// Decoupling lets tests construct fixtures without importing gopsutil.
type Partition struct {
	Device     string
	MountPoint string
	Filesystem string
	Opts       []string
}

// Usage is the projected subset of gopsutil's UsageStat we use.
type Usage struct {
	Total       uint64
	Used        uint64
	InodesTotal uint64
	InodesUsed  uint64
}

// gopsutilCollector wraps gopsutil/v4/disk + a per-OS EncryptionProbe.
type gopsutilCollector struct {
	src   diskSource
	probe EncryptionProbe
}

// NewCollector returns a production Collector backed by gopsutil/v4 and
// the per-OS EncryptionProbe registered for the current build (LUKS on
// linux, BitLocker on windows, FileVault on darwin, noopProbe elsewhere).
func NewCollector() Collector {
	return &gopsutilCollector{src: realSource{}, probe: newProbe()}
}

func (gopsutilCollector) Name() string { return "gopsutil-disk" }

// Collect enumerates mounted volumes (excluding pseudo filesystems by
// default) and capacities. Per-volume errors are logged at DEBUG and the
// row is emitted with whatever fields succeeded — gopsutil reports
// permission denied for some mount points on macOS (e.g. /private/var)
// even as root, which is expected.
func (c *gopsutilCollector) Collect(ctx context.Context) ([]Volume, error) {
	now := time.Now().UTC()

	parts, err := c.src.Partitions(ctx, false) // all=false → skip pseudo fs
	if err != nil {
		return nil, fmt.Errorf("list partitions: %w", err)
	}
	if len(parts) > MaxVolumes {
		slog.Warn("volumes: capping inventory at MaxVolumes",
			"observed", len(parts), "cap", MaxVolumes)
		parts = parts[:MaxVolumes]
	}

	out := make([]Volume, 0, len(parts))
	for _, p := range parts {
		if err := ctx.Err(); err != nil {
			return out, fmt.Errorf("context cancelled mid-collect: %w", err)
		}
		out = append(out, c.snapshot(ctx, p, now))
	}
	SortVolumes(out)
	return out, nil
}

// snapshot builds a Volume from one Partition. Usage stats are best-effort.
func (c *gopsutilCollector) snapshot(ctx context.Context, p Partition, now time.Time) Volume {
	v := Volume{
		MountPoint:      p.MountPoint,
		Device:          p.Device,
		Filesystem:      p.Filesystem,
		MountOpts:       strings.Join(p.Opts, ","),
		ReadOnly:        hasOpt(p.Opts, "ro"),
		Removable:       IsRemovableMount(p.MountPoint),
		Bootable:        IsBootable(p.MountPoint, p.Filesystem),
		Encryption:      EncUnknown,
		EncryptionState: EncStateUnknown,
		LastSeenAt:      now,
		CollectedAt:     now,
	}
	if u, err := c.src.Usage(ctx, p.MountPoint); err == nil {
		v.SizeBytes = u.Total
		v.UsedBytes = u.Used
		v.InodesTotal = u.InodesTotal
		v.InodesUsed = u.InodesUsed
	}
	if c.probe != nil {
		enc, state := c.probe.Probe(ctx, p.MountPoint, p.Device, p.Filesystem)
		v.Encryption = enc
		v.EncryptionState = state
	}
	return v
}

func hasOpt(opts []string, want string) bool {
	for _, o := range opts {
		if o == want {
			return true
		}
	}
	return false
}

// realSource is the production adapter wrapping gopsutil's package-level
// API into the diskSource interface.
type realSource struct{}

func (realSource) Partitions(ctx context.Context, all bool) ([]Partition, error) {
	ps, err := gops.PartitionsWithContext(ctx, all)
	if err != nil {
		return nil, fmt.Errorf("gopsutil partitions: %w", err)
	}
	out := make([]Partition, 0, len(ps))
	for _, p := range ps {
		out = append(out, Partition{
			Device:     p.Device,
			MountPoint: p.Mountpoint,
			Filesystem: p.Fstype,
			Opts:       p.Opts,
		})
	}
	return out, nil
}

func (realSource) Usage(ctx context.Context, mount string) (Usage, error) {
	u, err := gops.UsageWithContext(ctx, mount)
	if err != nil {
		return Usage{}, fmt.Errorf("gopsutil usage: %w", err)
	}
	return Usage{
		Total:       u.Total,
		Used:        u.Used,
		InodesTotal: u.InodesTotal,
		InodesUsed:  u.InodesUsed,
	}, nil
}
