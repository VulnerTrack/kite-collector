package hostmetrics

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	gopscpu "github.com/shirou/gopsutil/v4/cpu"
	gopsdisk "github.com/shirou/gopsutil/v4/disk"
	gopshost "github.com/shirou/gopsutil/v4/host"
	gopsload "github.com/shirou/gopsutil/v4/load"
	gopsmem "github.com/shirou/gopsutil/v4/mem"
	gopsnet "github.com/shirou/gopsutil/v4/net"
)

// gopsutilSource is the production adapter over gopsutil/v4's package-level
// functions. A single struct works on every supported OS because gopsutil
// handles the per-OS specifics internally — the same arrangement
// internal/discovery/agent/processes and .../listeners already use.
//
// Every subpackage imported here (cpu, mem, disk, host, load, net) performs
// unprivileged, read-only system-stat reads. No new capability, setuid, or
// elevated permission is requested relative to the inventory collectors
// already shipping (RFC-0157 §6.1, Elevation of Privilege).
type gopsutilSource struct{}

// Compile-time interface check.
var _ Source = gopsutilSource{}

// CPUPercent returns total CPU utilisation as a percentage.
//
// The zero interval is load-bearing: it makes gopsutil diff against the CPU
// times captured on the previous call instead of sleeping. A blocking
// sample interval here would stall the agent's emission ticker for the
// length of the interval on every tick. The very first call after start-up
// therefore reports utilisation since boot, which is correct-but-smoothed
// rather than wrong.
func (gopsutilSource) CPUPercent(ctx context.Context) (float64, error) {
	percents, err := gopscpu.PercentWithContext(ctx, 0, false)
	if err != nil {
		return 0, fmt.Errorf("gopsutil cpu percent: %w", err)
	}
	if len(percents) == 0 {
		return 0, errors.New("gopsutil cpu percent: no reading returned")
	}
	return percents[0], nil
}

func (gopsutilSource) Memory(ctx context.Context) (MemStat, error) {
	vm, err := gopsmem.VirtualMemoryWithContext(ctx)
	if err != nil {
		return MemStat{}, fmt.Errorf("gopsutil virtual memory: %w", err)
	}
	return MemStat{Total: vm.Total, Used: vm.Used, UsedPercent: vm.UsedPercent}, nil
}

// Partitions lists mounted filesystems. `all=false` already excludes most
// kernel pseudo-filesystems on Linux; selectPartitions filters the rest.
func (gopsutilSource) Partitions(ctx context.Context) ([]Partition, error) {
	stats, err := gopsdisk.PartitionsWithContext(ctx, false)
	if err != nil {
		return nil, fmt.Errorf("gopsutil disk partitions: %w", err)
	}
	out := make([]Partition, 0, len(stats))
	for _, s := range stats {
		out = append(out, Partition{
			Device:     s.Device,
			Mountpoint: s.Mountpoint,
			FSType:     s.Fstype,
		})
	}
	return out, nil
}

func (gopsutilSource) DiskUsage(ctx context.Context, mountpoint string) (DiskStat, error) {
	usage, err := gopsdisk.UsageWithContext(ctx, mountpoint)
	if err != nil {
		return DiskStat{}, fmt.Errorf("gopsutil disk usage: %w", err)
	}
	return DiskStat{
		Total:       usage.Total,
		Used:        usage.Used,
		UsedPercent: usage.UsedPercent,
	}, nil
}

func (gopsutilSource) NetIO(ctx context.Context) ([]NetIO, error) {
	stats, err := gopsnet.IOCountersWithContext(ctx, true)
	if err != nil {
		return nil, fmt.Errorf("gopsutil net io counters: %w", err)
	}
	out := make([]NetIO, 0, len(stats))
	for _, s := range stats {
		out = append(out, NetIO{
			Name:      s.Name,
			BytesRecv: s.BytesRecv,
			BytesSent: s.BytesSent,
			ErrIn:     s.Errin,
			ErrOut:    s.Errout,
		})
	}
	return out, nil
}

func (gopsutilSource) Uptime(ctx context.Context) (time.Duration, error) {
	seconds, err := gopshost.UptimeWithContext(ctx)
	if err != nil {
		return 0, fmt.Errorf("gopsutil host uptime: %w", err)
	}
	// Duration counts nanoseconds in an int64, so scaling by time.Second
	// overflows above ~292 years. gopsutil reports uint64 and a wrapped or
	// garbage clock reading lands well past that; treat it as a failed
	// reading rather than emitting a negative uptime.
	const maxUptimeSeconds = uint64(math.MaxInt64 / int64(time.Second))
	if seconds > maxUptimeSeconds {
		return 0, fmt.Errorf("implausible host uptime: %d seconds", seconds)
	}
	return time.Duration(seconds) * time.Second, nil
}

// LoadAverage is the one source with no meaningful reading on some
// platforms. The caller records the failure and keeps the rest of the
// snapshot (R3).
func (gopsutilSource) LoadAverage(ctx context.Context) (LoadStat, error) {
	avg, err := gopsload.AvgWithContext(ctx)
	if err != nil {
		return LoadStat{}, fmt.Errorf("gopsutil load average: %w", err)
	}
	return LoadStat{Load1: avg.Load1, Load5: avg.Load5, Load15: avg.Load15}, nil
}
