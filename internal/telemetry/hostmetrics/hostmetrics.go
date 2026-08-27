// Package hostmetrics collects host resource-utilization samples (CPU,
// memory, disk, network, uptime, load average) via gopsutil/v4 and shapes
// them as OpenTelemetry `system.*` semantic-convention instruments
// (RFC-0157 R1).
//
// The `system.*` namespace is deliberate: RFC-0073's `kite.*` instruments
// describe the agent's own work, these describe the host the agent runs on.
// Two different observation subjects must not share a namespace.
//
// Two properties matter more here than completeness:
//
//   - Best effort, never fatal (R3). Every source is probed independently.
//     A failure in one (unsupported platform, container without /proc,
//     restricted permissions) is recorded as a reason string on the
//     Snapshot and leaves the other sources' samples intact. Collect
//     returns a non-nil error only when no source produced a sample at all.
//   - Bounded attribute cardinality (R5). Device and interface names are
//     the only attribute values derived from host state. They are
//     sanitised to a small character set, truncated, filtered against a
//     virtual/pseudo-device denylist, sorted, and capped at MaxDevices per
//     instrument. Mountpoints — and any other filesystem path — never
//     leave this package.
//
// The package holds no OTLP wire types: internal/emitter owns
// serialisation, exactly as it already does for the logs signal.
package hostmetrics

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
)

// Kind distinguishes the two OTLP instrument shapes this package emits.
// No histogram instruments exist in v1 (RFC-0157 §5.2).
type Kind string

const (
	// KindGauge is a point-in-time measurement.
	KindGauge Kind = "gauge"
	// KindSum is a cumulative counter.
	KindSum Kind = "sum"
)

// Instrument names, OTel Semantic Conventions v1.27 `system` metrics group.
// This list is the Go half of the catalog; the Python projection side keeps
// an identical list in workspaces/kite_collector/domain/host_metrics.py.
// The two drifting apart is a soft failure by design (the ingest step logs
// kite_collector.otlp_parser.unknown_metric_definition and skips), never a
// crash.
const (
	MetricCPUUtilization    = "system.cpu.utilization"
	MetricMemoryUsage       = "system.memory.usage"
	MetricMemoryUtilization = "system.memory.utilization"
	MetricDiskUsage         = "system.disk.usage"
	MetricDiskUtilization   = "system.disk.utilization"
	MetricNetworkIO         = "system.network.io"
	MetricNetworkErrors     = "system.network.errors"
	MetricUptime            = "system.uptime"
	MetricLoad1             = "system.cpu.load_average.1m"
	MetricLoad5             = "system.cpu.load_average.5m"
	MetricLoad15            = "system.cpu.load_average.15m"
)

// UCUM units carried on each instrument.
const (
	UnitRatio   = "1"
	UnitBytes   = "By"
	UnitSeconds = "s"
	UnitErrors  = "{error}"
)

// The complete data-point attribute vocabulary (R5). Nothing outside this
// set is ever attached to a sample, and every value is drawn from either a
// fixed literal below or a sanitised device name.
const (
	AttrDevice    = "device"
	AttrDirection = "direction"
	AttrState     = "state"
)

// Fixed attribute values.
const (
	DirectionReceive  = "receive"
	DirectionTransmit = "transmit"
	StateUsed         = "used"
)

// MaxDevices caps how many disks and how many network interfaces a single
// snapshot may describe. Hosts with many virtual interfaces or loopback
// mounts would otherwise inflate the ORDER BY (..., attributes, ...)
// cardinality of otel_metrics_gauge (RFC-0157 §6.1, Denial of Service).
const MaxDevices = 8

// maxDeviceNameLen truncates a sanitised device name. Real device names are
// well under this; anything longer is a sign of a synthetic or hostile name.
const maxDeviceNameLen = 32

// ErrNoSamples is returned by Collect when every source failed. Callers log
// and skip the tick — collection failure is never fatal (R3). The returned
// error wraps the per-source causes, so errors.Is against os.ErrPermission
// or a context error still classifies correctly at the call site.
var ErrNoSamples = errors.New("hostmetrics: no source produced a sample")

// ErrNonFiniteValue marks a reading that arrived as NaN or ±Inf. It reaches
// callers only through Snapshot.Err; the sample itself is dropped.
var ErrNonFiniteValue = errors.New("non-finite value")

// Sample is one measured data point, ready for OTLP serialisation.
type Sample struct {
	// Attributes is nil for instruments with no dimensions (load average,
	// uptime, CPU/memory utilization). Never carries a path, command line,
	// user name, or any other high-sensitivity identifier.
	Attributes map[string]string
	Name       string
	Unit       string
	Kind       Kind
	Value      float64
	// Monotonic is meaningful only when Kind is KindSum.
	Monotonic bool
}

// Snapshot is one collection tick.
type Snapshot struct {
	CollectedAt time.Time
	// Failures records one short reason per source that could not be read.
	// Present so the caller can log a degraded collection without having to
	// treat it as an error.
	Failures []string
	// Unsupported names the sources this platform does not implement at all
	// (gopsutil's "not implemented yet"). Kept apart from Failures because
	// it is a permanent property of the platform rather than a degradation:
	// a caller that warns on every Failures entry would otherwise warn on
	// every tick, forever, about something no operator can act on.
	Unsupported []string
	Samples     []Sample
	// errs retains the wrapped error behind each Failures and Unsupported
	// entry. Failures is a flat []string because that is what a log line
	// wants; errs is what keeps errors.Is working once the snapshot has
	// crossed a package boundary and the strings are all that is left.
	errs []error
}

// Err returns the joined causes behind every failed and unsupported source,
// or nil when every source was readable. It is the errors.Is entry point
// for a degraded snapshot:
//
//	if errors.Is(snap.Err(), os.ErrPermission) { ... }
func (s Snapshot) Err() error { return errors.Join(s.errs...) }

// MemStat is the projected subset of gopsutil's mem.VirtualMemoryStat.
// Decoupling lets tests construct fixtures without importing gopsutil.
type MemStat struct {
	Total       uint64
	Used        uint64
	UsedPercent float64
}

// DiskStat is the projected subset of gopsutil's disk.UsageStat.
type DiskStat struct {
	Total       uint64
	Used        uint64
	UsedPercent float64
}

// Partition is the projected subset of gopsutil's disk.PartitionStat.
type Partition struct {
	Device     string
	Mountpoint string
	FSType     string
}

// NetIO is the projected subset of gopsutil's net.IOCountersStat.
type NetIO struct {
	Name      string
	BytesRecv uint64
	BytesSent uint64
	ErrIn     uint64
	ErrOut    uint64
}

// LoadStat is the projected subset of gopsutil's load.AvgStat.
type LoadStat struct {
	Load1  float64
	Load5  float64
	Load15 float64
}

// Source is the test seam: every OS-touching read the collector performs.
// Production wraps gopsutil/v4 (see source.go); tests inject fixtures.
type Source interface {
	CPUPercent(ctx context.Context) (float64, error)
	Memory(ctx context.Context) (MemStat, error)
	Partitions(ctx context.Context) ([]Partition, error)
	DiskUsage(ctx context.Context, mountpoint string) (DiskStat, error)
	NetIO(ctx context.Context) ([]NetIO, error)
	Uptime(ctx context.Context) (time.Duration, error)
	LoadAverage(ctx context.Context) (LoadStat, error)
}

// Collector turns Source readings into `system.*` samples.
type Collector struct {
	src        Source
	maxDevices int
}

// New returns a production Collector backed by gopsutil/v4.
func New() *Collector {
	return &Collector{src: gopsutilSource{}, maxDevices: MaxDevices}
}

// NewWithSource returns a Collector reading from src. Used by tests and by
// any caller that needs a tighter device cap than MaxDevices.
func NewWithSource(src Source, maxDevices int) *Collector {
	if maxDevices <= 0 {
		maxDevices = MaxDevices
	}
	return &Collector{src: src, maxDevices: maxDevices}
}

// Collect gathers one snapshot using the default gopsutil-backed collector.
// This is the entry point the agent's streaming loop calls.
func Collect(ctx context.Context) (Snapshot, error) {
	return New().Collect(ctx)
}

// Memory returns the current memory statistics from the default gopsutil
// source, without building a full Snapshot. It is the raw MemStat the durable
// memory time series records (Total/Used/UsedPercent), which Snapshot itself
// projects away into gauge samples.
func Memory(ctx context.Context) (MemStat, error) {
	return gopsutilSource{}.Memory(ctx)
}

// Collect probes every source once. Per-source failures are collected into
// Snapshot.Failures rather than aborting; only a total failure (no sample
// from any source) returns ErrNoSamples.
//
// ctx is honoured between sources: a cancelled or expired context stops the
// remaining probes and is returned as the error, wrapping context.Canceled
// or context.DeadlineExceeded, even when earlier sources did produce
// samples. The caller needs that distinction — an agent shutting down and a
// host that stopped answering are the same empty snapshot otherwise.
func (c *Collector) Collect(ctx context.Context) (Snapshot, error) {
	// 11 instruments plus per-device fan-out; a small over-allocation here
	// is cheaper than the regrowth on a host with several disks and NICs.
	snap := Snapshot{
		CollectedAt: time.Now().UTC(),
		Samples:     make([]Sample, 0, 32),
		Failures:    make([]string, 0, 4),
	}

	probes := []func(context.Context, *Snapshot){
		c.collectCPU,
		c.collectMemory,
		c.collectDisk,
		c.collectNetwork,
		c.collectUptime,
		c.collectLoad,
	}
	for _, probe := range probes {
		// Checked between probes rather than inside each one: gopsutil's
		// syscall-backed readers (statfs, /proc) do not observe ctx
		// themselves, so this is the only place cancellation can take
		// effect without abandoning a goroutine mid-read.
		if ctx.Err() != nil {
			break
		}
		probe(ctx, &snap)
	}

	if err := ctx.Err(); err != nil {
		// Recorded once, here, rather than per skipped source: six copies
		// of "context canceled" in Failures tells an operator nothing the
		// single returned error does not.
		snap.fail("collection", err)
		return snap, fmt.Errorf("hostmetrics: collection interrupted: %w", err)
	}
	if len(snap.Samples) == 0 {
		if cause := snap.Err(); cause != nil {
			return snap, fmt.Errorf("%w: %w", ErrNoSamples, cause)
		}
		return snap, ErrNoSamples
	}
	return snap, nil
}

func (c *Collector) collectCPU(ctx context.Context, snap *Snapshot) {
	percent, err := c.src.CPUPercent(ctx)
	if err != nil {
		snap.fail("cpu", err)
		return
	}
	snap.gauge(MetricCPUUtilization, UnitRatio, percent/100, nil)
}

func (c *Collector) collectMemory(ctx context.Context, snap *Snapshot) {
	stat, err := c.src.Memory(ctx)
	if err != nil {
		snap.fail("memory", err)
		return
	}
	snap.gauge(
		MetricMemoryUsage,
		UnitBytes,
		float64(stat.Used),
		map[string]string{AttrState: StateUsed},
	)
	snap.gauge(MetricMemoryUtilization, UnitRatio, ratio(stat.UsedPercent, stat.Used, stat.Total), nil)
}

func (c *Collector) collectDisk(ctx context.Context, snap *Snapshot) {
	parts, err := c.src.Partitions(ctx)
	if err != nil {
		snap.fail("disk_partitions", err)
		return
	}

	for _, p := range c.selectPartitions(parts) {
		// The one probe that loops over an unbounded external resource: up
		// to MaxDevices mounts, any of which can be a slow network share.
		// Collect records the cancellation cause for the whole cycle.
		if ctx.Err() != nil {
			return
		}
		usage, usageErr := c.src.DiskUsage(ctx, p.Mountpoint)
		if usageErr != nil {
			// One unreadable mount (a disconnected network share, a
			// permission-denied container mount) must not cost us the
			// other disks.
			snap.fail("disk_usage", usageErr)
			continue
		}
		device := sanitizeDeviceName(p.Device)
		snap.gauge(
			MetricDiskUsage,
			UnitBytes,
			float64(usage.Used),
			map[string]string{AttrDevice: device, AttrState: StateUsed},
		)
		snap.gauge(
			MetricDiskUtilization,
			UnitRatio,
			ratio(usage.UsedPercent, usage.Used, usage.Total),
			map[string]string{AttrDevice: device},
		)
	}
}

func (c *Collector) collectNetwork(ctx context.Context, snap *Snapshot) {
	counters, err := c.src.NetIO(ctx)
	if err != nil {
		snap.fail("network", err)
		return
	}

	for _, nic := range c.selectInterfaces(counters) {
		device := sanitizeDeviceName(nic.Name)
		snap.sum(MetricNetworkIO, UnitBytes, float64(nic.BytesRecv), map[string]string{
			AttrDevice: device, AttrDirection: DirectionReceive,
		})
		snap.sum(MetricNetworkIO, UnitBytes, float64(nic.BytesSent), map[string]string{
			AttrDevice: device, AttrDirection: DirectionTransmit,
		})
		snap.sum(MetricNetworkErrors, UnitErrors, float64(nic.ErrIn), map[string]string{
			AttrDevice: device, AttrDirection: DirectionReceive,
		})
		snap.sum(MetricNetworkErrors, UnitErrors, float64(nic.ErrOut), map[string]string{
			AttrDevice: device, AttrDirection: DirectionTransmit,
		})
	}
}

func (c *Collector) collectUptime(ctx context.Context, snap *Snapshot) {
	uptime, err := c.src.Uptime(ctx)
	if err != nil {
		snap.fail("uptime", err)
		return
	}
	snap.gauge(MetricUptime, UnitSeconds, uptime.Seconds(), nil)
}

func (c *Collector) collectLoad(ctx context.Context, snap *Snapshot) {
	avg, err := c.src.LoadAverage(ctx)
	if err != nil {
		// Load average is genuinely unavailable on some platforms. That is
		// a degraded snapshot, not an error.
		snap.fail("load_average", err)
		return
	}
	snap.gauge(MetricLoad1, UnitRatio, avg.Load1, nil)
	snap.gauge(MetricLoad5, UnitRatio, avg.Load5, nil)
	snap.gauge(MetricLoad15, UnitRatio, avg.Load15, nil)
}

// selectPartitions drops pseudo/virtual filesystems, de-duplicates by
// sanitised device name (bind mounts and btrfs subvolumes report the same
// device many times), sorts for determinism, and caps the result.
func (c *Collector) selectPartitions(parts []Partition) []Partition {
	seen := make(map[string]struct{}, len(parts))
	kept := make([]Partition, 0, len(parts))
	for _, p := range parts {
		if p.Mountpoint == "" || isPseudoFilesystem(p.FSType) {
			continue
		}
		device := sanitizeDeviceName(p.Device)
		if device == "" {
			continue
		}
		if _, dup := seen[device]; dup {
			continue
		}
		seen[device] = struct{}{}
		kept = append(kept, p)
	}
	sort.Slice(kept, func(i, j int) bool {
		return sanitizeDeviceName(kept[i].Device) < sanitizeDeviceName(kept[j].Device)
	})
	if len(kept) > c.maxDevices {
		kept = kept[:c.maxDevices]
	}
	return kept
}

// selectInterfaces drops loopback and virtual interfaces, sorts for
// determinism, and caps the result.
func (c *Collector) selectInterfaces(counters []NetIO) []NetIO {
	kept := make([]NetIO, 0, len(counters))
	for _, nic := range counters {
		if isVirtualInterface(nic.Name) {
			continue
		}
		if sanitizeDeviceName(nic.Name) == "" {
			continue
		}
		kept = append(kept, nic)
	}
	sort.Slice(kept, func(i, j int) bool { return kept[i].Name < kept[j].Name })
	if len(kept) > c.maxDevices {
		kept = kept[:c.maxDevices]
	}
	return kept
}

func (s *Snapshot) gauge(name, unit string, value float64, attrs map[string]string) {
	s.add(Sample{Name: name, Unit: unit, Kind: KindGauge, Value: value, Attributes: attrs})
}

func (s *Snapshot) sum(name, unit string, value float64, attrs map[string]string) {
	s.add(Sample{
		Name:       name,
		Unit:       unit,
		Kind:       KindSum,
		Value:      value,
		Attributes: attrs,
		Monotonic:  true,
	})
}

// add drops non-finite values. gopsutil returns NaN for a percentage over a
// zero-capacity device, and json.Marshal fails outright on NaN/±Inf — a
// single bad reading would otherwise cost the whole batch.
func (s *Snapshot) add(sample Sample) {
	if math.IsNaN(sample.Value) || math.IsInf(sample.Value, 0) {
		err := fmt.Errorf("%s: %w", sample.Name, ErrNonFiniteValue)
		s.errs = append(s.errs, err)
		s.Failures = append(s.Failures, err.Error())
		return
	}
	s.Samples = append(s.Samples, sample)
}

// fail records a source that could not be read: the wrapped error joins the
// snapshot's chain, and a flattened copy joins Failures for logging. A
// source the platform does not implement is recorded as Unsupported instead
// — still in the chain, but not something to warn about every tick.
func (s *Snapshot) fail(source string, err error) {
	wrapped := fmt.Errorf("%s: %w", source, err)
	s.errs = append(s.errs, wrapped)
	if isNotImplemented(err) {
		s.Unsupported = append(s.Unsupported, source)
		return
	}
	s.Failures = append(s.Failures, wrapped.Error())
}

// isNotImplemented reports whether err is gopsutil's "this platform does
// not implement this reading" sentinel.
//
// That sentinel is common.ErrNotImplementedError, which lives under
// gopsutil's internal/ tree and therefore cannot be named — let alone
// passed to errors.Is — by any package outside gopsutil itself. Matching
// the message is the only classification available to a consumer. The
// wording has been stable across v3 and v4 ("not implemented yet"), and a
// false negative costs nothing worse than the source being reported as a
// degradation rather than a platform limit.
func isNotImplemented(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(strings.ToLower(err.Error()), "not implemented")
}

// ratio converts a gopsutil "used percent" reading into a 0..1 ratio,
// recomputing it from the raw byte counts when the reported percentage is
// not finite (total == 0 on an empty or virtual device).
func ratio(usedPercent float64, used, total uint64) float64 {
	if !math.IsNaN(usedPercent) && !math.IsInf(usedPercent, 0) {
		return usedPercent / 100
	}
	if total == 0 {
		return 0
	}
	return float64(used) / float64(total)
}

// sanitizeDeviceName reduces a device or interface name to the small
// vocabulary R5 permits: the leading /dev/ path segment is dropped (so no
// filesystem path egresses), only `[A-Za-z0-9._:-]` survives, and the
// result is truncated. Returns "" when nothing usable remains, which the
// callers treat as "skip this device".
func sanitizeDeviceName(raw string) string {
	name := strings.TrimSpace(raw)
	name = strings.TrimPrefix(name, `\\.\`)
	if idx := strings.LastIndexAny(name, `/\`); idx >= 0 {
		name = name[idx+1:]
	}

	var b strings.Builder
	b.Grow(len(name))
	for _, r := range name {
		// Anything outside the permitted set (spaces, quotes, control
		// characters, non-ASCII) is discarded rather than escaped: a device
		// name is not free text and never needs them.
		if isDeviceRune(r) {
			b.WriteRune(r)
		}
	}

	out := b.String()
	if len(out) > maxDeviceNameLen {
		out = out[:maxDeviceNameLen]
	}
	return out
}

// isDeviceRune reports whether r may appear in a sanitised device name.
func isDeviceRune(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z':
		return true
	case r >= 'A' && r <= 'Z':
		return true
	case r >= '0' && r <= '9':
		return true
	case r == '.', r == '_', r == '-', r == ':':
		return true
	default:
		return false
	}
}

// pseudoFilesystems are kernel/virtual filesystems whose "usage" is either
// meaningless or a duplicate of a real device's.
var pseudoFilesystems = map[string]struct{}{
	"autofs": {}, "binfmt_misc": {}, "bpf": {}, "cgroup": {}, "cgroup2": {},
	"configfs": {}, "debugfs": {}, "devfs": {}, "devpts": {}, "devtmpfs": {},
	"efivarfs": {}, "fuse.gvfsd-fuse": {}, "fuse.portal": {}, "fusectl": {},
	"hugetlbfs": {}, "mqueue": {}, "nsfs": {}, "overlay": {}, "proc": {},
	"pstore": {}, "ramfs": {}, "rpc_pipefs": {}, "securityfs": {},
	"selinuxfs": {}, "squashfs": {}, "sysfs": {}, "tmpfs": {}, "tracefs": {},
}

func isPseudoFilesystem(fstype string) bool {
	_, ok := pseudoFilesystems[strings.ToLower(strings.TrimSpace(fstype))]
	return ok
}

// virtualInterfacePrefixes covers container, VM, VPN, and bridge interfaces.
// They are numerous, ephemeral, and carry no host-health signal — exactly
// the cardinality blow-up §6.1's Denial of Service row warns about.
var virtualInterfacePrefixes = []string{
	"lo", "docker", "veth", "br-", "virbr", "vboxnet", "vmnet", "tun", "tap",
	"cni", "flannel", "cali", "kube-", "utun", "wg", "zt", "ham", "nebula",
	"tailscale", "anpi", "awdl", "llw", "bridge", "gif", "stf", "ap1",
	"isatap",
}

func isVirtualInterface(name string) bool {
	lower := strings.ToLower(strings.TrimSpace(name))
	if lower == "" {
		return true
	}
	for _, prefix := range virtualInterfacePrefixes {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}
