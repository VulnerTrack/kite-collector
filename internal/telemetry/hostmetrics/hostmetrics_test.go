package hostmetrics

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeSource is the injected test double for every OS-touching read. Each
// field pairs a canned reading with an optional failure, so a test can make
// exactly one source fail and assert the rest survived (R3).
type fakeSource struct {
	usage     map[string]DiskStat
	cpuErr    error
	memErr    error
	partsErr  error
	usageErr  error
	nicsErr   error
	uptimeErr error
	loadErr   error
	parts     []Partition
	nics      []NetIO
	// probed records the sources actually read, in order, so a test can
	// assert that a cancelled context stopped the cycle rather than merely
	// discarding its results.
	probed []string
	mem    MemStat
	load   LoadStat
	uptime time.Duration
	cpu    float64
}

func (f *fakeSource) probe(name string) { f.probed = append(f.probed, name) }

func (f *fakeSource) CPUPercent(context.Context) (float64, error) {
	f.probe("cpu")
	return f.cpu, f.cpuErr
}

func (f *fakeSource) Memory(context.Context) (MemStat, error) {
	f.probe("memory")
	return f.mem, f.memErr
}

func (f *fakeSource) Partitions(context.Context) ([]Partition, error) {
	f.probe("partitions")
	return f.parts, f.partsErr
}

func (f *fakeSource) DiskUsage(_ context.Context, mountpoint string) (DiskStat, error) {
	f.probe("disk_usage")
	if f.usageErr != nil {
		return DiskStat{}, f.usageErr
	}
	stat, ok := f.usage[mountpoint]
	if !ok {
		return DiskStat{}, errors.New("no such mount")
	}
	return stat, nil
}

func (f *fakeSource) NetIO(context.Context) ([]NetIO, error) {
	f.probe("net_io")
	return f.nics, f.nicsErr
}

func (f *fakeSource) Uptime(context.Context) (time.Duration, error) {
	f.probe("uptime")
	return f.uptime, f.uptimeErr
}

func (f *fakeSource) LoadAverage(context.Context) (LoadStat, error) {
	f.probe("load_average")
	return f.load, f.loadErr
}

// cancelMidCycle cancels the collection context once the first source has
// been read, standing in for an agent stopped part-way through a cycle.
type cancelMidCycle struct {
	*fakeSource
	cancel context.CancelFunc
}

func (c cancelMidCycle) CPUPercent(ctx context.Context) (float64, error) {
	value, err := c.fakeSource.CPUPercent(ctx)
	c.cancel()
	return value, err
}

// healthySource returns a fixture with every source readable: one real
// disk, one real NIC, and a pseudo/virtual companion for each that the
// collector is expected to drop.
func healthySource() *fakeSource {
	return &fakeSource{
		cpu: 42.5,
		mem: MemStat{Total: 8 << 30, Used: 4 << 30, UsedPercent: 50},
		parts: []Partition{
			{Device: "/dev/sda1", Mountpoint: "/", FSType: "ext4"},
			{Device: "tmpfs", Mountpoint: "/run", FSType: "tmpfs"},
		},
		usage: map[string]DiskStat{
			"/":    {Total: 500 << 30, Used: 310 << 30, UsedPercent: 62},
			"/run": {Total: 1 << 30, Used: 1 << 20, UsedPercent: 0.1},
		},
		nics: []NetIO{
			{Name: "eth0", BytesRecv: 1000, BytesSent: 2000, ErrIn: 3, ErrOut: 4},
			{Name: "docker0", BytesRecv: 5, BytesSent: 6, ErrIn: 7, ErrOut: 8},
			{Name: "lo", BytesRecv: 9, BytesSent: 10},
		},
		uptime: 36 * time.Hour,
		load:   LoadStat{Load1: 0.5, Load5: 1.25, Load15: 2},
	}
}

func collectWith(t *testing.T, src Source) Snapshot {
	t.Helper()
	snap, err := NewWithSource(src, MaxDevices).Collect(context.Background())
	require.NoError(t, err)
	return snap
}

func names(snap Snapshot) map[string]int {
	out := map[string]int{}
	for _, s := range snap.Samples {
		out[s.Name]++
	}
	return out
}

func firstSample(snap Snapshot, name string) (Sample, bool) {
	for _, s := range snap.Samples {
		if s.Name == name {
			return s, true
		}
	}
	return Sample{}, false
}

// TestCollect_EmitsEveryCatalogInstrument pins the extensional catalog: all
// eleven `system.*` instruments RFC-0157 §4.2.1 enumerates must appear in a
// snapshot taken from a fully-readable host. Anything missing here silently
// becomes an ontology metric nobody ever populates.
func TestCollect_EmitsEveryCatalogInstrument(t *testing.T) {
	snap := collectWith(t, healthySource())
	got := names(snap)

	for _, want := range []string{
		MetricCPUUtilization,
		MetricMemoryUsage,
		MetricMemoryUtilization,
		MetricDiskUsage,
		MetricDiskUtilization,
		MetricNetworkIO,
		MetricNetworkErrors,
		MetricUptime,
		MetricLoad1,
		MetricLoad5,
		MetricLoad15,
	} {
		assert.Positive(t, got[want], "instrument %q produced no sample", want)
	}
	assert.Len(t, got, 11, "catalog drifted: %v", got)
}

// TestCollect_UtilizationIsARatioNotAPercent guards the unit contract: the
// catalog declares UCUM "1" for utilization, so a 42.5% reading must land
// as 0.425. Emitting 42.5 against a 0.80 threshold would fire every host.
func TestCollect_UtilizationIsARatioNotAPercent(t *testing.T) {
	snap := collectWith(t, healthySource())

	cpu, ok := firstSample(snap, MetricCPUUtilization)
	require.True(t, ok)
	assert.InDelta(t, 0.425, cpu.Value, 1e-9)
	assert.Equal(t, UnitRatio, cpu.Unit)

	mem, ok := firstSample(snap, MetricMemoryUtilization)
	require.True(t, ok)
	assert.InDelta(t, 0.5, mem.Value, 1e-9)

	disk, ok := firstSample(snap, MetricDiskUtilization)
	require.True(t, ok)
	assert.InDelta(t, 0.62, disk.Value, 1e-9)
}

// TestCollect_UsesGaugeAndSumKindsCorrectly pins the instrument shapes the
// Python catalog mirrors: utilisation/usage/uptime/load are gauges, network
// counters are monotonic sums.
func TestCollect_UsesGaugeAndSumKindsCorrectly(t *testing.T) {
	snap := collectWith(t, healthySource())

	for _, s := range snap.Samples {
		switch s.Name {
		case MetricNetworkIO, MetricNetworkErrors:
			assert.Equal(t, KindSum, s.Kind, "%s should be a sum", s.Name)
			assert.True(t, s.Monotonic, "%s should be monotonic", s.Name)
		default:
			assert.Equal(t, KindGauge, s.Kind, "%s should be a gauge", s.Name)
			assert.False(t, s.Monotonic, "%s must not claim monotonicity", s.Name)
		}
	}
}

// TestCollect_DropsPseudoFilesystemsAndVirtualInterfaces is the cardinality
// control from R5 / §6.1's Denial of Service row: tmpfs mounts and
// docker/loopback interfaces are numerous, ephemeral, and carry no
// host-health signal.
func TestCollect_DropsPseudoFilesystemsAndVirtualInterfaces(t *testing.T) {
	snap := collectWith(t, healthySource())

	devices := map[string]struct{}{}
	for _, s := range snap.Samples {
		if d, ok := s.Attributes[AttrDevice]; ok {
			devices[d] = struct{}{}
		}
	}

	assert.Contains(t, devices, "sda1")
	assert.Contains(t, devices, "eth0")
	assert.NotContains(t, devices, "tmpfs")
	assert.NotContains(t, devices, "docker0")
	assert.NotContains(t, devices, "lo")
}

// TestCollect_AttributeVocabularyIsBounded is the direct R5 assertion: the
// only attribute keys that may ever reach the wire are device, direction,
// and state, and no value may be a filesystem path.
func TestCollect_AttributeVocabularyIsBounded(t *testing.T) {
	snap := collectWith(t, healthySource())

	allowedKeys := map[string]struct{}{
		AttrDevice: {}, AttrDirection: {}, AttrState: {},
	}
	allowedDirections := map[string]struct{}{
		DirectionReceive: {}, DirectionTransmit: {},
	}

	for _, s := range snap.Samples {
		for k, v := range s.Attributes {
			assert.Contains(t, allowedKeys, k, "unexpected attribute key %q", k)
			assert.NotContains(t, v, "/", "attribute %q=%q leaks a path", k, v)
			assert.NotContains(t, v, `\`, "attribute %q=%q leaks a path", k, v)
			assert.LessOrEqual(t, len(v), maxDeviceNameLen)
		}
		if dir, ok := s.Attributes[AttrDirection]; ok {
			assert.Contains(t, allowedDirections, dir)
		}
		if state, ok := s.Attributes[AttrState]; ok {
			assert.Equal(t, StateUsed, state)
		}
	}
}

// TestCollect_CapsDeviceFanOut keeps a host with dozens of disks or NICs
// from inflating the otel_metrics_* ORDER BY key.
func TestCollect_CapsDeviceFanOut(t *testing.T) {
	src := healthySource()
	src.parts = nil
	src.usage = map[string]DiskStat{}
	src.nics = nil
	for i := range 20 {
		mount := "/mnt/" + string(rune('a'+i))
		src.parts = append(src.parts, Partition{
			Device:     "/dev/sd" + string(rune('a'+i)),
			Mountpoint: mount,
			FSType:     "ext4",
		})
		src.usage[mount] = DiskStat{Total: 100, Used: 50, UsedPercent: 50}
		src.nics = append(src.nics, NetIO{Name: "eth" + string(rune('0'+i%10)) + string(rune('a'+i))})
	}

	capped, err := NewWithSource(src, 3).Collect(context.Background())
	require.NoError(t, err)

	diskDevices := map[string]struct{}{}
	netDevices := map[string]struct{}{}
	for _, s := range capped.Samples {
		d, ok := s.Attributes[AttrDevice]
		if !ok {
			continue
		}
		if s.Name == MetricNetworkIO || s.Name == MetricNetworkErrors {
			netDevices[d] = struct{}{}
			continue
		}
		diskDevices[d] = struct{}{}
	}

	assert.Len(t, diskDevices, 3)
	assert.Len(t, netDevices, 3)
}

// TestCollect_PartialFailureKeepsOtherSamples is R3: one unsupported or
// restricted source must not cost the whole snapshot.
func TestCollect_PartialFailureKeepsOtherSamples(t *testing.T) {
	src := healthySource()
	src.loadErr = errors.New("load average unsupported on this platform")

	snap := collectWith(t, src)
	got := names(snap)

	assert.Zero(t, got[MetricLoad1])
	assert.Positive(t, got[MetricCPUUtilization])
	assert.Positive(t, got[MetricMemoryUsage])
	require.Len(t, snap.Failures, 1)
	assert.Contains(t, snap.Failures[0], "load_average")
}

// TestCollect_UnreadableMountDoesNotCostTheOtherDisks covers the
// disconnected-network-share case specifically: DiskUsage failing for one
// mount must not abort the disk loop.
func TestCollect_UnreadableMountDoesNotCostTheOtherDisks(t *testing.T) {
	src := healthySource()
	src.parts = append(src.parts, Partition{
		Device: "/dev/sdz9", Mountpoint: "/mnt/gone", FSType: "nfs",
	})

	snap := collectWith(t, src)

	devices := map[string]struct{}{}
	for _, s := range snap.Samples {
		if d, ok := s.Attributes[AttrDevice]; ok {
			devices[d] = struct{}{}
		}
	}
	assert.Contains(t, devices, "sda1")
	assert.NotContains(t, devices, "sdz9")
	assert.NotEmpty(t, snap.Failures)
}

// TestCollect_AllSourcesFailingReturnsErrNoSamples is the one error path:
// a sandboxed container with no /proc at all. The caller logs and skips the
// tick rather than treating it as fatal.
func TestCollect_AllSourcesFailingReturnsErrNoSamples(t *testing.T) {
	boom := errors.New("permission denied")
	src := &fakeSource{
		cpuErr: boom, memErr: boom, partsErr: boom,
		nicsErr: boom, uptimeErr: boom, loadErr: boom,
	}

	snap, err := NewWithSource(src, MaxDevices).Collect(context.Background())

	require.ErrorIs(t, err, ErrNoSamples)
	// The per-source cause travels with the sentinel: a caller that needs
	// to tell "no /proc in this container" from "permission denied" can,
	// without parsing Failures strings.
	require.ErrorIs(t, err, boom)
	assert.Empty(t, snap.Samples)
	assert.Len(t, snap.Failures, 6)
}

// TestSnapshot_ErrPreservesTheUnderlyingCause is the errors.Is contract on a
// partially-readable host: Failures is for the log line, Err is for code
// that has to classify what went wrong.
func TestSnapshot_ErrPreservesTheUnderlyingCause(t *testing.T) {
	src := healthySource()
	src.cpuErr = fmt.Errorf("read /proc/stat: %w", os.ErrPermission)

	snap := collectWith(t, src)

	require.ErrorIs(t, snap.Err(), os.ErrPermission)
	require.Len(t, snap.Failures, 1)
	assert.Contains(t, snap.Failures[0], "cpu")
	assert.Positive(t, names(snap)[MetricMemoryUsage], "one denied read is not the whole snapshot")
}

// TestCollect_NotImplementedIsAPlatformLimitNotADegradation keeps the
// per-tick warning honest. Load average is genuinely absent on some
// platforms; reporting that as a failure every 60s forever is noise no
// operator can act on, so it lands in Unsupported instead.
func TestCollect_NotImplementedIsAPlatformLimitNotADegradation(t *testing.T) {
	src := healthySource()
	// gopsutil's common.ErrNotImplementedError, which its internal/ tree
	// keeps out of reach of errors.Is.
	src.loadErr = errors.New("not implemented yet")

	snap := collectWith(t, src)

	assert.Empty(t, snap.Failures)
	assert.Equal(t, []string{"load_average"}, snap.Unsupported)
	assert.ErrorContains(t, snap.Err(), "load_average")
	assert.Zero(t, names(snap)[MetricLoad1])
}

// TestCollect_DeadContextIsDistinguishableFromNoSamples: an agent shutting
// down and a host that stopped answering both produce an empty snapshot.
// Only the error tells them apart, and the caller logs one but not the
// other.
func TestCollect_DeadContextIsDistinguishableFromNoSamples(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	src := healthySource()
	snap, err := NewWithSource(src, MaxDevices).Collect(ctx)

	require.ErrorIs(t, err, context.Canceled)
	assert.NotErrorIs(t, err, ErrNoSamples)
	assert.Empty(t, snap.Samples)
	assert.Empty(t, src.probed, "no source may be read under a dead context")
}

// TestCollect_CancellationMidCycleStopsTheRemainingProbes covers the
// shutdown-during-collection path: what was already read is kept, the rest
// is skipped rather than each failing in turn.
func TestCollect_CancellationMidCycleStopsTheRemainingProbes(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	base := healthySource()
	snap, err := NewWithSource(cancelMidCycle{fakeSource: base, cancel: cancel}, MaxDevices).
		Collect(ctx)

	require.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, []string{"cpu"}, base.probed, "later sources must be skipped, not failed")
	assert.Positive(t, names(snap)[MetricCPUUtilization], "the completed read is kept")
	assert.Zero(t, names(snap)[MetricMemoryUsage])
	require.Len(t, snap.Failures, 1)
	assert.Contains(t, snap.Failures[0], "collection")
}

// TestCollect_DropsNonFiniteValues guards the JSON encoder: json.Marshal
// fails outright on NaN/±Inf, so a single zero-capacity device would
// otherwise cost the entire batch.
func TestCollect_DropsNonFiniteValues(t *testing.T) {
	src := healthySource()
	src.cpu = math.NaN()

	snap := collectWith(t, src)

	assert.Zero(t, names(snap)[MetricCPUUtilization])
	for _, s := range snap.Samples {
		assert.False(t, math.IsNaN(s.Value))
		assert.False(t, math.IsInf(s.Value, 0))
	}
	assert.NotEmpty(t, snap.Failures)
}

// TestRatio_RecomputesWhenPercentIsNotFinite covers gopsutil returning NaN
// for UsedPercent on a zero-capacity device.
func TestRatio_RecomputesWhenPercentIsNotFinite(t *testing.T) {
	assert.InDelta(t, 0.25, ratio(25, 1, 4), 1e-9)
	assert.InDelta(t, 0.25, ratio(math.NaN(), 1, 4), 1e-9)
	assert.InDelta(t, 0.0, ratio(math.NaN(), 0, 0), 1e-9)
	assert.InDelta(t, 0.0, ratio(math.Inf(1), 0, 0), 1e-9)
}

func TestSanitizeDeviceName(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"linux block device", "/dev/sda1", "sda1"},
		{"nvme namespace", "/dev/nvme0n1p2", "nvme0n1p2"},
		{"windows drive letter", `C:`, "C:"},
		{"windows device path", `\\.\C:`, "C:"},
		{"plain interface", "eth0", "eth0"},
		{"strips spaces and quotes", `sd a'1"`, "sda1"},
		{"strips non ascii", "sda1é你", "sda1"},
		{"drops everything unusable", "!!!", ""},
		{"empty stays empty", "   ", ""},
		{
			"truncates absurd names",
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, sanitizeDeviceName(tc.in))
		})
	}
}

func TestIsVirtualInterface(t *testing.T) {
	for _, name := range []string{
		"lo", "lo0", "docker0", "veth1a2b", "br-abc", "virbr0", "tun0", "utun3",
		"wg0", "tailscale0",
	} {
		assert.True(t, isVirtualInterface(name), "%q should be virtual", name)
	}
	for _, name := range []string{"eth0", "ens192", "enp0s31f6", "eno1", "em1", "Ethernet"} {
		assert.False(t, isVirtualInterface(name), "%q should be physical", name)
	}
}

func TestIsPseudoFilesystem(t *testing.T) {
	for _, fs := range []string{"tmpfs", "TMPFS", "proc", "sysfs", "overlay", "devtmpfs", "squashfs"} {
		assert.True(t, isPseudoFilesystem(fs), "%q should be pseudo", fs)
	}
	for _, fs := range []string{"ext4", "xfs", "btrfs", "apfs", "NTFS", "zfs"} {
		assert.False(t, isPseudoFilesystem(fs), "%q should be real", fs)
	}
}

// TestCollect_DeduplicatesRepeatedDevices covers btrfs subvolumes and bind
// mounts, which report the same device under several mountpoints.
func TestCollect_DeduplicatesRepeatedDevices(t *testing.T) {
	src := healthySource()
	src.parts = []Partition{
		{Device: "/dev/sda1", Mountpoint: "/", FSType: "btrfs"},
		{Device: "/dev/sda1", Mountpoint: "/home", FSType: "btrfs"},
		{Device: "/dev/sda1", Mountpoint: "/var", FSType: "btrfs"},
	}
	src.usage = map[string]DiskStat{
		"/":     {Total: 100, Used: 50, UsedPercent: 50},
		"/home": {Total: 100, Used: 50, UsedPercent: 50},
		"/var":  {Total: 100, Used: 50, UsedPercent: 50},
	}

	snap := collectWith(t, src)

	assert.Equal(t, 1, names(snap)[MetricDiskUsage])
	assert.Equal(t, 1, names(snap)[MetricDiskUtilization])
}

// TestCollect_IsDeterministicAcrossRuns matters because map iteration order
// is randomised in Go: two collections of the same host state must produce
// the same samples in the same order, or the wire payload churns for no
// reason.
func TestCollect_IsDeterministicAcrossRuns(t *testing.T) {
	src := healthySource()
	first := collectWith(t, src)
	second := collectWith(t, src)

	require.Len(t, second.Samples, len(first.Samples))
	for i := range first.Samples {
		assert.Equal(t, first.Samples[i].Name, second.Samples[i].Name)
		assert.Equal(t, first.Samples[i].Attributes, second.Samples[i].Attributes)
	}
}
