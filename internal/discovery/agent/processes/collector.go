package processes

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	gops "github.com/shirou/gopsutil/v4/process"
)

// procSource is the test seam: gopsutil's `process.Processes(ctx)` plus
// the per-process accessor methods we need. Production uses the real
// gopsutil API; tests inject a synthetic source.
type procSource interface {
	List(ctx context.Context) ([]procHandle, error)
}

// procHandle is the per-process subset of gopsutil's *Process surface we
// actually consume. Returning structured "what we know / what we couldn't
// fetch" pairs from each accessor keeps the collector's error story
// uniform across OSes — gopsutil returns "not implemented" on some
// platforms (e.g. CWD on Windows pre-1607) which is fine to skip.
type procHandle interface {
	PID() int32
	PPID(ctx context.Context) (int32, error)
	Name(ctx context.Context) (string, error)
	Exe(ctx context.Context) (string, error)
	Cmdline(ctx context.Context) (string, error)
	Username(ctx context.Context) (string, error)
	Status(ctx context.Context) ([]string, error)
	NumThreads(ctx context.Context) (int32, error)
	MemoryInfo(ctx context.Context) (rss, vms uint64, ok bool)
	CWD(ctx context.Context) (string, error)
	CreatedAt(ctx context.Context) (time.Time, error)
}

// gopsutilCollector wraps gopsutil/v4/process. The single struct works on
// every supported OS because gopsutil handles per-OS specifics internally.
type gopsutilCollector struct {
	src procSource
}

// NewCollector returns a production Collector backed by gopsutil/v4.
func NewCollector() Collector {
	return &gopsutilCollector{src: realSource{}}
}

func (gopsutilCollector) Name() string { return "gopsutil" }

// Collect enumerates every visible process, capped at MaxProcesses, and
// returns them sorted by PID. Per-process errors are logged at DEBUG and
// the row is emitted with whatever fields succeeded — gopsutil routinely
// reports permission-denied for processes owned by other users, which is
// expected when the collector runs unprivileged.
func (c *gopsutilCollector) Collect(ctx context.Context) ([]Process, error) {
	now := time.Now().UTC()

	handles, err := c.src.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("list processes: %w", err)
	}
	if len(handles) > MaxProcesses {
		slog.Warn("processes: capping inventory at MaxProcesses",
			"code", string(LogCodeCollectorInventoryCapped), "observed", len(handles), "cap", MaxProcesses)
		handles = handles[:MaxProcesses]
	}

	out := make([]Process, 0, len(handles))
	for _, h := range handles {
		if err := ctx.Err(); err != nil {
			return out, fmt.Errorf("context cancelled mid-collect: %w", err)
		}
		out = append(out, snapshot(ctx, h, now))
	}
	SortProcesses(out)
	return out, nil
}

// snapshot fills a Process from a procHandle. Per-field errors are
// swallowed silently: the most common cause is EACCES on /proc/<pid>/cwd
// or similar, which is normal for unprivileged scans of other users'
// processes. The PID is always recorded; partial rows are still useful.
func snapshot(ctx context.Context, h procHandle, now time.Time) Process {
	p := Process{
		PID:         h.PID(),
		LastSeenAt:  now,
		CollectedAt: now,
		Status:      StatusUnknown,
	}
	if ppid, err := h.PPID(ctx); err == nil {
		p.PPID = ppid
	}
	if name, err := h.Name(ctx); err == nil {
		p.Name = name
	}
	if exe, err := h.Exe(ctx); err == nil {
		p.Exe = exe
	}
	if cmd, err := h.Cmdline(ctx); err == nil {
		p.Cmdline = TruncateCmdline(cmd)
	}
	if user, err := h.Username(ctx); err == nil {
		p.Username = user
	}
	if status, err := h.Status(ctx); err == nil && len(status) > 0 {
		p.Status = NormalizeStatus(status[0])
	}
	if n, err := h.NumThreads(ctx); err == nil {
		p.NumThreads = n
	}
	if rss, vms, ok := h.MemoryInfo(ctx); ok {
		p.RSSBytes = rss
		p.VMSBytes = vms
	}
	if cwd, err := h.CWD(ctx); err == nil {
		p.CWD = cwd
	}
	if started, err := h.CreatedAt(ctx); err == nil {
		p.StartedAt = started
	}
	p.IsKernelThread = IsKernelThread(p.Name, p.PPID)
	return p
}

// realSource is the production adapter wrapping gopsutil's package-level
// API into the procSource/procHandle interfaces. Isolating it here keeps
// the collector pure-Go for tests.
type realSource struct{}

func (realSource) List(ctx context.Context) ([]procHandle, error) {
	ps, err := gops.ProcessesWithContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("gopsutil processes: %w", err)
	}
	out := make([]procHandle, 0, len(ps))
	for _, p := range ps {
		out = append(out, realHandle{p: p})
	}
	return out, nil
}

type realHandle struct{ p *gops.Process }

func (r realHandle) PID() int32 { return r.p.Pid }

func (r realHandle) PPID(ctx context.Context) (int32, error) {
	v, err := r.p.PpidWithContext(ctx)
	if err != nil {
		return 0, fmt.Errorf("ppid: %w", err)
	}
	return v, nil
}

func (r realHandle) Name(ctx context.Context) (string, error) {
	v, err := r.p.NameWithContext(ctx)
	if err != nil {
		return "", fmt.Errorf("name: %w", err)
	}
	return v, nil
}

func (r realHandle) Exe(ctx context.Context) (string, error) {
	v, err := r.p.ExeWithContext(ctx)
	if err != nil {
		return "", fmt.Errorf("exe: %w", err)
	}
	return v, nil
}

func (r realHandle) Cmdline(ctx context.Context) (string, error) {
	v, err := r.p.CmdlineWithContext(ctx)
	if err != nil {
		return "", fmt.Errorf("cmdline: %w", err)
	}
	return v, nil
}

func (r realHandle) Username(ctx context.Context) (string, error) {
	v, err := r.p.UsernameWithContext(ctx)
	if err != nil {
		return "", fmt.Errorf("username: %w", err)
	}
	return v, nil
}

func (r realHandle) Status(ctx context.Context) ([]string, error) {
	v, err := r.p.StatusWithContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("status: %w", err)
	}
	return v, nil
}

func (r realHandle) NumThreads(ctx context.Context) (int32, error) {
	v, err := r.p.NumThreadsWithContext(ctx)
	if err != nil {
		return 0, fmt.Errorf("num threads: %w", err)
	}
	return v, nil
}

func (r realHandle) MemoryInfo(ctx context.Context) (uint64, uint64, bool) {
	m, err := r.p.MemoryInfoWithContext(ctx)
	if err != nil || m == nil {
		return 0, 0, false
	}
	return m.RSS, m.VMS, true
}

func (r realHandle) CWD(ctx context.Context) (string, error) {
	v, err := r.p.CwdWithContext(ctx)
	if err != nil {
		return "", fmt.Errorf("cwd: %w", err)
	}
	return v, nil
}

func (r realHandle) CreatedAt(ctx context.Context) (time.Time, error) {
	ms, err := r.p.CreateTimeWithContext(ctx)
	if err != nil {
		return time.Time{}, fmt.Errorf("create time: %w", err)
	}
	return time.UnixMilli(ms).UTC(), nil
}
