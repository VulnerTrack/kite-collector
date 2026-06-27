package processes

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestNormalizeStatusKnownForms(t *testing.T) {
	cases := map[string]Status{
		// Linux single-letter codes (gopsutil emits these from /proc/<pid>/stat)
		"R": StatusRunning, "S": StatusSleeping, "I": StatusIdle,
		"T": StatusStopped, "Z": StatusZombie, "W": StatusWait, "L": StatusLock,
		// Long forms (Windows, macOS, FreeBSD variants)
		"running": StatusRunning, "Run": StatusRunning,
		"sleeping": StatusSleeping, "Sleep": StatusSleeping,
		"stopped": StatusStopped, "Stop": StatusStopped,
		"zombie": StatusZombie, "Zomb": StatusZombie,
		"idle": StatusIdle,
		// Whitespace + case
		"  RUNNING  ": StatusRunning,
		// Empty + unknown
		"": StatusUnknown, "garbage": StatusUnknown,
	}
	for in, want := range cases {
		if got := NormalizeStatus(in); got != want {
			t.Fatalf("NormalizeStatus(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIsKernelThread(t *testing.T) {
	cases := []struct {
		name string
		ppid int32
		want bool
	}{
		{"[kworker/u:0]", 2, true},
		{"[ksoftirqd/0]", 2, true},
		{"sshd", 1, false},
		{"[fake-bracket]", 1, false}, // bracketed but ppid != 2 → user process
		{"kworker/u:0", 2, false},    // ppid=2 but no brackets → not a kthread
		{"", 2, false},
	}
	for _, tc := range cases {
		if got := IsKernelThread(tc.name, tc.ppid); got != tc.want {
			t.Fatalf("IsKernelThread(%q, %d) = %v, want %v",
				tc.name, tc.ppid, got, tc.want)
		}
	}
}

func TestTruncateCmdlineShortInputPassthrough(t *testing.T) {
	short := "/usr/bin/ssh -p 22 host.example"
	if got := TruncateCmdline(short); got != short {
		t.Fatalf("short input must passthrough, got %q", got)
	}
}

func TestTruncateCmdlineLongInputCapped(t *testing.T) {
	long := strings.Repeat("a", MaxCmdlineBytes*2)
	got := TruncateCmdline(long)
	if len(got) > MaxCmdlineBytes {
		t.Fatalf("truncated length %d exceeds cap %d", len(got), MaxCmdlineBytes)
	}
	if !strings.HasSuffix(got, "...") {
		t.Fatalf("truncated output must end with '...', got tail %q",
			got[len(got)-5:])
	}
}

func TestSortProcessesByPID(t *testing.T) {
	in := []Process{
		{PID: 4096}, {PID: 1}, {PID: 100}, {PID: 2},
	}
	SortProcesses(in)
	want := []int32{1, 2, 100, 4096}
	for i, p := range in {
		if p.PID != want[i] {
			t.Fatalf("pos %d: got pid %d want %d", i, p.PID, want[i])
		}
	}
}

func TestCollectEnumeratesAndSorts(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	src := &fakeSource{
		handles: []procHandle{
			&fakeHandle{
				pid:        2,
				ppid:       0,
				name:       "[kthreadd]",
				status:     "S",
				rss:        0,
				numThreads: 1,
			},
			&fakeHandle{
				pid:        100,
				ppid:       1,
				name:       "sshd",
				exe:        "/usr/sbin/sshd",
				cmdline:    "/usr/sbin/sshd -D",
				username:   "root",
				status:     "S",
				rss:        4096,
				vms:        16384,
				numThreads: 1,
				cwd:        "/",
				started:    now.Add(-time.Hour),
			},
			&fakeHandle{
				pid:        4242,
				ppid:       2, // looks like a kernel thread by ppid
				name:       "[kworker/u:0]",
				status:     "I",
				numThreads: 1,
			},
		},
	}
	c := &gopsutilCollector{src: src}

	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("want 3 processes, got %d", len(got))
	}
	// Sort by PID.
	if got[0].PID != 2 || got[1].PID != 100 || got[2].PID != 4242 {
		t.Fatalf("sort order: %d, %d, %d", got[0].PID, got[1].PID, got[2].PID)
	}
	// Kernel-thread detection.
	if !got[2].IsKernelThread {
		t.Fatalf("pid 4242 ([kworker/u:0], ppid=2) should be kernel thread")
	}
	if got[1].IsKernelThread {
		t.Fatalf("sshd should not be kernel thread")
	}
	// Status normalised.
	if got[1].Status != StatusSleeping {
		t.Fatalf("sshd status=%q, want sleeping", got[1].Status)
	}
	// Memory + cmdline fields populated.
	if got[1].RSSBytes != 4096 || got[1].VMSBytes != 16384 {
		t.Fatalf("memory lost: rss=%d vms=%d", got[1].RSSBytes, got[1].VMSBytes)
	}
	if got[1].Cmdline != "/usr/sbin/sshd -D" {
		t.Fatalf("cmdline lost: %q", got[1].Cmdline)
	}
	if got[1].Username != "root" {
		t.Fatalf("username lost: %q", got[1].Username)
	}
	if got[1].LastSeenAt.IsZero() || got[1].CollectedAt.IsZero() {
		t.Fatalf("timestamps not stamped: %+v", got[1])
	}
}

func TestCollectCapsAtMaxProcesses(t *testing.T) {
	src := &fakeSource{handles: make([]procHandle, MaxProcesses+50)}
	for i := range src.handles {
		src.handles[i] = &fakeHandle{pid: int32(i + 1), name: "x", status: "S"}
	}
	c := &gopsutilCollector{src: src}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != MaxProcesses {
		t.Fatalf("want %d processes (cap), got %d", MaxProcesses, len(got))
	}
}

func TestCollectPropagatesContextCancellation(t *testing.T) {
	src := &fakeSource{handles: []procHandle{
		&fakeHandle{pid: 1, name: "a", status: "S"},
		&fakeHandle{pid: 2, name: "b", status: "S"},
	}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancel
	c := &gopsutilCollector{src: src}
	_, err := c.Collect(ctx)
	if err == nil {
		t.Fatalf("expected context error, got nil")
	}
}

func TestPinnedStatusEnumStrings(t *testing.T) {
	// Sentinel: SQLite CHECK constraint depends on these exact strings.
	pairs := []struct{ got, want string }{
		{string(StatusRunning), "running"},
		{string(StatusSleeping), "sleeping"},
		{string(StatusIdle), "idle"},
		{string(StatusStopped), "stopped"},
		{string(StatusZombie), "zombie"},
		{string(StatusWait), "wait"},
		{string(StatusLock), "lock"},
		{string(StatusUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q (would break SQLite CHECK)",
				p.got, p.want)
		}
	}
}

// -- fakes ------------------------------------------------------------------

type fakeSource struct{ handles []procHandle }

func (f *fakeSource) List(_ context.Context) ([]procHandle, error) {
	return f.handles, nil
}

type fakeHandle struct {
	started    time.Time
	name       string
	exe        string
	cmdline    string
	username   string
	status     string
	cwd        string
	rss        uint64
	vms        uint64
	pid        int32
	ppid       int32
	numThreads int32
}

func (h *fakeHandle) PID() int32                                  { return h.pid }
func (h *fakeHandle) PPID(_ context.Context) (int32, error)       { return h.ppid, nil }
func (h *fakeHandle) Name(_ context.Context) (string, error)      { return h.name, nil }
func (h *fakeHandle) Exe(_ context.Context) (string, error)       { return h.exe, nil }
func (h *fakeHandle) Cmdline(_ context.Context) (string, error)   { return h.cmdline, nil }
func (h *fakeHandle) Username(_ context.Context) (string, error)  { return h.username, nil }
func (h *fakeHandle) Status(_ context.Context) ([]string, error)  { return []string{h.status}, nil }
func (h *fakeHandle) NumThreads(_ context.Context) (int32, error) { return h.numThreads, nil }

func (h *fakeHandle) MemoryInfo(_ context.Context) (uint64, uint64, bool) {
	if h.rss == 0 && h.vms == 0 {
		return 0, 0, false
	}
	return h.rss, h.vms, true
}

func (h *fakeHandle) CWD(_ context.Context) (string, error)          { return h.cwd, nil }
func (h *fakeHandle) CreatedAt(_ context.Context) (time.Time, error) { return h.started, nil }
