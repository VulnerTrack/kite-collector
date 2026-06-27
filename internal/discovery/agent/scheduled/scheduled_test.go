package scheduled

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"testing"
)

func TestPinnedEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(SourceCron), "cron"},
		{string(SourceSystemdTimer), "systemd-timer"},
		{string(SourceLaunchd), "launchd"},
		{string(SourceWindowsTaskScheduler), "windows-task-scheduler"},
		{string(SourceAt), "at"},
		{string(SourceUnknown), "unknown"},
		{string(ScheduleCron5), "cron-5-field"},
		{string(ScheduleCron7), "cron-7-field"},
		{string(ScheduleOnCalendar), "systemd-oncalendar"},
		{string(ScheduleMonotonic), "systemd-monotonic"},
		{string(ScheduleTimeTrigger), "time-trigger"},
		{string(ScheduleEventTrigger), "event-trigger"},
		{string(ScheduleUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q (breaks SQLite CHECK)",
				p.got, p.want)
		}
	}
}

func TestHashCommandDeterministic(t *testing.T) {
	a := HashCommand("/usr/bin/backup.sh")
	b := HashCommand("/usr/bin/backup.sh")
	if a != b {
		t.Fatalf("not deterministic: %q != %q", a, b)
	}
	if len(a) != 64 {
		t.Fatalf("want sha256 hex (64 chars), got %d", len(a))
	}
	if HashCommand("/usr/bin/backup.sh") == HashCommand("/usr/bin/restore.sh") {
		t.Fatalf("different commands must hash differently")
	}
	if HashCommand("  /usr/bin/backup.sh  ") != HashCommand("/usr/bin/backup.sh") {
		t.Fatalf("must trim whitespace before hashing")
	}
}

func TestIsPrivilegedRunAs(t *testing.T) {
	cases := map[string]bool{
		"root":                true,
		"ROOT":                true,
		"0":                   true,
		"system":              true,
		"SYSTEM":              true,
		"LocalSystem":         true,
		"ntauthority\\system": true,
		"alice":               false,
		"www-data":            false,
		"":                    false,
	}
	for in, want := range cases {
		if got := IsPrivilegedRunAs(in); got != want {
			t.Fatalf("IsPrivilegedRunAs(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestIsUntrustedCommandPath(t *testing.T) {
	cases := map[string]bool{
		"/tmp/payload.sh":         true,
		"/tmp/payload.sh --quiet": true,
		"/var/tmp/.beacon":        true,
		"/dev/shm/exec":           true,
		"/run/user/1000/socket":   true,
		"/usr/bin/curl":           false,
		"/usr/local/bin/safe":     false,
		"":                        false,
		`C:\Users\alice\AppData\Local\Temp\bad.exe`: true,
		`C:\Windows\Temp\evil.ps1`:                  true,
		`C:\Program Files\Safe\app.exe`:             false,
	}
	for in, want := range cases {
		if got := IsUntrustedCommandPath(in); got != want {
			t.Fatalf("IsUntrustedCommandPath(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestSortJobsDeterministic(t *testing.T) {
	in := []Job{
		{Source: SourceCron, SourcePath: "/etc/cron.d/zeta", Name: "z"},
		{Source: SourceCron, SourcePath: "/etc/crontab", Name: "b"},
		{Source: SourceCron, SourcePath: "/etc/crontab", Name: "a"},
		{Source: SourceSystemdTimer, SourcePath: "/etc/systemd/system/foo.timer", Name: "foo.timer"},
	}
	SortJobs(in)
	// Sort key: source → source_path → name.
	// SourceCron < SourceSystemdTimer (lexical).
	// Within SourceCron: /etc/cron.d/zeta < /etc/crontab (lexical: '.' < 't').
	// So z comes first, then a + b (sorted by name within /etc/crontab).
	want := []string{"z", "a", "b", "foo.timer"}
	for i, j := range in {
		if j.Name != want[i] {
			t.Fatalf("pos %d: got %q want %q (path=%q)",
				i, j.Name, want[i], j.SourcePath)
		}
	}
}

func TestSplitCronScheduleStandard(t *testing.T) {
	s, kind, rest, ok := splitCronSchedule("*/5 * * * * root /usr/bin/foo --flag")
	if !ok {
		t.Fatal("split failed")
	}
	if s != "*/5 * * * *" {
		t.Fatalf("schedule=%q", s)
	}
	if kind != ScheduleCron5 {
		t.Fatalf("kind=%q", kind)
	}
	if rest != "root /usr/bin/foo --flag" {
		t.Fatalf("rest=%q", rest)
	}
}

func TestSplitCronScheduleAlias(t *testing.T) {
	s, kind, rest, ok := splitCronSchedule("@daily root /usr/bin/backup.sh")
	if !ok {
		t.Fatal("split failed")
	}
	if s != "@daily" {
		t.Fatalf("schedule=%q", s)
	}
	if kind != ScheduleTimeTrigger {
		t.Fatalf("kind=%q", kind)
	}
	if rest != "root /usr/bin/backup.sh" {
		t.Fatalf("rest=%q", rest)
	}
}

func TestSplitCronScheduleTooFewFields(t *testing.T) {
	_, _, _, ok := splitCronSchedule("* * * * *")
	if ok {
		t.Fatal("must require at least 6 tokens (schedule + user/cmd)")
	}
}

func TestParseCronTabRealisticFixture(t *testing.T) {
	raw := `# /etc/crontab: system-wide crontab
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

17 * * * * root cd / && run-parts --report /etc/cron.hourly
25 6 * * * root test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
@daily root /usr/local/sbin/cleanup-tmp.sh
*/5 * * * * alice /usr/bin/check-status.sh
# disabled by hand
malformed garbage line
`
	jobs := parseCronTab(raw, "/etc/crontab", true)
	if len(jobs) != 4 {
		t.Fatalf("want 4 jobs, got %d: %+v", len(jobs), jobs)
	}

	// 1st job: hourly run-parts as root.
	hourly := jobs[0]
	if hourly.Source != SourceCron {
		t.Fatalf("source=%q", hourly.Source)
	}
	if hourly.RunAs != "root" {
		t.Fatalf("run_as=%q", hourly.RunAs)
	}
	if hourly.SourcePath != "/etc/crontab" {
		t.Fatalf("source_path=%q", hourly.SourcePath)
	}
	if hourly.Schedule != "17 * * * *" {
		t.Fatalf("schedule=%q", hourly.Schedule)
	}
	if !IsPrivilegedRunAs(hourly.RunAs) {
		t.Fatalf("hourly job should be flagged as privileged")
	}

	// 3rd: @daily alias.
	daily := jobs[2]
	if daily.Schedule != "@daily" {
		t.Fatalf("daily schedule=%q", daily.Schedule)
	}
	if daily.ScheduleKind != ScheduleTimeTrigger {
		t.Fatalf("daily kind=%q, want time-trigger", daily.ScheduleKind)
	}

	// 4th: */5 as alice (not privileged).
	check := jobs[3]
	if check.RunAs != "alice" {
		t.Fatalf("check run_as=%q", check.RunAs)
	}
	if IsPrivilegedRunAs(check.RunAs) {
		t.Fatalf("alice must not be flagged as privileged")
	}

	// Every job has a cmd_hash.
	for i, j := range jobs {
		if j.CmdHash == "" {
			t.Fatalf("job %d missing cmd_hash: %+v", i, j)
		}
	}
}

func TestParseCronTabSkipsEnvVars(t *testing.T) {
	raw := `SHELL=/bin/sh
PATH=/usr/bin:/bin
MAILTO=admin@example.com
* * * * * root /bin/true
`
	jobs := parseCronTab(raw, "/etc/crontab", true)
	if len(jobs) != 1 {
		t.Fatalf("want 1 job (env vars must be skipped), got %d", len(jobs))
	}
}

func TestCronCollectorEndToEnd(t *testing.T) {
	systemRaw := `* * * * * root /bin/true
*/5 * * * * alice /usr/bin/check.sh
`
	dropInBackup := `0 2 * * * backup /opt/scripts/snapshot.sh
`
	c := &cronCollector{
		systemCrontab: "/etc/crontab",
		dropInDir:     "/etc/cron.d",
		readFile: func(p string) ([]byte, error) {
			switch p {
			case "/etc/crontab":
				return []byte(systemRaw), nil
			case "/etc/cron.d/backup":
				return []byte(dropInBackup), nil
			}
			return nil, errors.New("not found")
		},
		readDir: func(p string) ([]os.DirEntry, error) {
			if p != "/etc/cron.d" {
				return nil, errors.New("not found")
			}
			return []os.DirEntry{
				fakeDirEntry{name: "backup", isDir: false},
				fakeDirEntry{name: ".hidden", isDir: false}, // must be skipped
				fakeDirEntry{name: "subdir", isDir: true},   // must be skipped
			}, nil
		},
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("want 3 jobs (2 system + 1 drop-in, hidden+dir skipped), got %d",
			len(got))
	}
	// SortJobs orders by source → path → name. /etc/cron.d/backup < /etc/crontab.
	if got[0].SourcePath != "/etc/cron.d/backup" {
		t.Fatalf("first job source_path=%q (sort order broken)", got[0].SourcePath)
	}
	if got[0].RunAs != "backup" {
		t.Fatalf("drop-in run_as=%q", got[0].RunAs)
	}
}

func TestCronCollectorTolerantOfMissingSystemCrontab(t *testing.T) {
	c := &cronCollector{
		systemCrontab: "/etc/crontab",
		dropInDir:     "/etc/cron.d",
		readFile:      func(string) ([]byte, error) { return nil, fs.ErrNotExist },
		readDir:       func(string) ([]os.DirEntry, error) { return nil, fs.ErrNotExist },
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("missing files must not error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want empty, got %d", len(got))
	}
}

// -- systemd --------------------------------------------------------------

func TestParseSystemctlTimersArray(t *testing.T) {
	raw := `[
  {"unit":"daily-backup.timer","activates":"daily-backup.service","next":"Tue 2026-06-24 02:00:00 UTC","last":"Mon 2026-06-23 02:00:00 UTC"},
  {"unit":"cleanup.timer","activates":"cleanup.service","next":"-","last":"-"}
]`
	ts, err := parseSystemctlTimers([]byte(raw))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(ts) != 2 {
		t.Fatalf("want 2 timers, got %d", len(ts))
	}
	if ts[0].Unit != "daily-backup.timer" || ts[0].Activates != "daily-backup.service" {
		t.Fatalf("first timer wrong: %+v", ts[0])
	}
}

func TestTimerToJobNormalisesPlaceholders(t *testing.T) {
	j := timerToJob(systemctlTimer{
		Unit: "cleanup.timer", Activates: "cleanup.service",
		Last: "-", Next: "n/a",
	})
	if j.LastRunAt != "" {
		t.Fatalf(`"-" must become ""`)
	}
	if j.NextRunAt != "" {
		t.Fatalf(`"n/a" must become ""`)
	}
	if j.Source != SourceSystemdTimer {
		t.Fatalf("source=%q", j.Source)
	}
	if j.Command != "cleanup.service" {
		t.Fatalf("command should default to activates: %q", j.Command)
	}
}

func TestSystemdTimerCollectorMissingBinary(t *testing.T) {
	c := &systemdTimerCollector{
		lookPath: func(string) (string, error) { return "", errors.New("nope") },
		run: func(context.Context, string, ...string) ([]byte, error) {
			t.Fatalf("run must not be invoked when systemctl missing")
			return nil, nil
		},
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("missing systemctl must not error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want empty, got %d", len(got))
	}
}

// -- chain ----------------------------------------------------------------

func TestChainCollectorSkipsErrors(t *testing.T) {
	good := stubCollector{out: []Job{{Source: SourceCron, Name: "x", CmdHash: "h"}}}
	bad := stubCollector{err: errors.New("daemon down")}
	chain := &chainCollector{collectors: []Collector{good, bad, good}}

	got, err := chain.Collect(context.Background())
	if err != nil {
		t.Fatalf("chain Collect: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 (good × 2), got %d", len(got))
	}
}

// -- helpers --------------------------------------------------------------

type stubCollector struct {
	err error
	out []Job
}

func (s stubCollector) Name() string { return "stub" }
func (s stubCollector) Collect(_ context.Context) ([]Job, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.out, nil
}

type fakeDirEntry struct {
	name  string
	isDir bool
}

func (f fakeDirEntry) Name() string               { return f.name }
func (f fakeDirEntry) IsDir() bool                { return f.isDir }
func (f fakeDirEntry) Type() fs.FileMode          { return 0 }
func (f fakeDirEntry) Info() (fs.FileInfo, error) { return nil, nil }
