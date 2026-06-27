// Package scheduled enumerates scheduled jobs across Linux (cron +
// systemd timers), macOS (launchd), and Windows (Task Scheduler). Every
// row is a potential persistence mechanism (MITRE ATT&CK T1053), so the
// audit pipeline treats this collector's output as a first-class signal
// for behavioural baselining and drift detection.
//
// Every collector is **read-only** — it parses crontabs, lists systemd
// timers, walks launchd plists, queries Task Scheduler. It never
// installs, modifies, or removes jobs. Read-only is enforced by
// guideline 4.2 of the kite-collector project.
//
// Job rows feed the CWE/CAPEC + ATT&CK pipeline:
//
//   - T1053 (Scheduled Task/Job) — every row is a candidate persistence
//     primitive; cross-referenced against known LOLBins / GTFOBins.
//   - CWE-250 (Unnecessary Privileges) — run_as='root' / SYSTEM jobs
//     that don't need elevation.
//   - CWE-829 (Untrusted Functionality) — commands in /tmp, /var/tmp,
//     /dev/shm, %TEMP% are attacker drop locations.
//   - Drift — any new (cmd_hash, source_path) combo since last scan is
//     an unmanaged change worth alerting on.
package scheduled

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
)

// MaxJobs bounds per-scan output. A hardened server has 20-100 jobs; a
// pipeline-ridden CI runner has a few hundred. The 4096 ceiling protects
// the SQLite write path from misconfigured templates.
const MaxJobs = 4096

// Source classifies the scheduler that owns a job. Strings pinned to
// host_scheduled_jobs.source CHECK enum.
type Source string

const (
	SourceCron                 Source = "cron"
	SourceSystemdTimer         Source = "systemd-timer"
	SourceLaunchd              Source = "launchd"
	SourceWindowsTaskScheduler Source = "windows-task-scheduler"
	SourceAt                   Source = "at"
	SourceUnknown              Source = "unknown"
)

// ScheduleKind classifies the grammar of the Schedule string. Pinned to
// the host_scheduled_jobs.schedule_kind CHECK enum.
type ScheduleKind string

const (
	ScheduleCron5        ScheduleKind = "cron-5-field" // m h dom mon dow
	ScheduleCron7        ScheduleKind = "cron-7-field" // s m h dom mon dow year (Quartz / Windows)
	ScheduleOnCalendar   ScheduleKind = "systemd-oncalendar"
	ScheduleMonotonic    ScheduleKind = "systemd-monotonic"
	ScheduleTimeTrigger  ScheduleKind = "time-trigger"  // launchd StartCalendarInterval / Task Scheduler TimeTrigger
	ScheduleEventTrigger ScheduleKind = "event-trigger" // launchd WatchPaths / Task Scheduler EventTrigger
	ScheduleUnknown      ScheduleKind = "unknown"
)

// Job is the cross-source record produced by every collector. Mirrors
// the host_scheduled_jobs column shape.
type Job struct {
	Source       Source       `json:"source"`
	Name         string       `json:"name"`
	SourcePath   string       `json:"source_path"`
	Schedule     string       `json:"schedule,omitempty"`
	ScheduleKind ScheduleKind `json:"schedule_kind"`
	Command      string       `json:"command,omitempty"`
	RunAs        string       `json:"run_as,omitempty"`
	LastRunAt    string       `json:"last_run_at,omitempty"`
	NextRunAt    string       `json:"next_run_at,omitempty"`
	CmdHash      string       `json:"cmd_hash"`
	LastExit     int          `json:"last_exit,omitempty"`
	Enabled      bool         `json:"enabled"`
}

// Collector is the read-only contract every implementation satisfies.
type Collector interface {
	// Name returns a stable identifier for telemetry (e.g. "cron-files").
	Name() string
	// Collect enumerates scheduled jobs. Read-only. Returns empty slice
	// when no source is available — callers can fall through.
	Collect(ctx context.Context) ([]Job, error)
}

// HashCommand returns a sha256 fingerprint of a job's command so re-scans
// upsert cleanly. Excludes Schedule + LastRunAt — we want the hash to
// stay stable when only the cadence changes, so the audit pipeline can
// see "this job's *command* drifted" as a distinct event from "this
// job's *schedule* changed".
func HashCommand(cmd string) string {
	canon := strings.TrimSpace(cmd)
	sum := sha256.Sum256([]byte(canon))
	return hex.EncodeToString(sum[:])
}

// IsPrivilegedRunAs reports whether a run-as string represents an
// elevated identity across any platform. Used by the CWE-250 audit rule.
func IsPrivilegedRunAs(runAs string) bool {
	switch strings.ToLower(runAs) {
	case "root", "0", "system", "localsystem", "ntauthority\\system":
		return true
	}
	return false
}

// IsUntrustedCommandPath reports whether a command path falls in a
// directory that's a classic attacker drop zone. Used by the CWE-829
// audit rule. Matches the first whitespace-delimited token of cmd so
// arguments don't confuse the heuristic.
func IsUntrustedCommandPath(cmd string) bool {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return false
	}
	first := cmd
	if i := strings.IndexAny(cmd, " \t"); i > 0 {
		first = cmd[:i]
	}
	switch {
	case strings.HasPrefix(first, "/tmp/"),
		strings.HasPrefix(first, "/var/tmp/"),
		strings.HasPrefix(first, "/dev/shm/"),
		strings.HasPrefix(first, "/run/user/"):
		return true
	}
	// Windows %TEMP% is typically C:\Users\<user>\AppData\Local\Temp
	lower := strings.ToLower(first)
	if strings.Contains(lower, `\appdata\local\temp\`) ||
		strings.Contains(lower, `\windows\temp\`) {
		return true
	}
	return false
}

// SortJobs returns a deterministic ordering: by source, then source_path,
// then name. Useful for golden-file tests and stable diff output.
func SortJobs(js []Job) {
	sort.Slice(js, func(i, j int) bool {
		if js[i].Source != js[j].Source {
			return js[i].Source < js[j].Source
		}
		if js[i].SourcePath != js[j].SourcePath {
			return js[i].SourcePath < js[j].SourcePath
		}
		return js[i].Name < js[j].Name
	})
}
