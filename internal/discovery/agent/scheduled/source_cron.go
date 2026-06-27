package scheduled

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// cronCollector reads /etc/crontab and /etc/cron.d/*. We deliberately
// skip /var/spool/cron/<user>/* and ~/.crontab: both are owner-only
// (mode 600) so the unprivileged agent gets EACCES, and shelling out
// to `crontab -l -u <user>` per system user multiplies syscalls.
// A follow-up iter can wire those when we run with appropriate caps.
type cronCollector struct {
	readFile      func(string) ([]byte, error)
	readDir       func(string) ([]os.DirEntry, error)
	systemCrontab string
	dropInDir     string
}

// NewCronCollector returns a cron-files-based Collector.
func NewCronCollector() Collector {
	return &cronCollector{
		systemCrontab: "/etc/crontab",
		dropInDir:     "/etc/cron.d",
		readFile:      func(p string) ([]byte, error) { return os.ReadFile(p) }, //#nosec G304 -- fixed system paths only
		readDir:       func(p string) ([]os.DirEntry, error) { return os.ReadDir(p) },
	}
}

func (c *cronCollector) Name() string { return "cron-files" }

func (c *cronCollector) Collect(ctx context.Context) ([]Job, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context cancelled: %w", err)
	}
	var out []Job

	// /etc/crontab is the system-wide table; format includes a user column.
	if data, err := c.readFile(c.systemCrontab); err == nil {
		out = append(out, parseCronTab(string(data), c.systemCrontab, true)...)
	}

	// /etc/cron.d/* are drop-in files; same 7-column format as /etc/crontab.
	entries, err := c.readDir(c.dropInDir)
	if err == nil {
		for _, e := range entries {
			if e.IsDir() || strings.HasPrefix(e.Name(), ".") {
				continue
			}
			full := filepath.Join(c.dropInDir, e.Name())
			data, ferr := c.readFile(full)
			if ferr != nil {
				continue
			}
			out = append(out, parseCronTab(string(data), full, true)...)
		}
	}

	if len(out) > MaxJobs {
		out = out[:MaxJobs]
	}
	SortJobs(out)
	return out, nil
}

// parseCronTab parses /etc/crontab + /etc/cron.d/* style files. When
// hasUserColumn is true (always, in current scope), the line format is:
//
//	minute hour day-of-month month day-of-week user command
//
// Comments (#) and `KEY=value` env lines are skipped. Time-aliases like
// `@reboot` / `@daily` / `@hourly` are captured into ScheduleKind even
// though they're not 5-field. A job name is synthesised from the
// hash-truncated command + path basename so two `@daily backup.sh` jobs
// in different files don't collide.
func parseCronTab(raw, sourcePath string, hasUserColumn bool) []Job {
	var out []Job
	base := filepath.Base(sourcePath)
	for lineNo, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Skip env-var-style declarations (KEY=value, no space before =).
		if !strings.HasPrefix(line, "@") {
			if eq := strings.IndexByte(line, '='); eq > 0 {
				// Check there's no space before the '=' — that distinguishes
				// `PATH=/usr/bin` (env) from `* * * * * user cmd =something` (job).
				if !strings.Contains(line[:eq], " ") && !strings.Contains(line[:eq], "\t") {
					continue
				}
			}
		}

		schedule, kind, rest, ok := splitCronSchedule(line)
		if !ok {
			continue
		}

		var runAs, command string
		if hasUserColumn {
			fields := strings.Fields(rest)
			if len(fields) < 2 {
				continue
			}
			runAs = fields[0]
			command = strings.TrimSpace(strings.TrimPrefix(rest, fields[0]))
		} else {
			command = strings.TrimSpace(rest)
		}
		if command == "" {
			continue
		}

		out = append(out, Job{
			Source:       SourceCron,
			Name:         fmt.Sprintf("%s:%d", base, lineNo+1),
			SourcePath:   sourcePath,
			Schedule:     schedule,
			ScheduleKind: kind,
			Command:      command,
			RunAs:        runAs,
			Enabled:      true,
			CmdHash:      HashCommand(command),
		})
	}
	return out
}

// splitCronSchedule pulls the schedule prefix off a cron line and
// returns (scheduleString, kind, restOfLine, ok). Handles:
//   - `@reboot/@daily/@hourly/@yearly/@annually/@monthly/@weekly`
//   - Standard 5-field expressions
//
// 7-field (Quartz) and step values (*/5) parse as Cron5 — we don't
// validate the cron semantics, we just classify the shape.
func splitCronSchedule(line string) (string, ScheduleKind, string, bool) {
	if strings.HasPrefix(line, "@") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return "", ScheduleUnknown, "", false
		}
		return fields[0], ScheduleTimeTrigger,
			strings.TrimSpace(strings.TrimPrefix(line, fields[0])), true
	}
	fields := strings.Fields(line)
	if len(fields) < 6 { // 5 schedule + at least 1 trailing token (user OR cmd)
		return "", ScheduleUnknown, "", false
	}
	schedule := strings.Join(fields[:5], " ")
	rest := strings.TrimSpace(strings.Join(fields[5:], " "))
	return schedule, ScheduleCron5, rest, true
}
