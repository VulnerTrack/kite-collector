package scheduled

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// WindowsPowerShellScript captures Get-ScheduledTask + Get-Scheduled-
// TaskInfo into one compact JSON array. We `[string]`-cast every value
// so PowerShell version drift (5.1 vs 7) doesn't change the wire
// format. Triggers are flattened — we only need the first one for the
// Schedule + ScheduleKind columns; the audit pipeline already has the
// trigger PSObject signature in raw_line for forensic queries.
const WindowsPowerShellScript = `
$ErrorActionPreference = 'Stop'
$tasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue)
$rows = @($tasks | ForEach-Object {
    $info = $null
    try { $info = Get-ScheduledTaskInfo -InputObject $_ -ErrorAction SilentlyContinue } catch {}
    $action = $null
    if ($_.Actions -and $_.Actions.Count -gt 0) { $action = $_.Actions[0] }
    $trigger = $null
    if ($_.Triggers -and $_.Triggers.Count -gt 0) { $trigger = $_.Triggers[0] }
    $triggerKind = if ($trigger) { [string]$trigger.CimClass.CimClassName } else { '' }
    $principal = $null
    if ($_.Principal) { $principal = $_.Principal }
    [pscustomobject]@{
        name          = [string]$_.TaskName
        task_path     = [string]$_.TaskPath
        state         = [string]$_.State
        run_as        = if ($principal) { [string]$principal.UserId } else { '' }
        run_level     = if ($principal) { [string]$principal.RunLevel } else { '' }
        execute       = if ($action) { [string]$action.Execute } else { '' }
        arguments     = if ($action) { [string]$action.Arguments } else { '' }
        working_dir   = if ($action) { [string]$action.WorkingDirectory } else { '' }
        trigger_kind  = $triggerKind
        trigger_cron  = if ($trigger -and $trigger.PSObject.Properties['StartBoundary']) { [string]$trigger.StartBoundary } else { '' }
        last_run_at   = if ($info -and $info.LastRunTime) { ([datetime]$info.LastRunTime).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') } else { $null }
        next_run_at   = if ($info -and $info.NextRunTime) { ([datetime]$info.NextRunTime).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') } else { $null }
        last_exit     = if ($info -and $info.LastTaskResult -ne $null) { [int]$info.LastTaskResult } else { 0 }
    }
})
$rows | ConvertTo-Json -Depth 4 -Compress
`

// rawWindowsTask mirrors the wire JSON shape.
type rawWindowsTask struct {
	Name        string      `json:"name"`
	TaskPath    string      `json:"task_path"`
	State       string      `json:"state"`
	RunAs       string      `json:"run_as"`
	RunLevel    string      `json:"run_level"`
	Execute     string      `json:"execute"`
	Arguments   string      `json:"arguments"`
	WorkingDir  string      `json:"working_dir"`
	TriggerKind string      `json:"trigger_kind"`
	TriggerCron string      `json:"trigger_cron"`
	LastRunAt   *string     `json:"last_run_at"`
	NextRunAt   *string     `json:"next_run_at"`
	LastExit    json.Number `json:"last_exit"`
}

// ParseWindowsPowerShellOutput converts the JSON blob the inline
// script emits into a []Job in the cross-platform shape.
//
// All returned jobs have Source=SourceWindowsTaskScheduler, the
// canonical ScheduleKind enum value, and a stable CmdHash. Singleton-
// object unwrap mirrors the windowscpumem / windowsnetwork pattern
// for hosts with exactly one task.
func ParseWindowsPowerShellOutput(data []byte) ([]Job, error) {
	trimmed := trimUTF8BOM(data)
	trimmed = []byte(strings.TrimSpace(string(trimmed)))
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("empty PowerShell output")
	}
	if trimmed[0] == '{' {
		trimmed = append(append([]byte{'['}, trimmed...), ']')
	}
	var raws []rawWindowsTask
	dec := json.NewDecoder(strings.NewReader(string(trimmed)))
	dec.UseNumber()
	if err := dec.Decode(&raws); err != nil {
		return nil, fmt.Errorf("decode windows tasks json: %w", err)
	}
	out := make([]Job, 0, len(raws))
	for _, r := range raws {
		name := strings.TrimSpace(r.Name)
		if name == "" {
			continue
		}
		cmd := joinExecuteArgs(r.Execute, r.Arguments)
		j := Job{
			Source:       SourceWindowsTaskScheduler,
			Name:         name,
			SourcePath:   joinTaskPath(r.TaskPath, name),
			Schedule:     strings.TrimSpace(r.TriggerCron),
			ScheduleKind: NormalizeWindowsTriggerKind(r.TriggerKind),
			Command:      cmd,
			RunAs:        NormalizeWindowsRunAs(r.RunAs),
			LastRunAt:    derefTime(r.LastRunAt),
			NextRunAt:    derefTime(r.NextRunAt),
			LastExit:     atoiNumber(r.LastExit),
			Enabled:      IsWindowsTaskEnabled(r.State),
			CmdHash:      HashCommand(cmd),
		}
		out = append(out, j)
	}
	return out, nil
}

// NormalizeWindowsTriggerKind maps the MSFT_Task<Foo>Trigger CIM
// class names to our pinned ScheduleKind enum.
//
// Time-driven triggers (Time/Daily/Weekly/Monthly/Idle/Session/
// SessionState) → ScheduleTimeTrigger.
// Event-driven (Boot/Logon/Registration/Event) → ScheduleEventTrigger.
func NormalizeWindowsTriggerKind(s string) ScheduleKind {
	k := strings.TrimSpace(s)
	switch k {
	case "MSFT_TaskTimeTrigger",
		"MSFT_TaskDailyTrigger",
		"MSFT_TaskWeeklyTrigger",
		"MSFT_TaskMonthlyTrigger",
		"MSFT_TaskMonthlyDOWTrigger",
		"MSFT_TaskIdleTrigger",
		"MSFT_TaskSessionStateChangeTrigger":
		return ScheduleTimeTrigger
	case "MSFT_TaskBootTrigger",
		"MSFT_TaskLogonTrigger",
		"MSFT_TaskRegistrationTrigger",
		"MSFT_TaskEventTrigger":
		return ScheduleEventTrigger
	}
	if k == "" {
		return ScheduleUnknown
	}
	return ScheduleUnknown
}

// IsWindowsTaskEnabled reports whether the Task Scheduler state means
// the task will fire on its trigger. "Disabled" returns false; every
// other state ("Ready","Running","Queued") returns true. The
// canonical PowerShell enum strings:
//
//	Unknown=0, Disabled=1, Queued=2, Ready=3, Running=4
func IsWindowsTaskEnabled(state string) bool {
	switch strings.ToLower(strings.TrimSpace(state)) {
	case "disabled", "unknown", "0", "1":
		return false
	}
	return true
}

// NormalizeWindowsRunAs translates well-known SIDs to their human-
// readable names so the IsPrivilegedRunAs audit rule fires across
// the union of Linux + Windows row shapes.
//
//	S-1-5-18 = LocalSystem
//	S-1-5-19 = LocalService
//	S-1-5-20 = NetworkService
func NormalizeWindowsRunAs(s string) string {
	v := strings.TrimSpace(s)
	switch v {
	case "S-1-5-18":
		return "LocalSystem"
	case "S-1-5-19":
		return "LocalService"
	case "S-1-5-20":
		return "NetworkService"
	}
	return v
}

// joinTaskPath produces "\Microsoft\Windows\UPnP\UPnPHostConfig"
// from the (`\Microsoft\Windows\UPnP\`, `UPnPHostConfig`) tuple
// Get-ScheduledTask emits — TaskPath always ends with a backslash.
func joinTaskPath(folder, name string) string {
	folder = strings.TrimSpace(folder)
	name = strings.TrimSpace(name)
	if folder == "" {
		return name
	}
	if strings.HasSuffix(folder, "\\") {
		return folder + name
	}
	return folder + "\\" + name
}

// joinExecuteArgs concatenates Execute + Arguments into a single
// command string the audit pipeline can hash + LOLBin-match against.
func joinExecuteArgs(exe, args string) string {
	exe = strings.TrimSpace(exe)
	args = strings.TrimSpace(args)
	switch {
	case exe == "" && args == "":
		return ""
	case args == "":
		return exe
	case exe == "":
		return args
	}
	return exe + " " + args
}

func derefTime(s *string) string {
	if s == nil {
		return ""
	}
	v := strings.TrimSpace(*s)
	if v == "" {
		return ""
	}
	if t, err := time.Parse(time.RFC3339, v); err == nil {
		return t.UTC().Format(time.RFC3339)
	}
	return v
}

func atoiNumber(n json.Number) int {
	if n == "" {
		return 0
	}
	if v, err := n.Int64(); err == nil {
		return int(v)
	}
	if i, err := strconv.Atoi(n.String()); err == nil {
		return i
	}
	return 0
}

func trimUTF8BOM(data []byte) []byte {
	if len(data) >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
		return data[3:]
	}
	return data
}
