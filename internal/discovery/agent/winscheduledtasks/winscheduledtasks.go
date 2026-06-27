// Package winscheduledtasks inventories Windows scheduled tasks
// from the on-disk XML cache at C:\Windows\System32\Tasks\. The
// Task Scheduler stores every registered task as both a registry
// entry (HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule\
// TaskCache) AND as a single XML file under this directory; we
// parse the file side because the audit pipeline can hash it for
// drift detection without spinning up any Windows COM call.
//
// File-based discovery is the deliberate design choice — every
// Windows host has these files, every parser reads them the same
// way (UTF-16 LE BOM + XML), and the on-disk view survives the
// Task Scheduler service being down or tampered with.
//
// Headline finding shapes (MITRE T1053.005 — Scheduled Task,
// T1564 — Hide Artifacts, T1546.012 — Image File Execution
// Options Injection):
//
//   - Task under a non-Microsoft directory + Principal SYSTEM +
//     LogonTrigger/BootTrigger + Hidden=true = textbook implant.
//     The audit pipeline alerts verbatim on the union.
//   - Action Command path under C:\Users\Public, C:\Windows\Temp,
//     or any %TEMP% expansion = world-writable execution target
//     (CWE-426 + T1574.005 ServiceFileWeakPermissions adjacent).
//   - RunLevel=HighestAvailable on a third-party task = will run
//     with the user's max token, a common UAC-bypass primitive on
//     UAC-protected admin accounts.
//
// Read-only by intent — we walk the Tasks directory only, never
// invoke schtasks.exe / Register-ScheduledTask. (Project guideline
// 4.2.)
package winscheduledtasks

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"sort"
	"strings"
)

// MaxTasks bounds per-scan output. A loaded Windows host carries
// 200-600 tasks; the 8192 ceiling covers heavily-customised
// enterprise endpoints without bloating SQLite writes.
const MaxTasks = 8192

// MicrosoftTaskRoots is the curated set of directory prefixes whose
// children are considered OS-managed. Tasks under these never flag
// the third-party persistence finding.
func MicrosoftTaskRoots() []string {
	return []string{
		`\Microsoft\`,
		`\Microsoft`,
	}
}

// WorldWritableDirRoots is the curated set of directory prefixes
// that any local user can write into. Action Command values under
// these trigger the world-writable finding.
func WorldWritableDirRoots() []string {
	return []string{
		`c:\users\public\`,
		`c:\users\public`,
		`c:\windows\temp\`,
		`c:\windows\temp`,
		`c:\temp\`,
		`c:\temp`,
		`%temp%\`,
		`%tmp%\`,
		`%public%\`,
		`%userprofile%\appdata\local\temp\`,
		`c:\programdata\temp\`,
	}
}

// Task mirrors host_scheduled_tasks_xml's column shape exactly.
type Task struct {
	FilePath                      string   `json:"file_path"`
	FileHash                      string   `json:"file_hash"`
	TaskPath                      string   `json:"task_path"`
	TaskName                      string   `json:"task_name"`
	Author                        string   `json:"author,omitempty"`
	Description                   string   `json:"description,omitempty"`
	RegistrationDate              string   `json:"registration_date,omitempty"`
	URI                           string   `json:"uri,omitempty"`
	PrincipalUserID               string   `json:"principal_user_id,omitempty"`
	PrincipalGroupID              string   `json:"principal_group_id,omitempty"`
	RunLevel                      string   `json:"run_level,omitempty"`
	LogonType                     string   `json:"logon_type,omitempty"`
	Triggers                      []string `json:"triggers,omitempty"`
	Actions                       []Action `json:"actions,omitempty"`
	ActionCount                   int      `json:"action_count,omitempty"`
	TriggerCount                  int      `json:"trigger_count,omitempty"`
	IsMicrosoftManaged            bool     `json:"is_microsoft_managed"`
	IsEnabled                     bool     `json:"is_enabled"`
	IsHidden                      bool     `json:"is_hidden"`
	RunsAsSystem                  bool     `json:"runs_as_system"`
	RunsAsHighest                 bool     `json:"runs_as_highest"`
	HasLogonTrigger               bool     `json:"has_logon_trigger"`
	HasBootTrigger                bool     `json:"has_boot_trigger"`
	HasIdleTrigger                bool     `json:"has_idle_trigger"`
	HasEventTrigger               bool     `json:"has_event_trigger"`
	IsCommandInWorldWritableDir   bool     `json:"is_command_in_world_writable_dir"`
	IsThirdPartySystemPersistence bool     `json:"is_third_party_system_persistence"`
}

// Action mirrors one <Exec> element. The richer <ComHandler>,
// <SendEmail>, <ShowMessage> action types appear too rarely on
// modern Windows to warrant their own fields; we stringify them
// into Action.RawElement so audit queries can still grep.
type Action struct {
	Kind             string `json:"kind"` // "Exec" / "ComHandler" / "SendEmail" / "ShowMessage" / "Unknown"
	Command          string `json:"command,omitempty"`
	Arguments        string `json:"arguments,omitempty"`
	WorkingDirectory string `json:"working_directory,omitempty"`
}

// Collector is the read-only contract every implementation satisfies.
type Collector interface {
	Name() string
	Collect(ctx context.Context) ([]Task, error)
}

// HashContents returns the SHA-256 hex of a task XML body.
func HashContents(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// IsMicrosoftManagedPath reports whether a task's logical path
// (e.g. `\Microsoft\Windows\AppID\PolicyConverter`) sits under one of
// the curated Microsoft-owned roots.
func IsMicrosoftManagedPath(taskPath string) bool {
	p := strings.ToLower(strings.TrimSpace(taskPath))
	for _, root := range MicrosoftTaskRoots() {
		if strings.HasPrefix(p, strings.ToLower(root)) {
			return true
		}
	}
	return false
}

// IsSystemPrincipal reports whether a UserId value resolves to the
// LocalSystem account — either the well-known SID `S-1-5-18` or one
// of its named aliases.
func IsSystemPrincipal(userID string) bool {
	v := strings.ToLower(strings.TrimSpace(userID))
	switch v {
	case "s-1-5-18", "localsystem", "system", "nt authority\\system":
		return true
	}
	return false
}

// IsHighestRunLevel reports whether RunLevel asks for the user's
// highest available token. This is the explicit UAC-bypass primitive
// when paired with a non-SYSTEM Principal on UAC-protected accounts.
func IsHighestRunLevel(level string) bool {
	return strings.EqualFold(strings.TrimSpace(level), "HighestAvailable")
}

// IsCommandInWorldWritableDir reports whether an action Command path
// roots under one of the curated world-writable directories. Empty
// command returns false. Comparison is case-insensitive (Windows
// paths are case-insensitive by definition).
func IsCommandInWorldWritableDir(command string) bool {
	v := strings.ToLower(strings.TrimSpace(command))
	if v == "" {
		return false
	}
	// Strip surrounding quotes — `"C:\Path\foo.exe"` style is common.
	v = strings.Trim(v, `"`)
	cleaned := filepath.ToSlash(v)
	for _, root := range WorldWritableDirRoots() {
		r := strings.ToLower(filepath.ToSlash(root))
		if strings.HasPrefix(cleaned, r) {
			return true
		}
	}
	return false
}

// IsBoolTrue maps the XML grammar's true/false content. Empty input
// returns false — matching Task Scheduler's "absent element = off"
// semantics.
func IsBoolTrue(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "true", "1":
		return true
	}
	return false
}

// AnnotateSecurity sets the derived booleans on a Task that has its
// raw fields populated.
func AnnotateSecurity(t *Task) {
	t.IsMicrosoftManaged = IsMicrosoftManagedPath(t.TaskPath)
	t.RunsAsSystem = IsSystemPrincipal(t.PrincipalUserID)
	t.RunsAsHighest = IsHighestRunLevel(t.RunLevel)
	t.IsCommandInWorldWritableDir = false
	for _, a := range t.Actions {
		if IsCommandInWorldWritableDir(a.Command) {
			t.IsCommandInWorldWritableDir = true
			break
		}
	}
	t.HasLogonTrigger = containsToken(t.Triggers, "LogonTrigger")
	t.HasBootTrigger = containsToken(t.Triggers, "BootTrigger")
	t.HasIdleTrigger = containsToken(t.Triggers, "IdleTrigger")
	t.HasEventTrigger = containsToken(t.Triggers, "EventTrigger")
	t.TriggerCount = len(t.Triggers)
	t.ActionCount = len(t.Actions)
	t.IsThirdPartySystemPersistence = !t.IsMicrosoftManaged &&
		t.RunsAsSystem && t.IsHidden &&
		(t.HasLogonTrigger || t.HasBootTrigger)
}

func containsToken(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// SortTasks returns a deterministic ordering by task path.
func SortTasks(ts []Task) {
	sort.Slice(ts, func(i, j int) bool {
		return ts[i].TaskPath < ts[j].TaskPath
	})
}

// EncodeStringList returns a JSON array suitable for the *_json
// columns. Empty input always emits "[]" so the column is never NULL.
func EncodeStringList(ss []string) string {
	if len(ss) == 0 {
		return "[]"
	}
	b, err := json.Marshal(ss)
	if err != nil {
		return "[]"
	}
	return string(b)
}

// EncodeActions returns the canonical JSON shape for the actions_json
// column.
func EncodeActions(as []Action) string {
	if len(as) == 0 {
		return "[]"
	}
	b, err := json.Marshal(as)
	if err != nil {
		return "[]"
	}
	return string(b)
}
