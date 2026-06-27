package services

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// WindowsPowerShellScript is the inline script the Windows collector
// runs. It pulls Win32_Service into a compact JSON array — one object
// per service. We `[string]`-cast every value so PowerShell version
// drift doesn't change the wire format.
//
// Lives in a non-build-tagged file so the parser tests can run on
// Linux CI: only the actual `powershell.exe` invocation in windows.go
// needs the build tag.
const WindowsPowerShellScript = `
$ErrorActionPreference = 'Stop'
$svcs = @(Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue)
$rows = @($svcs | ForEach-Object {
    [pscustomobject]@{
        name         = [string]$_.Name
        display_name = [string]$_.DisplayName
        description  = [string]$_.Description
        path_name    = [string]$_.PathName
        start_mode   = [string]$_.StartMode
        state        = [string]$_.State
        start_name   = [string]$_.StartName
        process_id   = if ($_.ProcessId -ne $null) { [int]$_.ProcessId } else { 0 }
        exit_code    = if ($_.ExitCode -ne $null) { [int]$_.ExitCode } else { 0 }
    }
})
$rows | ConvertTo-Json -Depth 3 -Compress
`

// rawWindowsService mirrors the wire JSON shape. Wrap StartName in
// pointer-string so we can distinguish absent (= LocalSystem default)
// from explicit-empty.
type rawWindowsService struct {
	Name        string      `json:"name"`
	DisplayName string      `json:"display_name"`
	Description string      `json:"description"`
	PathName    string      `json:"path_name"`
	StartMode   string      `json:"start_mode"`
	State       string      `json:"state"`
	StartName   string      `json:"start_name"`
	ProcessID   json.Number `json:"process_id"`
	ExitCode    json.Number `json:"exit_code"`
}

// ParseWindowsPowerShellOutput converts the JSON blob the inline
// script emits into a []Service in the cross-platform shape. Single-
// service hosts (rare but possible on Server Core) sometimes arrive
// as a JSON object instead of a 1-element array — we unwrap so the
// caller's loop iterates uniformly.
//
// All returned services have Manager=ManagerWindowsSCM, the canonical
// StartMode/State enum values, and CollectedAt/LastSeenAt left at
// zero for the caller to fill (the collector's responsibility, not
// the parser's).
func ParseWindowsPowerShellOutput(data []byte) ([]Service, error) {
	trimmed := trimWindowsBOM(data)
	trimmed = []byte(strings.TrimSpace(string(trimmed)))
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("empty PowerShell output")
	}
	// Singleton-object unwrap: a single-service host can emit one
	// object instead of an array.
	if trimmed[0] == '{' {
		trimmed = append(append([]byte{'['}, trimmed...), ']')
	}
	var raws []rawWindowsService
	dec := json.NewDecoder(strings.NewReader(string(trimmed)))
	dec.UseNumber()
	if err := dec.Decode(&raws); err != nil {
		return nil, fmt.Errorf("decode windows services json: %w", err)
	}
	out := make([]Service, 0, len(raws))
	for _, r := range raws {
		if strings.TrimSpace(r.Name) == "" {
			continue
		}
		out = append(out, Service{
			Manager:     ManagerWindowsSCM,
			Name:        strings.TrimSpace(r.Name),
			DisplayName: strings.TrimSpace(r.DisplayName),
			Description: strings.TrimSpace(r.Description),
			BinaryPath:  strings.TrimSpace(r.PathName),
			RunAs:       strings.TrimSpace(r.StartName),
			State:       NormalizeWindowsState(r.State),
			StartMode:   NormalizeWindowsStartMode(r.StartMode),
			PID:         atoiNumber(r.ProcessID),
			ExitCode:    atoiNumber(r.ExitCode),
		})
	}
	return out, nil
}

// NormalizeWindowsState maps the Win32_Service.State string into our
// pinned State enum. The SCM emits "Running" / "Stopped" / "Paused"
// / "Start Pending" / "Stop Pending" / "Continue Pending" /
// "Pause Pending". The audit-relevant question is "is this service
// doing useful work right now?", so "Paused" collapses to
// StateStopped (the service isn't responding to requests); pending
// states map to StateActivating / StateDeactivating.
func NormalizeWindowsState(s string) State {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "running":
		return StateRunning
	case "stopped", "paused":
		return StateStopped
	case "start pending", "continue pending":
		return StateActivating
	case "stop pending", "pause pending":
		return StateDeactivating
	}
	return StateUnknown
}

// NormalizeWindowsStartMode maps the Win32_Service.StartMode string
// into our pinned StartMode enum. The SCM emits "Boot", "System",
// "Auto", "Manual", "Disabled" — drivers use Boot/System, services
// use Auto/Manual/Disabled.
func NormalizeWindowsStartMode(s string) StartMode {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "auto":
		return StartAuto
	case "manual":
		return StartManual
	case "disabled":
		return StartDisabled
	case "boot":
		return StartBoot
	case "system":
		return StartSystem
	}
	return StartUnknown
}

// StampWindowsServices sets CollectedAt + LastSeenAt to `now` on
// every service. Caller invokes this after ParseWindowsPowerShell-
// Output so the parser stays time-independent (easier to unit-test).
func StampWindowsServices(svcs []Service, now time.Time) {
	for i := range svcs {
		svcs[i].CollectedAt = now
		svcs[i].LastSeenAt = now
	}
}

// atoiNumber is a tiny json.Number → int helper that tolerates the
// PowerShell-emits-empty-string-for-null case.
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

func trimWindowsBOM(data []byte) []byte {
	if len(data) >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
		return data[3:]
	}
	return data
}
