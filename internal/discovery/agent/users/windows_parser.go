package users

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// WindowsPowerShellScript captures Get-LocalUser plus the membership
// of the local Administrators group into one compact JSON object with
// two arrays. Adminship is computed server-side via a SID set so the
// per-user lookup is O(1) on the Go side.
//
// We `[string]`-cast every value so PowerShell version drift doesn't
// change the wire format. Lives in a non-build-tagged file so the
// parser tests run on Linux CI.
const WindowsPowerShellScript = `
$ErrorActionPreference = 'Stop'
$users = @(Get-LocalUser -ErrorAction SilentlyContinue)

$adminSids = @{}
try {
    $members = @(Get-LocalGroupMember -Group Administrators -ErrorAction SilentlyContinue)
    foreach ($m in $members) {
        if ($m.SID -and $m.SID.Value) { $adminSids[[string]$m.SID.Value] = $true }
    }
} catch {}

function ToIso([object]$dt) {
    if ($null -eq $dt) { return $null }
    try { return (([datetime]$dt).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')) } catch { return $null }
}

$rows = @($users | ForEach-Object {
    $sid = [string]$_.SID.Value
    [pscustomobject]@{
        username                 = [string]$_.Name
        sid                      = $sid
        full_name                = [string]$_.FullName
        description              = [string]$_.Description
        enabled                  = [bool]$_.Enabled
        password_required        = [bool]$_.PasswordRequired
        password_last_set        = ToIso($_.PasswordLastSet)
        password_expires         = ToIso($_.PasswordExpires)
        last_logon               = ToIso($_.LastLogon)
        account_expires          = ToIso($_.AccountExpires)
        password_never_expires   = ($_.PasswordExpires -eq $null)
        user_may_change_password = [bool]$_.UserMayChangePassword
        is_admin                 = $adminSids.ContainsKey($sid)
    }
})
$rows | ConvertTo-Json -Depth 3 -Compress
`

// rawWindowsUser mirrors the wire JSON shape.
type rawWindowsUser struct {
	AccountExpires        *string `json:"account_expires"`
	PasswordLastSet       *string `json:"password_last_set"`
	PasswordExpires       *string `json:"password_expires"`
	LastLogon             *string `json:"last_logon"`
	SID                   string  `json:"sid"`
	FullName              string  `json:"full_name"`
	Description           string  `json:"description"`
	Username              string  `json:"username"`
	Enabled               bool    `json:"enabled"`
	PasswordRequired      bool    `json:"password_required"`
	PasswordNeverExpires  bool    `json:"password_never_expires"`
	UserMayChangePassword bool    `json:"user_may_change_password"`
	IsAdmin               bool    `json:"is_admin"`
}

// ParseWindowsPowerShellOutput converts the JSON blob into []User in
// the cross-platform shape. All returned users have Source=SourceLocal
// (the SAM is the local store; AD-synced accounts surface elsewhere).
func ParseWindowsPowerShellOutput(data []byte) ([]User, error) {
	trimmed := trimUTF8BOM(data)
	trimmed = []byte(strings.TrimSpace(string(trimmed)))
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("empty PowerShell output")
	}
	// Singleton-object unwrap: a single-user host can emit one object.
	if trimmed[0] == '{' {
		trimmed = append(append([]byte{'['}, trimmed...), ']')
	}
	var raws []rawWindowsUser
	dec := json.NewDecoder(strings.NewReader(string(trimmed)))
	dec.UseNumber()
	if err := dec.Decode(&raws); err != nil {
		return nil, fmt.Errorf("decode windows users json: %w", err)
	}
	out := make([]User, 0, len(raws))
	for _, r := range raws {
		name := strings.TrimSpace(r.Username)
		if name == "" {
			continue
		}
		groups := []string{}
		if r.IsAdmin {
			groups = []string{"Administrators"}
		}
		u := User{
			Username:       name,
			UID:            strings.TrimSpace(r.SID),
			FullName:       strings.TrimSpace(r.FullName),
			Source:         SourceLocal,
			PasswordStatus: WindowsPasswordStatus(r),
			LastLoginAt:    deref(r.LastLogon),
			Groups:         groups,
			IsAdmin:        r.IsAdmin,
			// Every non-disabled SAM account can log in interactively.
			IsInteractive:   r.Enabled,
			IsLocked:        !r.Enabled,
			PasswordAgeDays: PasswordAgeDays(deref(r.PasswordLastSet)),
		}
		out = append(out, u)
		if len(out) >= MaxUsers {
			break
		}
	}
	return out, nil
}

// WindowsPasswordStatus maps a SAM record to our pinned PasswordStatus
// enum. Order matters: disabled wins over no-password wins over
// expired wins over active.
func WindowsPasswordStatus(r rawWindowsUser) PasswordStatus {
	if !r.Enabled {
		return PasswordDisabled
	}
	if !r.PasswordRequired {
		return PasswordNoPassword
	}
	if r.PasswordExpires != nil {
		if t, err := time.Parse(time.RFC3339, deref(r.PasswordExpires)); err == nil {
			if t.Before(time.Now()) {
				return PasswordExpired
			}
		}
	}
	return PasswordActive
}

// PasswordAgeDays computes (today - password_last_set) in days. Returns
// 0 when the timestamp is missing / unparseable so the column never
// goes negative or NULL.
func PasswordAgeDays(lastSet string) int {
	if lastSet == "" {
		return 0
	}
	t, err := time.Parse(time.RFC3339, lastSet)
	if err != nil {
		return 0
	}
	age := time.Since(t)
	if age < 0 {
		return 0
	}
	return int(age.Hours() / 24)
}

// IsWellKnownWindowsAdminName reports whether the username matches one
// of the canonical Windows admin account names. Used by the audit
// pipeline to suppress alerts on the OS-shipped Administrator account
// while still surfacing custom admin users.
func IsWellKnownWindowsAdminName(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "administrator", "defaultaccount", "wdagutilityaccount", "guest":
		return true
	}
	return false
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return strings.TrimSpace(*s)
}

func trimUTF8BOM(data []byte) []byte {
	if len(data) >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
		return data[3:]
	}
	return data
}
