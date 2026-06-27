package users

import (
	"strings"
	"testing"
	"time"
)

func TestWindowsPasswordStatusDisabledWins(t *testing.T) {
	if WindowsPasswordStatus(rawWindowsUser{Enabled: false, PasswordRequired: true}) != PasswordDisabled {
		t.Fatal("disabled must win")
	}
}

func TestWindowsPasswordStatusNoPassword(t *testing.T) {
	if WindowsPasswordStatus(rawWindowsUser{Enabled: true, PasswordRequired: false}) != PasswordNoPassword {
		t.Fatal("no password required → no-password")
	}
}

func TestWindowsPasswordStatusExpired(t *testing.T) {
	past := "2020-01-01T00:00:00Z"
	if WindowsPasswordStatus(rawWindowsUser{
		Enabled: true, PasswordRequired: true, PasswordExpires: &past,
	}) != PasswordExpired {
		t.Fatal("past expiry must flag expired")
	}
}

func TestWindowsPasswordStatusActive(t *testing.T) {
	future := time.Now().Add(90 * 24 * time.Hour).UTC().Format(time.RFC3339)
	if WindowsPasswordStatus(rawWindowsUser{
		Enabled: true, PasswordRequired: true, PasswordExpires: &future,
	}) != PasswordActive {
		t.Fatal("future expiry must remain active")
	}
}

func TestPasswordAgeDays(t *testing.T) {
	thirtyDaysAgo := time.Now().Add(-30 * 24 * time.Hour).UTC().Format(time.RFC3339)
	if got := PasswordAgeDays(thirtyDaysAgo); got < 29 || got > 31 {
		t.Fatalf("got %d, want ~30", got)
	}
	if got := PasswordAgeDays(""); got != 0 {
		t.Fatalf("empty must be 0, got %d", got)
	}
	if got := PasswordAgeDays("garbage"); got != 0 {
		t.Fatalf("garbage must be 0, got %d", got)
	}
	// Future timestamp (clock skew) clamps to 0.
	future := time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)
	if got := PasswordAgeDays(future); got != 0 {
		t.Fatalf("future timestamp must clamp to 0, got %d", got)
	}
}

func TestIsWellKnownWindowsAdminName(t *testing.T) {
	for _, n := range []string{
		"Administrator", "administrator", "DefaultAccount",
		"WDAGUtilityAccount", "Guest",
	} {
		if !IsWellKnownWindowsAdminName(n) {
			t.Fatalf("%q must be well-known", n)
		}
	}
	for _, n := range []string{"alice", "bob", "svc-deploy", ""} {
		if IsWellKnownWindowsAdminName(n) {
			t.Fatalf("%q must NOT be well-known", n)
		}
	}
}

// -- ParseWindowsPowerShellOutput typical fixture ----------------------

func TestParseWindowsPowerShellOutputTypical(t *testing.T) {
	future := time.Now().Add(90 * 24 * time.Hour).UTC().Format(time.RFC3339)
	lastSet := time.Now().Add(-15 * 24 * time.Hour).UTC().Format(time.RFC3339)
	lastLogon := time.Now().Add(-2 * time.Hour).UTC().Format(time.RFC3339)

	body := []byte(`[
        {
            "username": "Administrator",
            "sid": "S-1-5-21-1234-5678-9012-500",
            "full_name": "",
            "description": "Built-in account",
            "enabled": true,
            "password_required": true,
            "password_last_set": "` + lastSet + `",
            "password_expires": null,
            "last_logon": "` + lastLogon + `",
            "account_expires": null,
            "password_never_expires": true,
            "user_may_change_password": true,
            "is_admin": true
        },
        {
            "username": "alice",
            "sid": "S-1-5-21-1234-5678-9012-1001",
            "full_name": "Alice Example",
            "enabled": true,
            "password_required": true,
            "password_last_set": "` + lastSet + `",
            "password_expires": "` + future + `",
            "last_logon": "` + lastLogon + `",
            "is_admin": false
        },
        {
            "username": "Guest",
            "sid": "S-1-5-21-1234-5678-9012-501",
            "enabled": false,
            "password_required": false,
            "is_admin": false
        }
    ]`)

	got, err := ParseWindowsPowerShellOutput(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("users=%d", len(got))
	}

	admin := got[0]
	if admin.UID != "S-1-5-21-1234-5678-9012-500" {
		t.Fatalf("admin SID=%q", admin.UID)
	}
	if !admin.IsAdmin {
		t.Fatal("Administrator must flag is_admin")
	}
	if len(admin.Groups) != 1 || admin.Groups[0] != "Administrators" {
		t.Fatalf("admin groups=%v", admin.Groups)
	}
	if admin.PasswordStatus != PasswordActive {
		t.Fatalf("admin password_status=%q", admin.PasswordStatus)
	}
	if admin.PasswordAgeDays < 14 || admin.PasswordAgeDays > 16 {
		t.Fatalf("password_age_days=%d (want ~15)", admin.PasswordAgeDays)
	}
	if !admin.IsInteractive {
		t.Fatal("enabled SAM account must flag interactive")
	}
	if admin.IsLocked {
		t.Fatal("enabled must NOT be locked")
	}

	alice := got[1]
	if alice.IsAdmin {
		t.Fatal("alice must NOT flag admin")
	}
	if alice.PasswordStatus != PasswordActive {
		t.Fatalf("alice password_status=%q", alice.PasswordStatus)
	}

	guest := got[2]
	if guest.PasswordStatus != PasswordDisabled {
		t.Fatalf("disabled guest password_status=%q", guest.PasswordStatus)
	}
	if !guest.IsLocked {
		t.Fatal("disabled must flag locked")
	}
	if guest.IsInteractive {
		t.Fatal("disabled must NOT be interactive")
	}
}

// -- ParseWindowsPowerShellOutput singleton-object unwrap --------------

func TestParseWindowsPowerShellOutputSingletonUnwrap(t *testing.T) {
	body := []byte(`{
        "username": "Solo",
        "sid": "S-1-5-21-1-1-1-1000",
        "enabled": true,
        "password_required": true,
        "is_admin": false
    }`)
	got, err := ParseWindowsPowerShellOutput(body)
	if err != nil {
		t.Fatalf("singleton parse: %v", err)
	}
	if len(got) != 1 || got[0].Username != "Solo" {
		t.Fatalf("singleton unwrap broken: %+v", got)
	}
}

// -- ParseWindowsPowerShellOutput edge cases ---------------------------

func TestParseWindowsPowerShellOutputSkipEmptyUsername(t *testing.T) {
	body := []byte(`[
        {"username":"","sid":"S","enabled":true,"password_required":true},
        {"username":"real","sid":"S-1","enabled":true,"password_required":true}
    ]`)
	got, err := ParseWindowsPowerShellOutput(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Username != "real" {
		t.Fatalf("empty-username row must drop: %+v", got)
	}
}

func TestParseWindowsPowerShellOutputNoPasswordFlags(t *testing.T) {
	body := []byte(`[{
        "username":"weak","sid":"S-2",
        "enabled":true,"password_required":false,"is_admin":false
    }]`)
	got, err := ParseWindowsPowerShellOutput(body)
	if err != nil {
		t.Fatal(err)
	}
	if got[0].PasswordStatus != PasswordNoPassword {
		t.Fatalf("weak password_status=%q", got[0].PasswordStatus)
	}
}

// -- error paths -------------------------------------------------------

func TestParseWindowsPowerShellOutputEmptyError(t *testing.T) {
	if _, err := ParseWindowsPowerShellOutput(nil); err == nil {
		t.Fatal("empty must error")
	}
}

func TestParseWindowsPowerShellOutputMalformedError(t *testing.T) {
	if _, err := ParseWindowsPowerShellOutput([]byte("not json")); err == nil {
		t.Fatal("malformed must error")
	}
}

func TestParseWindowsPowerShellOutputBOMTolerated(t *testing.T) {
	body := append([]byte{0xEF, 0xBB, 0xBF}, []byte(
		`[{"username":"x","sid":"S","enabled":true,"password_required":true}]`,
	)...)
	if _, err := ParseWindowsPowerShellOutput(body); err != nil {
		t.Fatalf("BOM payload must parse: %v", err)
	}
}

// -- script shape spot-check ------------------------------------------

func TestWindowsPowerShellScriptShape(t *testing.T) {
	for _, must := range []string{
		"Get-LocalUser",
		"Get-LocalGroupMember",
		"Administrators",
		"is_admin",
		"ConvertTo-Json",
	} {
		if !strings.Contains(WindowsPowerShellScript, must) {
			t.Fatalf("WindowsPowerShellScript missing %q", must)
		}
	}
}
