package users

import (
	"testing"
)

func TestPinnedEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(SourceLocal), "local"},
		{string(SourceAD), "ad"},
		{string(SourceLDAP), "ldap"},
		{string(SourceAzureAD), "azure-ad"},
		{string(SourceSSSD), "sssd"},
		{string(SourceOpenDirectory), "open-directory"},
		{string(SourceUnknown), "unknown"},
		{string(PasswordActive), "active"},
		{string(PasswordLocked), "locked"},
		{string(PasswordExpired), "expired"},
		{string(PasswordDisabled), "disabled"},
		{string(PasswordNoPassword), "no-password"},
		{string(PasswordUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q (breaks SQLite CHECK)",
				p.got, p.want)
		}
	}
}

func TestIsInteractiveShell(t *testing.T) {
	cases := map[string]bool{
		"/bin/bash":         true,
		"/bin/zsh":          true,
		"/usr/bin/fish":     true,
		"/sbin/nologin":     false,
		"/usr/sbin/nologin": false,
		"/bin/false":        false,
		"/usr/bin/false":    false,
		"/dev/null":         false,
		"":                  false,
	}
	for in, want := range cases {
		if got := IsInteractiveShell(in); got != want {
			t.Fatalf("IsInteractiveShell(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestAdminDetection(t *testing.T) {
	if !IsAdminUID("0") {
		t.Fatalf("uid 0 must be admin")
	}
	if IsAdminUID("1000") {
		t.Fatalf("uid 1000 must not be admin by uid alone")
	}
	for _, g := range []string{"wheel", "sudo", "admin", "root"} {
		if !IsAdminGroup(g) {
			t.Fatalf("group %q should grant admin", g)
		}
	}
	for _, g := range []string{"users", "docker", "video"} {
		if IsAdminGroup(g) {
			t.Fatalf("group %q should NOT grant admin", g)
		}
	}
}

func TestEncodeGroupsAlwaysJSONArray(t *testing.T) {
	if got := EncodeGroups(nil); got != "[]" {
		t.Fatalf("EncodeGroups(nil) = %q, want []", got)
	}
	if got := EncodeGroups([]string{}); got != "[]" {
		t.Fatalf("EncodeGroups(empty) = %q, want []", got)
	}
	got := EncodeGroups([]string{"sudo", "docker"})
	if got != `["sudo","docker"]` {
		t.Fatalf("EncodeGroups = %q", got)
	}
}

func TestSortUsersNumericUID(t *testing.T) {
	in := []User{
		{Source: SourceLocal, UID: "1000", Username: "alice"},
		{Source: SourceLocal, UID: "0", Username: "root"},
		{Source: SourceLocal, UID: "100", Username: "messagebus"},
		{Source: SourceAD, UID: "10000", Username: "domain-admin"},
	}
	SortUsers(in)
	// AD < local lexically, so ad rows come first, then local sorted by UID.
	want := []string{"domain-admin", "root", "messagebus", "alice"}
	for i, u := range in {
		if u.Username != want[i] {
			t.Fatalf("pos %d: got %q, want %q", i, u.Username, want[i])
		}
	}
}
