//go:build !windows

package users

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

const samplePasswd = `# Comment line
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sshd:x:113:65534::/run/sshd:/usr/sbin/nologin
alice:x:1000:1000:Alice Wonderland,,,:/home/alice:/bin/bash
bob:!:1001:1001:Bob B,,,:/home/bob:/bin/zsh
charlie::1002:1002:No Password Charlie:/home/charlie:/bin/bash
malformed-line-no-colons
`

const sampleGroup = `# group file
root:x:0:
daemon:x:1:
wheel:x:10:root,alice
sudo:x:27:alice,bob
docker:x:998:alice
users:x:100:alice,bob,charlie
admin:x:101:bob
`

func TestParsePasswdAllShapes(t *testing.T) {
	users := parsePasswd(samplePasswd)
	if len(users) != 7 {
		t.Fatalf("want 7 users, got %d", len(users))
	}
	by := map[string]User{}
	for _, u := range users {
		by[u.Username] = u
	}

	root := by["root"]
	if root.UID != "0" {
		t.Fatalf("root uid lost: %q", root.UID)
	}
	if root.Shell != "/bin/bash" {
		t.Fatalf("root shell lost: %q", root.Shell)
	}
	// password "x" → unknown
	if root.PasswordStatus != PasswordUnknown {
		t.Fatalf("root password status=%q, want unknown", root.PasswordStatus)
	}

	alice := by["alice"]
	if alice.FullName != "Alice Wonderland" {
		t.Fatalf("alice full name not from GECOS[0]: %q", alice.FullName)
	}
	if alice.Home != "/home/alice" {
		t.Fatalf("alice home: %q", alice.Home)
	}

	bob := by["bob"]
	if bob.PasswordStatus != PasswordLocked {
		t.Fatalf("bob (passwd='!') should be locked, got %q", bob.PasswordStatus)
	}
	if !bob.IsLocked {
		t.Fatalf("bob.IsLocked should be true")
	}

	charlie := by["charlie"]
	if charlie.PasswordStatus != PasswordNoPassword {
		t.Fatalf("charlie (passwd='') should be no-password, got %q", charlie.PasswordStatus)
	}
}

func TestParseGroupsAdminDetection(t *testing.T) {
	byUser, admins := parseGroups(sampleGroup)

	// alice is in wheel + sudo + docker + users (admin via wheel + sudo).
	if !admins["alice"] {
		t.Fatalf("alice should be admin (member of wheel + sudo)")
	}
	if len(byUser["alice"]) != 4 {
		t.Fatalf("alice groups=%v, want 4", byUser["alice"])
	}

	// bob is in sudo + admin + users (admin via sudo + admin).
	if !admins["bob"] {
		t.Fatalf("bob should be admin (member of sudo + admin)")
	}

	// charlie is only in users (not admin).
	if admins["charlie"] {
		t.Fatalf("charlie should NOT be admin")
	}
}

func TestUnixCollectorEndToEnd(t *testing.T) {
	dir := t.TempDir()
	passwd := filepath.Join(dir, "passwd")
	group := filepath.Join(dir, "group")
	if err := os.WriteFile(passwd, []byte(samplePasswd), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(group, []byte(sampleGroup), 0o644); err != nil {
		t.Fatal(err)
	}

	c := &unixCollector{passwdPath: passwd, groupPath: group}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 7 {
		t.Fatalf("want 7 users, got %d", len(got))
	}

	by := map[string]User{}
	for _, u := range got {
		by[u.Username] = u
	}

	root := by["root"]
	if !root.IsAdmin {
		t.Fatalf("root should be admin (uid=0)")
	}
	if !root.IsInteractive {
		t.Fatalf("root with /bin/bash should be interactive")
	}
	if root.Source != SourceLocal {
		t.Fatalf("root source=%q, want local", root.Source)
	}

	alice := by["alice"]
	if !alice.IsAdmin {
		t.Fatalf("alice should be admin (wheel + sudo)")
	}
	wantGroups := []string{"docker", "sudo", "users", "wheel"} // sorted
	if len(alice.Groups) != 4 {
		t.Fatalf("alice groups=%v, want 4 sorted: %v", alice.Groups, wantGroups)
	}
	for i, g := range alice.Groups {
		if g != wantGroups[i] {
			t.Fatalf("alice.Groups[%d]=%q, want %q (must be sorted)",
				i, g, wantGroups[i])
		}
	}

	daemon := by["daemon"]
	if daemon.IsInteractive {
		t.Fatalf("daemon with /usr/sbin/nologin must NOT be interactive")
	}
	if daemon.IsAdmin {
		t.Fatalf("daemon must not be admin")
	}
}

func TestUnixCollectorMissingPasswdGracefulError(t *testing.T) {
	c := &unixCollector{
		passwdPath: "/does/not/exist",
		groupPath:  "/does/not/exist",
	}
	got, err := c.Collect(context.Background())
	if err == nil {
		t.Fatalf("missing passwd must error")
	}
	if len(got) != 0 {
		t.Fatalf("want empty on error, got %d", len(got))
	}
}

func TestUnixCollectorMissingGroupSoftFails(t *testing.T) {
	dir := t.TempDir()
	passwd := filepath.Join(dir, "passwd")
	if err := os.WriteFile(passwd, []byte(samplePasswd), 0o644); err != nil {
		t.Fatal(err)
	}
	c := &unixCollector{
		passwdPath: passwd,
		groupPath:  "/does/not/exist",
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("missing group must NOT error (soft-fail): %v", err)
	}
	if len(got) != 7 {
		t.Fatalf("want 7 users (passwd-only), got %d", len(got))
	}
	// Without group file, only uid=0 should be admin.
	adminCount := 0
	for _, u := range got {
		if u.IsAdmin {
			adminCount++
		}
	}
	if adminCount != 1 {
		t.Fatalf("want exactly 1 admin (root by uid), got %d", adminCount)
	}
}

func TestCommaFirstHandlesPlainName(t *testing.T) {
	cases := map[string]string{
		"":                       "",
		"Alice":                  "Alice",
		"Alice,,,":               "Alice",
		"Alice Wonderland,,,":    "Alice Wonderland",
		"  Spaced  ,extra,stuff": "Spaced",
	}
	for in, want := range cases {
		if got := commaFirst(in); got != want {
			t.Fatalf("commaFirst(%q) = %q, want %q", in, got, want)
		}
	}
}
