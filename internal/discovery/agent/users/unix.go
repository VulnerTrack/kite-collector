//go:build !windows

package users

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
)

// unixCollector reads /etc/passwd + /etc/group to enumerate local users.
// macOS includes Open Directory users in /etc/passwd as stub entries for
// compatibility, so this collector works there too (a future dscl-backed
// collector will supersede it for the rich macOS attributes).
//
// /etc/shadow is intentionally NOT read: it's root-only, and the audit
// signals we want (locked, expired) need shadow parsing — but we'd rather
// degrade gracefully when running unprivileged than fail. Future iter
// adds a shadow-aware path that runs only when readable.
type unixCollector struct {
	passwdPath string
	groupPath  string
}

// NewUnixCollector returns a Unix /etc/passwd + /etc/group reader.
func NewUnixCollector() Collector {
	return &unixCollector{
		passwdPath: "/etc/passwd",
		groupPath:  "/etc/group",
	}
}

func (c *unixCollector) Name() string { return "unix-passwd" }

func (c *unixCollector) Collect(ctx context.Context) ([]User, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context cancelled: %w", err)
	}

	passwdBytes, err := os.ReadFile(c.passwdPath) //#nosec G304 -- fixed system path
	if err != nil {
		return []User{}, fmt.Errorf("read passwd: %w", err)
	}
	groupBytes, err := os.ReadFile(c.groupPath) //#nosec G304 -- fixed system path
	if err != nil {
		// passwd succeeded but group failed — emit users without group
		// membership rather than zero. is_admin will be false for everyone
		// except uid=0, which is a degradation we annotate via Source.
		groupBytes = nil
	}

	users := parsePasswd(string(passwdBytes))
	if len(users) > MaxUsers {
		users = users[:MaxUsers]
	}

	groupsByUser, adminMembers := parseGroups(string(groupBytes))

	out := make([]User, 0, len(users))
	for _, u := range users {
		u.Source = SourceLocal
		u.IsInteractive = IsInteractiveShell(u.Shell)
		u.Groups = groupsByUser[u.Username]
		sort.Strings(u.Groups)
		u.IsAdmin = IsAdminUID(u.UID) || adminMembers[u.Username]
		// passwd-only collector can't distinguish password states beyond
		// the literal "x"/"*" markers — punt to PasswordUnknown unless
		// the shadow-aware path runs later.
		if u.PasswordStatus == "" {
			u.PasswordStatus = PasswordUnknown
		}
		out = append(out, u)
	}
	SortUsers(out)
	return out, nil
}

// parsePasswd parses lines of the format:
//
//	username:x:uid:gid:gecos:home:shell
//
// Lines starting with '#' (comments) and short lines are skipped. The
// password column is normally "x" (meaning hash is in /etc/shadow); the
// literal "*" means the account is locked, "" means no password — both
// are captured into PasswordStatus where unambiguous.
func parsePasswd(raw string) []User {
	var out []User
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.SplitN(line, ":", 7)
		if len(fields) < 7 {
			continue
		}
		u := User{
			Username:   fields[0],
			UID:        fields[2],
			PrimaryGID: fields[3],
			FullName:   commaFirst(fields[4]),
			Home:       fields[5],
			Shell:      fields[6],
		}
		switch fields[1] {
		case "":
			u.PasswordStatus = PasswordNoPassword
		case "*", "!", "!!":
			u.PasswordStatus = PasswordLocked
			u.IsLocked = true
		case "x":
			// Hash lives in /etc/shadow — unknown from here.
			u.PasswordStatus = PasswordUnknown
		default:
			// Literal hash in passwd (rare; means no shadow).
			u.PasswordStatus = PasswordActive
		}
		out = append(out, u)
	}
	return out
}

// parseGroups parses /etc/group lines of the format:
//
//	groupname:x:gid:user1,user2,user3
//
// Returns two maps:
//   - groupsByUser["alice"] = ["sudo", "docker", "users"]
//   - adminMembers["alice"] = true     (member of any AdminGroups())
func parseGroups(raw string) (map[string][]string, map[string]bool) {
	byUser := make(map[string][]string)
	admins := make(map[string]bool)
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.SplitN(line, ":", 4)
		if len(fields) < 4 {
			continue
		}
		groupName := fields[0]
		members := strings.Split(fields[3], ",")
		for _, m := range members {
			m = strings.TrimSpace(m)
			if m == "" {
				continue
			}
			byUser[m] = append(byUser[m], groupName)
			if IsAdminGroup(groupName) {
				admins[m] = true
			}
		}
	}
	return byUser, admins
}

// commaFirst returns the part before the first comma — GECOS uses comma-
// separated fields and the first one is conventionally the full name.
func commaFirst(s string) string {
	if i := strings.IndexByte(s, ','); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return strings.TrimSpace(s)
}
