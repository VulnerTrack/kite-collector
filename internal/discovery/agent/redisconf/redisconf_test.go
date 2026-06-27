package redisconf

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPinnedRoleStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(RoleServer), "server"},
		{string(RoleSentinel), "sentinel"},
		{string(RoleCluster), "cluster"},
		{string(RoleUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("role drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestHashContentsDeterministic(t *testing.T) {
	a := HashContents([]byte("bind 127.0.0.1\n"))
	b := HashContents([]byte("bind 127.0.0.1\n"))
	if a != b || len(a) != 64 {
		t.Fatalf("a=%q b=%q", a, b)
	}
}

func TestIsLoopbackAddress(t *testing.T) {
	hit := []string{"127.0.0.1", "::1", "localhost", "127.0.0.2"}
	for _, a := range hit {
		if !IsLoopbackAddress(a) {
			t.Fatalf("%q must flag loopback", a)
		}
	}
	miss := []string{"0.0.0.0", "::", "10.0.0.5", "192.168.1.1", "fe80::1", ""}
	for _, a := range miss {
		if IsLoopbackAddress(a) {
			t.Fatalf("%q must NOT flag loopback", a)
		}
	}
}

func TestIsExternalBind(t *testing.T) {
	if !IsExternalBind([]string{"0.0.0.0"}) {
		t.Fatal("0.0.0.0 must flag external")
	}
	if !IsExternalBind([]string{"127.0.0.1", "10.0.0.5"}) {
		t.Fatal("mixed loopback+ext must flag external")
	}
	if IsExternalBind([]string{"127.0.0.1", "::1"}) {
		t.Fatal("loopback-only must NOT flag external")
	}
}

func TestIsLoopbackOnly(t *testing.T) {
	if !IsLoopbackOnly([]string{"127.0.0.1", "::1"}) {
		t.Fatal("all-loopback must flag")
	}
	if IsLoopbackOnly([]string{"127.0.0.1", "10.0.0.5"}) {
		t.Fatal("mixed must NOT flag loopback-only")
	}
	if IsLoopbackOnly(nil) {
		t.Fatal("empty (no bind = listen all) must NOT flag loopback-only")
	}
}

func TestIsWeakPassword(t *testing.T) {
	for _, p := range []string{"foobared", "FOOBARED", "redis", "admin", "short"} {
		if !IsWeakPassword(p) {
			t.Fatalf("%q must flag weak", p)
		}
	}
	for _, p := range []string{
		"correct-horse-battery-staple-9!", // > MinPasswordLength, not stock
		"aB3$xY7@vZ1!qP9&",                // 16 chars
		"",                                // empty = not set, not "weak"
	} {
		if IsWeakPassword(p) {
			t.Fatalf("%q must NOT flag weak", p)
		}
	}
}

func TestHasDangerousUnrenamed(t *testing.T) {
	// ACL gating disables this finding wholesale.
	if HasDangerousUnrenamed(nil, true) {
		t.Fatal("ACL enabled must short-circuit to false")
	}
	// Nothing renamed: every dangerous command at default → flag.
	if !HasDangerousUnrenamed(nil, false) {
		t.Fatal("nothing renamed = flag")
	}
	// All disabled → don't flag.
	disabledAll := []RenamedCommand{
		{From: "CONFIG", To: ""},
		{From: "EVAL", To: ""},
		{From: "MODULE", To: ""},
		{From: "DEBUG", To: ""},
		{From: "FLUSHALL", To: ""},
		{From: "FLUSHDB", To: ""},
		{From: "SHUTDOWN", To: ""},
		{From: "SLAVEOF", To: ""},
		{From: "REPLICAOF", To: ""},
	}
	if HasDangerousUnrenamed(disabledAll, false) {
		t.Fatal("all disabled must NOT flag")
	}
	// Renamed to a custom value (not disabled) → still flag, because
	// it's just security through obscurity.
	renamed := []RenamedCommand{
		{From: "CONFIG", To: "secret-name"},
	}
	if !HasDangerousUnrenamed(renamed, false) {
		t.Fatal("rename ≠ disable; must still flag")
	}
}

func TestNormalizeRole(t *testing.T) {
	cases := map[string]ConfigRole{
		"/etc/redis/redis.conf":          RoleServer,
		"/etc/redis-server.conf":         RoleServer,
		"/etc/redis/redis-sentinel.conf": RoleSentinel,
		"/etc/redis/cluster-node.conf":   RoleCluster,
		"/etc/random.conf":               RoleUnknown,
	}
	for in, want := range cases {
		if got := NormalizeRole(in); got != want {
			t.Fatalf("NormalizeRole(%q)=%q want %q", in, got, want)
		}
	}
}

func TestEncodeStringList(t *testing.T) {
	if EncodeStringList(nil) != "[]" {
		t.Fatal("nil")
	}
	if got := EncodeStringList([]string{"127.0.0.1"}); got != `["127.0.0.1"]` {
		t.Fatalf("got %q", got)
	}
}

func TestEncodeRenamedCommands(t *testing.T) {
	if EncodeRenamedCommands(nil) != "[]" {
		t.Fatal("nil")
	}
	got := EncodeRenamedCommands([]RenamedCommand{{From: "CONFIG", To: ""}})
	if !strings.Contains(got, `"from":"CONFIG"`) {
		t.Fatalf("got %q", got)
	}
}

// -- Parse + AnnotateSecurity end-to-end ------------------------------

func TestParseTypicalHardened(t *testing.T) {
	body := []byte(`# typical hardened redis.conf
bind 127.0.0.1 ::1
port 6379
tls-port 6380
protected-mode yes
requirepass "Tr0ub4dor&3-Tr0ub4dor&3-Tr0ub4dor"
aclfile /etc/redis/users.acl
rename-command CONFIG ""
rename-command EVAL ""
rename-command MODULE ""
rename-command DEBUG ""
rename-command FLUSHALL ""
rename-command FLUSHDB ""
rename-command SHUTDOWN ""
rename-command SLAVEOF ""
rename-command REPLICAOF ""
dir /var/lib/redis
dbfilename dump.rdb
`)
	got := Parse(body, "/etc/redis/redis.conf")
	if got.ConfigRole != RoleServer {
		t.Fatalf("role=%q", got.ConfigRole)
	}
	if got.Port != 6379 || got.TLSPort != 6380 {
		t.Fatalf("ports: %d / %d", got.Port, got.TLSPort)
	}
	if !got.IsBoundToLoopbackOnly {
		t.Fatalf("loopback-only must flag: %+v", got.BindAddresses)
	}
	if got.IsExternallyBound {
		t.Fatal("must NOT flag externally bound")
	}
	if !got.RequirepassPresent {
		t.Fatal("requirepass set must flag present")
	}
	if got.IsPasswordWeak {
		t.Fatal("strong password must NOT flag weak")
	}
	if !got.IsACLEnabled {
		t.Fatal("aclfile must flag ACL enabled")
	}
	if got.HasDangerousUnrenamedCommands {
		t.Fatal("ACL gating must short-circuit dangerous-unrenamed")
	}
	if !got.IsTLSEnabled {
		t.Fatal("tls-port > 0 must flag TLS")
	}
	if got.IsUnauthenticatedWorldExposed {
		t.Fatal("hardened must NOT flag world-exposed")
	}
}

func TestParseWorstCase(t *testing.T) {
	body := []byte(`# worst-case: bound to 0.0.0.0, no auth, protected mode off
bind 0.0.0.0
port 6379
protected-mode no
`)
	got := Parse(body, "/etc/redis/redis.conf")
	if !got.IsExternallyBound {
		t.Fatal("0.0.0.0 must flag external")
	}
	if got.IsBoundToLoopbackOnly {
		t.Fatal("0.0.0.0 must NOT flag loopback-only")
	}
	if got.RequirepassPresent {
		t.Fatal("no requirepass must NOT flag present")
	}
	if got.IsProtectedModeEnabled {
		t.Fatal("protected-mode no must propagate")
	}
	if !got.IsUnauthenticatedWorldExposed {
		t.Fatalf("worst-case must flag world-exposed: %+v", got)
	}
	if !got.HasDangerousUnrenamedCommands {
		t.Fatal("no rename-command + no ACL must flag")
	}
	if !got.IsTLSDisabledWithExternalBind {
		t.Fatal("no tls-port + external bind must flag")
	}
}

func TestParseNoBindIsExternal(t *testing.T) {
	// Redis with no `bind` listens on every interface.
	body := []byte("port 6379\n")
	got := Parse(body, "/etc/redis/redis.conf")
	if !got.IsExternallyBound {
		t.Fatal("no bind = listen all = external")
	}
}

func TestParseWeakPasswordFlag(t *testing.T) {
	body := []byte(`bind 0.0.0.0
requirepass foobared
`)
	got := Parse(body, "x")
	if !got.RequirepassPresent || !got.IsPasswordWeak {
		t.Fatalf("flags: %+v", got)
	}
	// Even with a weak password, requirepass IS present, so
	// is_unauthenticated_world_exposed should be false. The audit
	// pipeline catches weak-pass separately via is_password_weak.
	if got.IsUnauthenticatedWorldExposed {
		t.Fatal("requirepass present must clear world-exposed flag")
	}
}

func TestParseRenameCommandSyntax(t *testing.T) {
	body := []byte(`rename-command CONFIG ""
rename-command flushall ""
rename-command MODULE custom-loader
`)
	got := Parse(body, "x")
	if len(got.RenamedCommands) != 3 {
		t.Fatalf("renamed=%d", len(got.RenamedCommands))
	}
	for _, r := range got.RenamedCommands {
		if r.From != strings.ToUpper(r.From) {
			t.Fatalf("From must be uppercased: %+v", r)
		}
	}
}

func TestParseQuotedStringValues(t *testing.T) {
	body := []byte(`dir "/var/lib/redis with space"
requirepass "pass with space"
`)
	got := Parse(body, "x")
	if got.Dir != "/var/lib/redis with space" {
		t.Fatalf("dir=%q", got.Dir)
	}
	if got.Requirepass != "pass with space" {
		t.Fatalf("requirepass=%q", got.Requirepass)
	}
}

func TestParseSkipsCommentsAndBlanks(t *testing.T) {
	body := []byte("# top\n\n   # indented\n\nport 1234\n")
	got := Parse(body, "x")
	if got.Port != 1234 {
		t.Fatalf("port=%d", got.Port)
	}
}

func TestParseIncludesAreCaptured(t *testing.T) {
	body := []byte("include /etc/redis/local.conf\ninclude relative.conf\n")
	got := Parse(body, "/etc/redis/redis.conf")
	if len(got.Includes) != 2 {
		t.Fatalf("includes=%v", got.Includes)
	}
}

func TestParseProtectedModeDefaultsTrue(t *testing.T) {
	// When the directive is missing, protected-mode is true per the
	// upstream redis-server default.
	got := Parse([]byte("bind 127.0.0.1\n"), "x")
	if !got.IsProtectedModeEnabled {
		t.Fatal("default protected-mode=yes must hold")
	}
}

// -- Requirepass is not persisted in JSON ----------------------------

func TestRequirepassNotInJSON(t *testing.T) {
	c := Config{Requirepass: "totally-secret-value"}
	// Hand off to the json encoder via EncodeStringList? No — verify
	// via the struct tag: a json.Marshal on Config must not include
	// the value. Use a direct json.Marshal.
	got := mustJSON(t, c)
	if strings.Contains(got, "totally-secret-value") {
		t.Fatalf("requirepass leaked to JSON: %s", got)
	}
}

// -- collector end-to-end -------------------------------------------

func TestFileCollectorWalksAndFollowsIncludes(t *testing.T) {
	tmp := t.TempDir()
	main := filepath.Join(tmp, "redis.conf")
	local := filepath.Join(tmp, "local.conf")
	must(t, os.WriteFile(main, []byte("bind 0.0.0.0\ninclude local.conf\n"), 0o600))
	must(t, os.WriteFile(local, []byte("requirepass thisone-is-sixteen!\n"), 0o600))

	c := &fileCollector{
		seeds:    []string{main, "/nope-missing.conf"},
		readFile: os.ReadFile,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 (main + include), got %d: %+v", len(got), got)
	}
	// Find the include row by file path.
	var locCfg Config
	for _, cfg := range got {
		if cfg.FilePath == local {
			locCfg = cfg
		}
	}
	if locCfg.FilePath == "" {
		t.Fatalf("include row missing: %+v", got)
	}
	if !locCfg.RequirepassPresent {
		t.Fatal("include row must capture requirepass")
	}
}

func TestFileCollectorIgnoresCycles(t *testing.T) {
	tmp := t.TempDir()
	a := filepath.Join(tmp, "a.conf")
	b := filepath.Join(tmp, "b.conf")
	must(t, os.WriteFile(a, []byte("include "+b+"\n"), 0o600))
	must(t, os.WriteFile(b, []byte("include "+a+"\n"), 0o600))

	c := &fileCollector{
		seeds:    []string{a},
		readFile: os.ReadFile,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("cycle: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("cycle must visit each file exactly once: %d", len(got))
	}
}

func TestFileCollectorMissingSeedsOK(t *testing.T) {
	c := &fileCollector{
		seeds:    []string{"/none-a", "/none-b"},
		readFile: os.ReadFile,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("missing must not error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want empty, got %d", len(got))
	}
}

// -- SortConfigs ----------------------------------------------------

func TestSortConfigsDeterministic(t *testing.T) {
	in := []Config{
		{FilePath: "/etc/redis/z.conf"},
		{FilePath: "/etc/redis/a.conf"},
	}
	SortConfigs(in)
	if in[0].FilePath != "/etc/redis/a.conf" {
		t.Fatalf("first=%+v", in[0])
	}
}

// -- helpers --------------------------------------------------------

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func mustJSON(t *testing.T, v Config) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
