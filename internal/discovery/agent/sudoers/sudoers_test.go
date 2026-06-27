package sudoers

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPinnedEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(EntryUserSpec), "user-spec"},
		{string(EntryDefaults), "defaults"},
		{string(EntryUserAlias), "user-alias"},
		{string(EntryRunasAlias), "runas-alias"},
		{string(EntryHostAlias), "host-alias"},
		{string(EntryCmndAlias), "cmnd-alias"},
		{string(EntryInclude), "include"},
		{string(EntryUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q (breaks SQLite CHECK)",
				p.got, p.want)
		}
	}
}

func TestEncodeStringListEmpty(t *testing.T) {
	if got := EncodeStringList(nil); got != "[]" {
		t.Fatalf("nil = %q", got)
	}
}

func TestHashContentsDeterministic(t *testing.T) {
	a := HashContents([]byte("Defaults timestamp_timeout=30\n"))
	b := HashContents([]byte("Defaults timestamp_timeout=30\n"))
	if a != b {
		t.Fatal("not deterministic")
	}
	if len(a) != 64 {
		t.Fatalf("expected sha256 hex, got %d chars", len(a))
	}
}

func TestIsDangerousDefault(t *testing.T) {
	for _, k := range []string{"env_keep", "secure_path", "timestamp_timeout"} {
		if !IsDangerousDefault(k) {
			t.Fatalf("%q must be flagged", k)
		}
	}
	for _, k := range []string{"insults", "passwd_tries", ""} {
		if IsDangerousDefault(k) {
			t.Fatalf("%q must NOT be flagged", k)
		}
	}
}

func TestSplitMergeContinuations(t *testing.T) {
	in := `line one
continued line one \
continued line two \
end of continuation
plain line
`
	got := splitMergeContinuations(in)
	want := []string{
		"line one",
		"continued line one continued line two end of continuation",
		"plain line",
		"",
	}
	if len(got) != len(want) {
		t.Fatalf("got %d lines, want %d: %q", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("line %d: got %q, want %q", i, got[i], want[i])
		}
	}
}

func TestSplitKV(t *testing.T) {
	cases := []struct {
		in        string
		wantKey   string
		wantValue string
	}{
		{"timestamp_timeout=30", "timestamp_timeout", "30"},
		{"!requiretty", "!requiretty", ""},
		{`env_keep += "FOO BAR"`, "env_keep", `+= "FOO BAR"`},
		{"insults", "insults", ""},
		{"  spaces  =  30  ", "spaces", "30"},
	}
	for _, tc := range cases {
		k, v := splitKV(tc.in)
		if k != tc.wantKey || v != tc.wantValue {
			t.Fatalf("splitKV(%q) = (%q, %q), want (%q, %q)",
				tc.in, k, v, tc.wantKey, tc.wantValue)
		}
	}
}

func TestSplitCommaTrimRespectsQuotes(t *testing.T) {
	got := splitCommaTrim(`/usr/bin/foo, /usr/bin/bar "with, comma", /bin/baz`)
	want := []string{
		`/usr/bin/foo`,
		`/usr/bin/bar "with, comma"`,
		`/bin/baz`,
	}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("pos %d: got %q, want %q", i, got[i], want[i])
		}
	}
}

func TestCollapseWhitespace(t *testing.T) {
	got := collapseWhitespace("  alice\tALL=(ALL)\t\tNOPASSWD: ALL  ")
	want := "alice ALL=(ALL) NOPASSWD: ALL"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// -- parseDefaults --------------------------------------------------

func TestParseDefaultsSimple(t *testing.T) {
	e := parseDefaults(`Defaults timestamp_timeout=30`)
	if e.EntryType != EntryDefaults {
		t.Fatalf("entry_type=%q", e.EntryType)
	}
	if e.DefaultsKey != "timestamp_timeout" || e.DefaultsValue != "30" {
		t.Fatalf("key/val=(%q,%q)", e.DefaultsKey, e.DefaultsValue)
	}
	if !e.IsDangerousDefault {
		t.Fatal("timestamp_timeout must be flagged dangerous")
	}
}

func TestParseDefaultsNegated(t *testing.T) {
	e := parseDefaults(`Defaults !requiretty`)
	if e.DefaultsKey != "!requiretty" {
		t.Fatalf("key=%q", e.DefaultsKey)
	}
	if !e.IsDangerousDefault {
		t.Fatal("negated Defaults must be flagged")
	}
}

func TestParseDefaultsAtHostScoped(t *testing.T) {
	e := parseDefaults(`Defaults@webhost env_keep += "DISPLAY XAUTHORITY"`)
	if e.DefaultsKey != "env_keep" {
		t.Fatalf("key=%q", e.DefaultsKey)
	}
	if !strings.HasPrefix(e.DefaultsValue, "+=") {
		t.Fatalf("value should preserve += operator: %q", e.DefaultsValue)
	}
	if !e.IsDangerousDefault {
		t.Fatal("env_keep must be flagged dangerous")
	}
}

func TestParseDefaultsInsultsNotDangerous(t *testing.T) {
	e := parseDefaults(`Defaults insults`)
	if e.IsDangerousDefault {
		t.Fatal("insults must NOT be flagged")
	}
}

// -- parseAlias -----------------------------------------------------

func TestParseAliasUser(t *testing.T) {
	e := parseAlias(`User_Alias ADMINS = alice, bob, charlie`, "User_Alias", EntryUserAlias)
	if e.EntryType != EntryUserAlias {
		t.Fatalf("type=%q", e.EntryType)
	}
	if e.AliasName != "ADMINS" {
		t.Fatalf("name=%q", e.AliasName)
	}
	if len(e.AliasMembers) != 3 {
		t.Fatalf("members=%v", e.AliasMembers)
	}
	// Members must be sorted (alice < bob < charlie).
	want := []string{"alice", "bob", "charlie"}
	for i, m := range e.AliasMembers {
		if m != want[i] {
			t.Fatalf("member[%d]=%q, want %q", i, m, want[i])
		}
	}
}

func TestParseAliasMalformed(t *testing.T) {
	e := parseAlias(`User_Alias broken without equals`, "User_Alias", EntryUserAlias)
	if e.EntryType != EntryUnknown {
		t.Fatalf("type=%q, want unknown", e.EntryType)
	}
}

// -- parseInclude ---------------------------------------------------

func TestParseInclude(t *testing.T) {
	cases := map[string]string{
		`@includedir /etc/sudoers.d`:  "/etc/sudoers.d",
		`#include /etc/sudoers.local`: "/etc/sudoers.local",
		`@include /etc/sudoers.d/foo`: "/etc/sudoers.d/foo",
	}
	for line, want := range cases {
		e := parseInclude(line)
		if e.EntryType != EntryInclude {
			t.Fatalf("%q: type=%q", line, e.EntryType)
		}
		if e.IncludesPath != want {
			t.Fatalf("%q: includes_path=%q, want %q", line, e.IncludesPath, want)
		}
	}
}

// -- parseUserSpec --------------------------------------------------

func TestParseUserSpecTotalPrivilege(t *testing.T) {
	e := parseUserSpec(`alice ALL=(ALL:ALL) NOPASSWD: ALL`)
	if e.EntryType != EntryUserSpec {
		t.Fatalf("type=%q", e.EntryType)
	}
	if e.Principal != "alice" {
		t.Fatalf("principal=%q", e.Principal)
	}
	if e.Hosts != "ALL" {
		t.Fatalf("hosts=%q", e.Hosts)
	}
	if e.RunasUser != "ALL" || e.RunasGroup != "ALL" {
		t.Fatalf("runas=(%q,%q)", e.RunasUser, e.RunasGroup)
	}
	if !e.IsPasswordless {
		t.Fatal("NOPASSWD tag must flag is_passwordless")
	}
	if !e.IsTotalPrivilege {
		t.Fatal("ALL=(ALL) ALL pattern must flag is_total_privilege")
	}
	if len(e.Commands) != 1 || e.Commands[0] != "ALL" {
		t.Fatalf("commands=%v", e.Commands)
	}
}

func TestParseUserSpecGroupSpec(t *testing.T) {
	e := parseUserSpec(`%sudo ALL=(ALL) ALL`)
	if e.Principal != "%sudo" {
		t.Fatalf("principal=%q (must keep %% prefix)", e.Principal)
	}
	if e.IsPasswordless {
		t.Fatal("no NOPASSWD → must NOT flag passwordless")
	}
	if !e.IsTotalPrivilege {
		t.Fatal("ALL=(ALL) ALL is still total privilege even with password")
	}
}

func TestParseUserSpecRestrictedCommand(t *testing.T) {
	e := parseUserSpec(`alice ALL=NOPASSWD: /usr/bin/systemctl restart nginx, /usr/bin/journalctl`)
	if !e.IsPasswordless {
		t.Fatal("NOPASSWD set")
	}
	if e.IsTotalPrivilege {
		t.Fatal("restricted command list must NOT be total privilege")
	}
	if len(e.Commands) != 2 {
		t.Fatalf("commands=%v", e.Commands)
	}
	// Sorted alphabetically.
	if e.Commands[0] != "/usr/bin/journalctl" {
		t.Fatalf("commands not sorted: %v", e.Commands)
	}
}

func TestParseUserSpecMultiTag(t *testing.T) {
	e := parseUserSpec(`bot ALL=(deployer) NOPASSWD: SETENV: /opt/bin/deploy.sh`)
	if !e.IsPasswordless {
		t.Fatal("NOPASSWD")
	}
	wantTags := map[string]bool{"NOPASSWD": true, "SETENV": true}
	for _, tag := range e.Tags {
		if !wantTags[tag] {
			t.Fatalf("unexpected tag %q", tag)
		}
		delete(wantTags, tag)
	}
	if len(wantTags) > 0 {
		t.Fatalf("missing tags: %v", wantTags)
	}
	if e.RunasUser != "deployer" {
		t.Fatalf("runas_user=%q", e.RunasUser)
	}
}

func TestParseUserSpecMultiHost(t *testing.T) {
	e := parseUserSpec(`bot web1,web2,web3=(srv) /opt/bin/restart`)
	if e.Hosts != "web1,web2,web3" {
		t.Fatalf("hosts=%q", e.Hosts)
	}
	if e.IsTotalPrivilege {
		t.Fatal("scoped host + single command must NOT be total privilege")
	}
}

// -- Parse (end-to-end on a file body) ------------------------------

func TestParseRealisticSudoersFile(t *testing.T) {
	body := []byte(`# /etc/sudoers - syntax compatible with sudo 1.9.x
#
Defaults    env_reset
Defaults    mail_badpass
Defaults    secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
Defaults    timestamp_timeout=60
Defaults    !requiretty

# User and Cmnd aliases
User_Alias  ADMINS = alice, bob
Cmnd_Alias  SOFTWARE = /usr/bin/apt, \
                       /usr/bin/dpkg

# User specs
root        ALL=(ALL:ALL) ALL
%sudo       ALL=(ALL:ALL) ALL
%wheel      ALL=(ALL) NOPASSWD: ALL
ADMINS      ALL=SOFTWARE
alice       ALL=NOPASSWD: /usr/bin/systemctl restart nginx

# Includes
#includedir /etc/sudoers.d
`)
	got := Parse(body, "/etc/sudoers")

	// Spot-check structural correctness.
	byType := map[EntryType]int{}
	for _, e := range got {
		byType[e.EntryType]++
	}
	if byType[EntryDefaults] != 5 {
		t.Fatalf("defaults count=%d, want 5", byType[EntryDefaults])
	}
	if byType[EntryUserAlias] != 1 {
		t.Fatalf("user-alias count=%d", byType[EntryUserAlias])
	}
	if byType[EntryCmndAlias] != 1 {
		t.Fatalf("cmnd-alias count=%d (continuation must merge into one entry)",
			byType[EntryCmndAlias])
	}
	if byType[EntryUserSpec] != 5 {
		t.Fatalf("user-spec count=%d, want 5", byType[EntryUserSpec])
	}
	if byType[EntryInclude] != 1 {
		t.Fatalf("include count=%d", byType[EntryInclude])
	}

	// Find the wheel NOPASSWD ALL line and verify both flags.
	var wheel Entry
	for _, e := range got {
		if e.EntryType == EntryUserSpec && e.Principal == "%wheel" {
			wheel = e
			break
		}
	}
	if !wheel.IsPasswordless {
		t.Fatal("wheel must be flagged passwordless")
	}
	if !wheel.IsTotalPrivilege {
		t.Fatal("wheel must be flagged total privilege")
	}

	// Verify alice's restricted line is NOT total privilege.
	var alice Entry
	for _, e := range got {
		if e.EntryType == EntryUserSpec && e.Principal == "alice" {
			alice = e
			break
		}
	}
	if !alice.IsPasswordless {
		t.Fatal("alice must be flagged passwordless")
	}
	if alice.IsTotalPrivilege {
		t.Fatal("alice has restricted command → must NOT be total privilege")
	}

	// Verify the Cmnd_Alias line was merged across the continuation.
	for _, e := range got {
		if e.EntryType == EntryCmndAlias && e.AliasName == "SOFTWARE" {
			if len(e.AliasMembers) != 2 {
				t.Fatalf("SOFTWARE alias members=%v (continuation merge broken)",
					e.AliasMembers)
			}
		}
	}

	// File hash present on every row.
	for _, e := range got {
		if e.FileHash == "" {
			t.Fatalf("file_hash missing on %+v", e)
		}
	}
}

// -- collector ------------------------------------------------------

func TestSudoIncludesFile(t *testing.T) {
	cases := map[string]bool{
		"00-base":     true,
		"99-final":    true,
		"alice":       true,
		"file.bak":    false, // contains '.'
		"file~":       false, // backup
		".hidden":     false, // contains '.'
		"00-base.swp": false,
		"":            false,
	}
	for in, want := range cases {
		if got := sudoIncludesFile(in); got != want {
			t.Fatalf("sudoIncludesFile(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestFileCollectorWalksMainAndDropIn(t *testing.T) {
	tmp := t.TempDir()
	mainPath := filepath.Join(tmp, "sudoers")
	dropIn := filepath.Join(tmp, "sudoers.d")
	if err := os.MkdirAll(dropIn, 0o755); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, mainPath, `Defaults timestamp_timeout=15
root ALL=(ALL:ALL) ALL
`)
	mustWrite(t, filepath.Join(dropIn, "00-admin"), `%wheel ALL=(ALL) NOPASSWD: ALL
`)
	mustWrite(t, filepath.Join(dropIn, "99-bot"), `bot ALL=NOPASSWD: /usr/bin/systemctl reload nginx
`)
	mustWrite(t, filepath.Join(dropIn, "ignored.bak"), `dangerous=value
`)
	mustWrite(t, filepath.Join(dropIn, "vim-swap~"), `also dangerous
`)

	c := &fileCollector{
		mainFile:  mainPath,
		dropInDir: dropIn,
		readFile:  os.ReadFile,
		readDir:   os.ReadDir,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	// 2 entries from main + 1 from 00-admin + 1 from 99-bot = 4.
	// Backup file (.bak) and vim swap (~) MUST be skipped.
	if len(got) != 4 {
		t.Fatalf("want 4 entries, got %d: %+v", len(got), got)
	}

	// Verify lexical drop-in order (00-admin processed before 99-bot).
	dropInPaths := []string{}
	for _, e := range got {
		if filepath.Dir(e.FilePath) == dropIn {
			dropInPaths = append(dropInPaths, filepath.Base(e.FilePath))
		}
	}
	if len(dropInPaths) != 2 || dropInPaths[0] != "00-admin" || dropInPaths[1] != "99-bot" {
		t.Fatalf("drop-in order wrong: %v", dropInPaths)
	}

	// Verify the wheel NOPASSWD ALL entry got picked up correctly.
	var wheel Entry
	for _, e := range got {
		if e.Principal == "%wheel" {
			wheel = e
			break
		}
	}
	if !wheel.IsPasswordless || !wheel.IsTotalPrivilege {
		t.Fatalf("wheel flags lost: %+v", wheel)
	}
}

func TestFileCollectorMissingMainOK(t *testing.T) {
	c := &fileCollector{
		mainFile:  "/nope",
		dropInDir: "/also-nope",
		readFile:  os.ReadFile,
		readDir:   os.ReadDir,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("missing must not error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want empty, got %d", len(got))
	}
}

func TestSortEntriesDeterministic(t *testing.T) {
	in := []Entry{
		{FilePath: "/etc/sudoers.d/zzz", LineNo: 1},
		{FilePath: "/etc/sudoers", LineNo: 5},
		{FilePath: "/etc/sudoers", LineNo: 2},
	}
	SortEntries(in)
	if in[0].FilePath != "/etc/sudoers" || in[0].LineNo != 2 {
		t.Fatalf("first: %+v", in[0])
	}
	if in[2].FilePath != "/etc/sudoers.d/zzz" {
		t.Fatalf("last: %+v", in[2])
	}
}

// -- helpers --------------------------------------------------------

func mustWrite(t *testing.T, p, body string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}
