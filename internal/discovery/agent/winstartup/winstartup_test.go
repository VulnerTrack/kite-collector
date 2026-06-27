package winstartup

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func TestPinnedScopeStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(ScopeAllUsers), "all-users"},
		{string(ScopePerUser), "per-user"},
		{string(ScopeUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("scope drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestHashContentsDeterministic(t *testing.T) {
	a := HashContents([]byte("lnk-body"))
	b := HashContents([]byte("lnk-body"))
	if a != b || len(a) != 64 {
		t.Fatalf("a=%q b=%q", a, b)
	}
}

func TestIsExecutableExtension(t *testing.T) {
	hit := []string{".exe", ".EXE", ".bat", ".cmd", ".vbs", ".ps1", ".scr"}
	for _, e := range hit {
		if !IsExecutableExtension(e) {
			t.Fatalf("%q must flag executable", e)
		}
	}
	miss := []string{".lnk", ".ini", "", ".txt"}
	for _, e := range miss {
		if IsExecutableExtension(e) {
			t.Fatalf("%q must NOT flag executable", e)
		}
	}
}

func TestIsTargetInWorldWritableDir(t *testing.T) {
	hit := []string{
		`C:\Users\Public\stage.exe`,
		`C:\Windows\Temp\implant.exe`,
		`%TEMP%\beacon.exe`,
		`%PUBLIC%\go.exe`,
	}
	for _, p := range hit {
		if !IsTargetInWorldWritableDir(p) {
			t.Fatalf("%q must flag world-writable", p)
		}
	}
	miss := []string{
		`C:\Program Files\Vendor\app.exe`,
		`C:\Users\alice\AppData\Local\Vendor\app.exe`,
		``,
	}
	for _, p := range miss {
		if IsTargetInWorldWritableDir(p) {
			t.Fatalf("%q must NOT flag world-writable", p)
		}
	}
}

// -- AnnotateSecurity end-to-end -------------------------------------

func TestAnnotateAllUsersExeImplant(t *testing.T) {
	i := Item{
		Scope:         ScopeAllUsers,
		FileExtension: ".exe",
		TargetPath:    "",
	}
	AnnotateSecurity(&i)
	if !i.IsAllUsersScope {
		t.Fatal("all-users scope must propagate")
	}
	if !i.IsExecutableExtension {
		t.Fatal(".exe must flag executable")
	}
	if i.IsShortcut {
		t.Fatal(".exe must NOT flag shortcut")
	}
}

func TestAnnotateShortcutToWorldWritable(t *testing.T) {
	i := Item{
		Scope:         ScopePerUser,
		FileExtension: ".lnk",
		TargetPath:    `C:\Users\Public\dropper.exe`,
	}
	AnnotateSecurity(&i)
	if !i.IsShortcut {
		t.Fatal(".lnk must flag shortcut")
	}
	if !i.IsTargetInWorldWritableDir {
		t.Fatal("Public target must flag")
	}
	if i.IsAllUsersScope {
		t.Fatal("per-user must NOT flag all-users")
	}
}

// -- ParseShellLinkTarget --------------------------------------------

// buildMinimalLnk constructs a valid Shell Link body with a
// LinkInfo block carrying the given ANSI LocalBasePath. No
// LinkTargetIDList (HasLinkTargetIDList=0). The resulting bytes
// satisfy ParseShellLinkTarget's expectations.
func buildMinimalLnk(localBasePath string) []byte {
	// LinkInfo block layout we emit:
	//   00-03 LinkInfoSize
	//   04-07 LinkInfoHeaderSize (= 0x1C — no Unicode variant)
	//   08-0B LinkInfoFlags (bit 0 = VolumeIDAndLocalBasePath)
	//   0C-0F VolumeIDOffset (= 0, we skip the VolumeID blob)
	//   10-13 LocalBasePathOffset (= 0x1C; first byte after the LinkInfo header)
	//   14-17 CommonNetworkRelativeLinkOffset (= 0)
	//   18-1B CommonPathSuffixOffset (= 0)
	//   1C... LocalBasePath ANSI string + null terminator
	const linkInfoHeaderSize = 0x1C
	localBaseBytes := append([]byte(localBasePath), 0)
	linkInfoSize := linkInfoHeaderSize + len(localBaseBytes)

	out := make([]byte, 76+linkInfoSize)
	// ShellLinkHeader.
	binary.LittleEndian.PutUint32(out[0:4], 76) // HeaderSize
	binary.LittleEndian.PutUint32(out[0x14:0x18], flagHasLinkInfo)
	// LinkInfo block starts at offset 76.
	li := out[76:]
	binary.LittleEndian.PutUint32(li[0:4], uint32(linkInfoSize)) //nolint:gosec // bounded by curated fixture
	binary.LittleEndian.PutUint32(li[4:8], uint32(linkInfoHeaderSize))
	binary.LittleEndian.PutUint32(li[8:12], linkInfoFlagVolumeIDAndLocalBasePath)
	binary.LittleEndian.PutUint32(li[12:16], 0)
	binary.LittleEndian.PutUint32(li[16:20], uint32(linkInfoHeaderSize))
	binary.LittleEndian.PutUint32(li[20:24], 0)
	binary.LittleEndian.PutUint32(li[24:28], 0)
	copy(li[linkInfoHeaderSize:], localBaseBytes)
	return out
}

func TestParseShellLinkTargetANSI(t *testing.T) {
	body := buildMinimalLnk(`C:\Program Files\Vendor\app.exe`)
	got, err := ParseShellLinkTarget(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got != `C:\Program Files\Vendor\app.exe` {
		t.Fatalf("target=%q", got)
	}
}

func TestParseShellLinkTargetEmptyBodyError(t *testing.T) {
	if _, err := ParseShellLinkTarget(nil); err == nil {
		t.Fatal("empty body must error")
	}
}

func TestParseShellLinkTargetBadHeaderError(t *testing.T) {
	body := make([]byte, 76)
	// HeaderSize is wrong (0 instead of 76).
	if _, err := ParseShellLinkTarget(body); err == nil {
		t.Fatal("bad header must error")
	}
}

func TestParseShellLinkTargetNoLinkInfo(t *testing.T) {
	// Valid header, no LinkInfo flag → returns "" + nil.
	body := make([]byte, 76)
	binary.LittleEndian.PutUint32(body[0:4], 76)
	got, err := ParseShellLinkTarget(body)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got != "" {
		t.Fatalf("expected empty target, got %q", got)
	}
}

// -- collector end-to-end -------------------------------------------

func TestFileCollectorAllUsersAndPerUser(t *testing.T) {
	tmp := t.TempDir()

	// ProgramData/...StartUp/
	allUsers := filepath.Join(tmp, "ProgramData", "Startup")
	must(t, os.MkdirAll(allUsers, 0o755))
	// Direct .exe drop — implant signal.
	must(t, os.WriteFile(filepath.Join(allUsers, "implant.exe"),
		[]byte("MZ\x00\x00"), 0o644))
	// .lnk pointing to a world-writable target.
	must(t, os.WriteFile(filepath.Join(allUsers, "stage.lnk"),
		buildMinimalLnk(`C:\Users\Public\dropper.exe`), 0o644))

	// Per-user: alice + bob.
	usersBase := filepath.Join(tmp, "Users")
	aliceStartup := filepath.Join(usersBase, "alice", DefaultPerUserSuffix)
	bobStartup := filepath.Join(usersBase, "bob", DefaultPerUserSuffix)
	must(t, os.MkdirAll(aliceStartup, 0o755))
	must(t, os.MkdirAll(bobStartup, 0o755))
	must(t, os.WriteFile(filepath.Join(aliceStartup, "OneDrive.lnk"),
		buildMinimalLnk(`C:\Program Files\OneDrive\OneDrive.exe`), 0o644))
	must(t, os.WriteFile(filepath.Join(bobStartup, "Teams.lnk"),
		buildMinimalLnk(`C:\Program Files\Teams\Teams.exe`), 0o644))

	// System pseudo-profiles should be skipped.
	must(t, os.MkdirAll(filepath.Join(usersBase, "Public", DefaultPerUserSuffix), 0o755))
	must(t, os.WriteFile(
		filepath.Join(usersBase, "Public", DefaultPerUserSuffix, "skip.lnk"),
		buildMinimalLnk(`C:\skip.exe`), 0o644))
	must(t, os.MkdirAll(filepath.Join(usersBase, "Default", DefaultPerUserSuffix), 0o755))

	c := &fileCollector{
		usersBase:    usersBase,
		allUsersRoot: allUsers,
		readFile:     os.ReadFile,
		readDir:      os.ReadDir,
		statFile:     os.Stat,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	// 2 from all-users + 2 from real users (alice/bob); Public/Default skipped.
	if len(got) != 4 {
		t.Fatalf("want 4, got %d: %+v", len(got), got)
	}

	byName := map[string]Item{}
	for _, i := range got {
		byName[i.FileName] = i
	}

	implant := byName["implant.exe"]
	if !implant.IsAllUsersScope {
		t.Fatal("ProgramData implant must flag all-users")
	}
	if !implant.IsExecutableExtension {
		t.Fatal(".exe must flag executable")
	}

	stage := byName["stage.lnk"]
	if !stage.IsAllUsersScope {
		t.Fatal("ProgramData stage.lnk must flag all-users")
	}
	if stage.TargetPath != `C:\Users\Public\dropper.exe` {
		t.Fatalf("stage target=%q", stage.TargetPath)
	}
	if !stage.IsTargetInWorldWritableDir {
		t.Fatal("Public target must flag world-writable")
	}

	onedrive := byName["OneDrive.lnk"]
	if onedrive.IsAllUsersScope {
		t.Fatal("per-user OneDrive must NOT flag all-users")
	}
	if onedrive.UserProfile != "alice" {
		t.Fatalf("user=%q", onedrive.UserProfile)
	}
	if onedrive.IsTargetInWorldWritableDir {
		t.Fatal("Program Files target must NOT flag world-writable")
	}
}

func TestFileCollectorMissingDirsOK(t *testing.T) {
	c := &fileCollector{
		usersBase:    "/nope-users",
		allUsersRoot: "/nope-allusers",
		readFile:     os.ReadFile,
		readDir:      os.ReadDir,
		statFile:     os.Stat,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("missing must not error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want empty, got %d", len(got))
	}
}

// -- SortItems ------------------------------------------------------

func TestSortItemsDeterministic(t *testing.T) {
	in := []Item{
		{Scope: ScopePerUser, FilePath: "z"},
		{Scope: ScopeAllUsers, FilePath: "a"},
		{Scope: ScopeAllUsers, FilePath: "b"},
	}
	SortItems(in)
	if in[0].Scope != ScopeAllUsers || in[0].FilePath != "a" {
		t.Fatalf("first=%+v", in[0])
	}
	if in[2].Scope != ScopePerUser {
		t.Fatalf("last=%+v", in[2])
	}
}

// -- helpers --------------------------------------------------------

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
