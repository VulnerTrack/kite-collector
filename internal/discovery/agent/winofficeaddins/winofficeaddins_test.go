package winofficeaddins

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestPinnedOfficeHostStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(HostWord), "word"},
		{string(HostExcel), "excel"},
		{string(HostPowerPoint), "powerpoint"},
		{string(HostOutlook), "outlook"},
		{string(HostOfficeShared), "office-shared"},
		{string(HostUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("host drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestPinnedScopeStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(ScopePerUser), "per-user"},
		{string(ScopeMachineWide), "machine-wide"},
		{string(ScopeUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("scope drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestHashContentsDeterministic(t *testing.T) {
	a := HashContents([]byte("dotm-body"))
	b := HashContents([]byte("dotm-body"))
	if a != b || len(a) != 64 {
		t.Fatalf("a=%q b=%q", a, b)
	}
}

func TestIsMacroEnabledExtension(t *testing.T) {
	hit := []string{".dotm", ".DOTM", ".xlsm", ".xltm", ".xlam", ".pptm", ".potm", ".ppam", ".xla", ".xlt", ".dot", ".pot"}
	for _, e := range hit {
		if !IsMacroEnabledExtension(e) {
			t.Fatalf("%q must flag macro-enabled", e)
		}
	}
	miss := []string{".docx", ".xlsx", ".pptx", ".pdf", "", ".lnk"}
	for _, e := range miss {
		if IsMacroEnabledExtension(e) {
			t.Fatalf("%q must NOT flag macro-enabled", e)
		}
	}
}

func TestIsNativeAddinDLL(t *testing.T) {
	if !IsNativeAddinDLL(".wll") {
		t.Fatal(".wll must flag")
	}
	if !IsNativeAddinDLL(".XLL") {
		t.Fatal(".XLL must flag (case-insensitive)")
	}
	for _, e := range []string{".dll", ".sys", "", ".dotm"} {
		if IsNativeAddinDLL(e) {
			t.Fatalf("%q must NOT flag native add-in", e)
		}
	}
}

func TestIsOutlookVBAFile(t *testing.T) {
	if !IsOutlookVBAFile("VbaProject.OTM") {
		t.Fatal("VbaProject.OTM must flag")
	}
	if !IsOutlookVBAFile("vbaproject.otm") {
		t.Fatal("case-insensitive")
	}
	for _, n := range []string{"VbaProject.otm.bak", "OutlookProject.OTM", ""} {
		if IsOutlookVBAFile(n) {
			t.Fatalf("%q must NOT flag", n)
		}
	}
}

func TestHostFromDirName(t *testing.T) {
	cases := map[string]OfficeHost{
		"Word":       HostWord,
		"word":       HostWord,
		"Excel":      HostExcel,
		"PowerPoint": HostPowerPoint,
		"Outlook":    HostOutlook,
		"AddIns":     HostOfficeShared,
		"random":     HostUnknown,
	}
	for in, want := range cases {
		if got := HostFromDirName(in); got != want {
			t.Fatalf("HostFromDirName(%q)=%q want %q", in, got, want)
		}
	}
}

// -- AnnotateSecurity end-to-end -------------------------------------

func TestAnnotateMacroTemplate(t *testing.T) {
	i := Item{
		FileName:      "implant.dotm",
		FileExtension: ".dotm",
		OfficeHost:    HostWord,
		Scope:         ScopePerUser,
	}
	AnnotateSecurity(&i)
	if !i.IsMacroEnabledExtension {
		t.Fatal(".dotm must flag macro")
	}
	if !i.IsPersistenceCandidate {
		t.Fatal("macro template in STARTUP must flag persistence")
	}
	if i.IsMachineWide || i.IsOutlookVBAProject {
		t.Fatalf("wrong flags: %+v", i)
	}
}

func TestAnnotateMachineWideXll(t *testing.T) {
	i := Item{
		FileName:      "trader.xll",
		FileExtension: ".xll",
		OfficeHost:    HostExcel,
		Scope:         ScopeMachineWide,
	}
	AnnotateSecurity(&i)
	if !i.IsNativeAddinDLL {
		t.Fatal(".xll must flag native add-in")
	}
	if !i.IsMachineWide {
		t.Fatal("machine-wide scope must flag")
	}
	if !i.IsPersistenceCandidate {
		t.Fatal("native add-in must flag persistence")
	}
}

func TestAnnotateOutlookVBA(t *testing.T) {
	i := Item{
		FileName:      "VbaProject.OTM",
		FileExtension: ".otm",
		OfficeHost:    HostOutlook,
		Scope:         ScopePerUser,
	}
	AnnotateSecurity(&i)
	if !i.IsOutlookVBAProject {
		t.Fatal("VbaProject.OTM must flag Outlook VBA")
	}
	if !i.IsPersistenceCandidate {
		t.Fatal("Outlook VBA must flag persistence")
	}
}

func TestAnnotatePlainDocxNotPersistence(t *testing.T) {
	i := Item{
		FileName:      "Normal.dotx",
		FileExtension: ".dotx",
		OfficeHost:    HostWord,
		Scope:         ScopePerUser,
	}
	AnnotateSecurity(&i)
	if i.IsMacroEnabledExtension {
		t.Fatal(".dotx (no macros) must NOT flag macro-enabled")
	}
	if i.IsPersistenceCandidate {
		t.Fatal(".dotx must NOT flag persistence")
	}
}

// -- collector end-to-end -------------------------------------------

func TestFileCollectorWalksUserAndMachineWide(t *testing.T) {
	tmp := t.TempDir()

	// Machine-wide: Office16\STARTUP\evil.dotm
	mwRoot := filepath.Join(tmp, "Office16")
	mwStartup := filepath.Join(mwRoot, "STARTUP")
	must(t, os.MkdirAll(mwStartup, 0o755))
	must(t, os.WriteFile(filepath.Join(mwStartup, "evil.dotm"),
		[]byte("docm-body"), 0o644))
	// .docx in STARTUP — present but NOT persistence-flagged.
	mwXlstart := filepath.Join(mwRoot, "XLSTART")
	must(t, os.MkdirAll(mwXlstart, 0o755))
	must(t, os.WriteFile(filepath.Join(mwXlstart, "Personal.xlsm"),
		[]byte("xlsm-body"), 0o644))

	// Per-user: alice + bob.
	usersBase := filepath.Join(tmp, "Users")
	aliceWord := filepath.Join(usersBase, "alice", `AppData\Roaming\Microsoft\Word\STARTUP`)
	bobOutlook := filepath.Join(usersBase, "bob", `AppData\Roaming\Microsoft\Outlook`)
	must(t, os.MkdirAll(aliceWord, 0o755))
	must(t, os.MkdirAll(bobOutlook, 0o755))
	must(t, os.WriteFile(filepath.Join(aliceWord, "alice-helper.dotm"),
		[]byte("alice-body"), 0o644))
	must(t, os.WriteFile(filepath.Join(bobOutlook, "VbaProject.OTM"),
		[]byte("vba-body"), 0o644))

	// Public profile should be skipped.
	publicWord := filepath.Join(usersBase, "Public", `AppData\Roaming\Microsoft\Word\STARTUP`)
	must(t, os.MkdirAll(publicWord, 0o755))
	must(t, os.WriteFile(filepath.Join(publicWord, "skip.dotm"),
		[]byte("skip"), 0o644))

	c := &fileCollector{
		usersBase:        usersBase,
		machineWideRoots: []string{mwRoot},
		readFile:         os.ReadFile,
		readDir:          os.ReadDir,
		statFile:         os.Stat,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	// MW: 2 (evil.dotm + Personal.xlsm). Per-user: 2 (alice + bob). Public skipped.
	if len(got) != 4 {
		t.Fatalf("want 4 rows, got %d: %+v", len(got), got)
	}

	byName := map[string]Item{}
	for _, i := range got {
		byName[i.FileName] = i
	}

	evil := byName["evil.dotm"]
	if evil.OfficeHost != HostWord || !evil.IsMachineWide ||
		!evil.IsPersistenceCandidate {
		t.Fatalf("evil.dotm wrong: %+v", evil)
	}

	personal := byName["Personal.xlsm"]
	if personal.OfficeHost != HostExcel || !personal.IsMacroEnabledExtension {
		t.Fatalf("Personal.xlsm wrong: %+v", personal)
	}

	aliceItem := byName["alice-helper.dotm"]
	if aliceItem.UserProfile != "alice" || !aliceItem.IsPersistenceCandidate {
		t.Fatalf("alice item wrong: %+v", aliceItem)
	}

	bobVBA := byName["VbaProject.OTM"]
	if !bobVBA.IsOutlookVBAProject || bobVBA.UserProfile != "bob" {
		t.Fatalf("bob VBA wrong: %+v", bobVBA)
	}
}

func TestFileCollectorMissingRootsOK(t *testing.T) {
	c := &fileCollector{
		usersBase:        "/nope-users",
		machineWideRoots: []string{"/nope-office"},
		readFile:         os.ReadFile,
		readDir:          os.ReadDir,
		statFile:         os.Stat,
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
		{OfficeHost: HostWord, Scope: ScopePerUser, FilePath: "z"},
		{OfficeHost: HostExcel, Scope: ScopeMachineWide, FilePath: "a"},
		{OfficeHost: HostExcel, Scope: ScopePerUser, FilePath: "b"},
	}
	SortItems(in)
	if in[0].OfficeHost != HostExcel || in[0].Scope != ScopeMachineWide {
		t.Fatalf("first=%+v", in[0])
	}
	if in[2].OfficeHost != HostWord {
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
