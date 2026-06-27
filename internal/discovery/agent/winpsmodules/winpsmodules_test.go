package winpsmodules

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestPinnedInstallScopeStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(ScopeSystem), "system"},
		{string(ScopeUser), "user"},
		{string(ScopeUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("install_scope drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestHashContentsDeterministic(t *testing.T) {
	a := HashContents([]byte("@{ModuleVersion='1.0.0'}"))
	b := HashContents([]byte("@{ModuleVersion='1.0.0'}"))
	if a != b || len(a) != 64 {
		t.Fatalf("a=%q b=%q", a, b)
	}
}

func TestClassifyInstallScope(t *testing.T) {
	system := []string{
		`C:\Program Files\PowerShell\7\Modules\Az\1.0\Az.psd1`,
		`c:\program files\windowspowershell\modules\foo\foo.psd1`,
		`C:\Windows\System32\WindowsPowerShell\v1.0\Modules\Microsoft.PowerShell.Management\Microsoft.PowerShell.Management.psd1`,
	}
	for _, p := range system {
		if got := ClassifyInstallScope(p); got != ScopeSystem {
			t.Fatalf("%q got %q, want system", p, got)
		}
	}
	user := []string{
		`C:\Users\alice\Documents\PowerShell\Modules\Foo\1.0\Foo.psd1`,
		`C:\Users\bob\Documents\WindowsPowerShell\Modules\bar\bar.psd1`,
		`C:\Users\carol\OneDrive\Documents\PowerShell\Modules\baz\baz.psd1`,
	}
	for _, p := range user {
		if got := ClassifyInstallScope(p); got != ScopeUser {
			t.Fatalf("%q got %q, want user", p, got)
		}
	}
	if got := ClassifyInstallScope(`C:\opt\custom\Modules\foo\foo.psd1`); got != ScopeUnknown {
		t.Fatalf("custom path got %q, want unknown", got)
	}
}

func TestIsBinaryRootModule(t *testing.T) {
	hit := []string{"Foo.dll", "bin/foo.DLL", "Bar.cdxml"}
	for _, r := range hit {
		if !IsBinaryRootModule(r) {
			t.Fatalf("%q must flag binary", r)
		}
	}
	miss := []string{"Foo.psm1", "Foo.ps1", "", "bin/foo.txt"}
	for _, r := range miss {
		if IsBinaryRootModule(r) {
			t.Fatalf("%q must NOT flag binary", r)
		}
	}
}

func TestIsRootModuleOutsideDir(t *testing.T) {
	hit := []string{
		`..\..\Foo.dll`,
		`/etc/foo.psm1`,
		`\foo.psm1`,
		`C:\Foo\bar.dll`,
		`D:/abs/foo.psm1`,
	}
	for _, r := range hit {
		if !IsRootModuleOutsideDir(r) {
			t.Fatalf("%q must flag outside", r)
		}
	}
	miss := []string{
		"foo.psm1",
		"bin/foo.dll",
		"sub/dir/Foo.psd1",
		"",
	}
	for _, r := range miss {
		if IsRootModuleOutsideDir(r) {
			t.Fatalf("%q must NOT flag outside", r)
		}
	}
}

// -- AnnotateSecurity end-to-end -------------------------------------

func TestAnnotateUserScopedBinaryModule(t *testing.T) {
	m := Module{
		FilePath:   `C:\Users\alice\Documents\PowerShell\Modules\Implant\Implant.psd1`,
		ModuleName: "Implant",
		RootModule: "bin/Implant.dll",
	}
	AnnotateSecurity(&m)
	if !m.IsUserScoped {
		t.Fatal("user-path must flag user-scoped")
	}
	if !m.HasBinaryRootModule {
		t.Fatal("DLL RootModule must flag binary")
	}
	if !m.IsMissingAuthor || !m.IsMissingCompany {
		t.Fatal("empty Author+CompanyName must flag")
	}
}

func TestAnnotateCleanMicrosoftModule(t *testing.T) {
	m := Module{
		FilePath:    `C:\Program Files\WindowsPowerShell\Modules\Az.Accounts\Az.Accounts.psd1`,
		ModuleName:  "Az.Accounts",
		Author:      "Microsoft Corporation",
		CompanyName: "Microsoft Corporation",
		RootModule:  "Az.Accounts.psm1",
	}
	AnnotateSecurity(&m)
	if m.IsUserScoped {
		t.Fatal("Program Files must NOT flag user-scoped")
	}
	if m.HasBinaryRootModule {
		t.Fatal(".psm1 must NOT flag binary")
	}
	if m.IsMissingAuthor || m.IsMissingCompany {
		t.Fatal("Microsoft module fields must be populated")
	}
	if m.HasRootModuleOutsideDir {
		t.Fatal("sibling .psm1 must NOT flag outside")
	}
}

func TestAnnotatePathTraversalRootModule(t *testing.T) {
	m := Module{
		FilePath:    `C:\Program Files\WindowsPowerShell\Modules\Sketchy\Sketchy.psd1`,
		ModuleName:  "Sketchy",
		Author:      "Sketchy",
		CompanyName: "Sketchy",
		RootModule:  `..\..\..\Windows\Temp\Sketchy.dll`,
	}
	AnnotateSecurity(&m)
	if !m.HasRootModuleOutsideDir {
		t.Fatalf("parent escape must flag: %+v", m)
	}
	if !m.HasBinaryRootModule {
		t.Fatal(".dll must flag binary")
	}
}

// -- ParsePSD1 typical hardened -------------------------------------

func TestParsePSD1Typical(t *testing.T) {
	body := []byte(`# Module manifest for Az.Accounts
@{
    RootModule = 'Az.Accounts.psm1'
    ModuleVersion = '2.12.1'
    GUID = '17a2feff-488b-47f9-8729-dd4c23a4e0c8'
    Author = 'Microsoft Corporation'
    CompanyName = 'Microsoft Corporation'
    Copyright = '(c) Microsoft Corporation. All rights reserved.'
    Description = 'Microsoft Azure Account credential management cmdlets.'
    PowerShellVersion = '5.1'
    DotNetFrameworkVersion = '4.7.2'
    FunctionsToExport = @()
    CmdletsToExport = @('Connect-AzAccount', 'Disconnect-AzAccount')
    PrivateData = @{
        PSData = @{
            Tags = @('Azure','Auth')
        }
    }
}`)
	got, err := ParsePSD1(body, `C:\Program Files\PowerShell\Modules\Az.Accounts\Az.Accounts.psd1`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.ModuleName != "Az.Accounts" {
		t.Fatalf("module_name=%q", got.ModuleName)
	}
	if got.ModuleVersion != "2.12.1" {
		t.Fatalf("version=%q", got.ModuleVersion)
	}
	if got.Author != "Microsoft Corporation" {
		t.Fatalf("author=%q", got.Author)
	}
	if got.RootModule != "Az.Accounts.psm1" {
		t.Fatalf("root=%q", got.RootModule)
	}
	if got.GUID != "17a2feff-488b-47f9-8729-dd4c23a4e0c8" {
		t.Fatalf("guid=%q", got.GUID)
	}
	if got.PowerShellVersion != "5.1" {
		t.Fatalf("ps_version=%q", got.PowerShellVersion)
	}
	if got.InstallScope != ScopeSystem {
		t.Fatalf("install_scope=%q", got.InstallScope)
	}
	if got.IsUserScoped || got.HasBinaryRootModule {
		t.Fatal("clean Microsoft module must not flag")
	}
}

// -- ParsePSD1 with mixed quote styles ------------------------------

func TestParsePSD1MixedQuotes(t *testing.T) {
	body := []byte(`@{
  ModuleVersion = "1.0.0"
  Author = 'Single Quoted'
  Description = "Has 'single' inside"
  RootModule = 'MyMod.psm1'
}`)
	got, err := ParsePSD1(body, "x.psd1")
	if err != nil {
		t.Fatal(err)
	}
	if got.ModuleVersion != "1.0.0" {
		t.Fatalf("version=%q", got.ModuleVersion)
	}
	if got.Author != "Single Quoted" {
		t.Fatalf("author=%q", got.Author)
	}
	if got.Description != "Has 'single' inside" {
		t.Fatalf("description=%q", got.Description)
	}
}

// -- ParsePSD1 inline-comment handling ------------------------------

func TestParsePSD1InlineComments(t *testing.T) {
	body := []byte(`@{
  ModuleVersion = '1.0.0'  # version tag
  Author        = 'Alice'  # the author
}`)
	got, err := ParsePSD1(body, "x")
	if err != nil {
		t.Fatal(err)
	}
	if got.ModuleVersion != "1.0.0" || got.Author != "Alice" {
		t.Fatalf("inline comments broken: %+v", got)
	}
}

// -- ParsePSD1 user-scoped binary implant fixture --------------------

func TestParsePSD1UserScopedImplant(t *testing.T) {
	body := []byte(`@{
    RootModule = 'bin\Implant.dll'
    ModuleVersion = '0.0.1'
}`)
	got, err := ParsePSD1(body,
		`C:\Users\alice\Documents\PowerShell\Modules\Implant\Implant.psd1`)
	if err != nil {
		t.Fatal(err)
	}
	if !got.IsUserScoped {
		t.Fatal("user path must flag")
	}
	if !got.HasBinaryRootModule {
		t.Fatal(".dll RootModule must flag binary")
	}
	if !got.IsMissingAuthor || !got.IsMissingCompany {
		t.Fatal("missing Author/CompanyName must flag")
	}
}

// -- ParsePSD1 BOM tolerance ----------------------------------------

func TestParsePSD1BOMTolerance(t *testing.T) {
	body := append([]byte{0xEF, 0xBB, 0xBF},
		[]byte(`@{ModuleVersion='1.0.0';Author='X'}`)...)
	got, err := ParsePSD1(body, "x.psd1")
	if err != nil {
		t.Fatalf("BOM should be tolerated: %v", err)
	}
	if got.ModuleVersion != "1.0.0" {
		t.Fatalf("version=%q", got.ModuleVersion)
	}
}

// -- ParsePSD1 empty error ------------------------------------------

func TestParsePSD1Empty(t *testing.T) {
	if _, err := ParsePSD1(nil, "x"); err == nil {
		t.Fatal("empty must error")
	}
}

// -- collector end-to-end -------------------------------------------

func TestFileCollectorWalksRecursively(t *testing.T) {
	tmp := t.TempDir()
	// Mimic: Modules/Foo/1.0.0/Foo.psd1
	fooDir := filepath.Join(tmp, "Foo", "1.0.0")
	must(t, os.MkdirAll(fooDir, 0o755))
	must(t, os.WriteFile(filepath.Join(fooDir, "Foo.psd1"),
		[]byte(`@{ModuleVersion='1.0.0';Author='Alice';CompanyName='AliceCorp';RootModule='Foo.psm1'}`), 0o644))

	// Mimic: Modules/Bar/Bar.psd1 (unversioned)
	barDir := filepath.Join(tmp, "Bar")
	must(t, os.MkdirAll(barDir, 0o755))
	must(t, os.WriteFile(filepath.Join(barDir, "Bar.psd1"),
		[]byte(`@{ModuleVersion='0.5.0';RootModule='bin\Bar.dll'}`), 0o644))

	// Skipped files.
	must(t, os.WriteFile(filepath.Join(tmp, "README.md"), []byte("skip"), 0o644))
	must(t, os.WriteFile(filepath.Join(tmp, ".hidden.psd1"),
		[]byte(`@{ModuleVersion='9.9.9'}`), 0o644))

	c := &fileCollector{
		roots:    []string{tmp},
		readFile: os.ReadFile,
		readDir:  os.ReadDir,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 (skip .md + .hidden), got %d: %+v", len(got), got)
	}

	byName := map[string]Module{}
	for _, m := range got {
		byName[m.ModuleName] = m
	}
	if byName["Foo"].ModuleVersion != "1.0.0" {
		t.Fatalf("Foo wrong: %+v", byName["Foo"])
	}
	if !byName["Bar"].HasBinaryRootModule {
		t.Fatalf("Bar should flag binary: %+v", byName["Bar"])
	}
	if !byName["Bar"].IsMissingAuthor {
		t.Fatal("Bar missing Author must flag")
	}
}

func TestFileCollectorMissingRootsOK(t *testing.T) {
	c := &fileCollector{
		roots:    []string{"/nope-a", "/nope-b"},
		readFile: os.ReadFile,
		readDir:  os.ReadDir,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("missing must not error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want empty, got %d", len(got))
	}
}

// -- SortModules ----------------------------------------------------

func TestSortModulesDeterministic(t *testing.T) {
	in := []Module{
		{ModuleName: "Foo", ModuleVersion: "2.0.0"},
		{ModuleName: "Bar", ModuleVersion: "1.0.0"},
		{ModuleName: "Foo", ModuleVersion: "1.0.0"},
	}
	SortModules(in)
	if in[0].ModuleName != "Bar" {
		t.Fatalf("first=%+v", in[0])
	}
	if in[1].ModuleName != "Foo" || in[1].ModuleVersion != "1.0.0" {
		t.Fatalf("Foo order: in[1]=%+v in[2]=%+v", in[1], in[2])
	}
}

// -- helpers --------------------------------------------------------

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
