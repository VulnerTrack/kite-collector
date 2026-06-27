package windrivers

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPinnedSourceRootStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(SourceSystem32Drivers), "system32-drivers"},
		{string(SourceDriverStore), "driver-store"},
		{string(SourceUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("source_root drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestHashContentsDeterministic(t *testing.T) {
	a := HashContents([]byte("driver-body"))
	b := HashContents([]byte("driver-body"))
	if a != b || len(a) != 64 {
		t.Fatalf("a=%q b=%q", a, b)
	}
}

func TestIsThirdPartySubdirName(t *testing.T) {
	hit := []string{"VendorX", "Intel", "NVIDIA", "Crowdstrike", "vmtools"}
	for _, s := range hit {
		if !IsThirdPartySubdirName(s) {
			t.Fatalf("%q must flag third-party", s)
		}
	}
	miss := []string{"", "UMDF", "umdf", "en-US", "en", "Setup", "SETUP", "DriverData"}
	for _, s := range miss {
		if IsThirdPartySubdirName(s) {
			t.Fatalf("%q must NOT flag third-party", s)
		}
	}
}

func TestIsKernelDriverExtension(t *testing.T) {
	if !IsKernelDriverExtension("ntfs.sys") {
		t.Fatal(".sys must flag")
	}
	if !IsKernelDriverExtension("NTFS.SYS") {
		t.Fatal("case-insensitive .sys must flag")
	}
	for _, n := range []string{"x.dll", "x.exe", "x.inf", ""} {
		if IsKernelDriverExtension(n) {
			t.Fatalf("%q must NOT flag", n)
		}
	}
}

// -- AnnotateSecurity end-to-end -------------------------------------

func TestAnnotateTopLevelSysDriver(t *testing.T) {
	d := Driver{
		FilePath:      `C:\Windows\System32\drivers\ntfs.sys`,
		FileName:      "ntfs.sys",
		FileExtension: ".sys",
		ParentSubdir:  "",
	}
	AnnotateSecurity(&d)
	if !d.IsTopLevel {
		t.Fatal("empty subdir must flag top-level")
	}
	if d.IsThirdPartySubdir {
		t.Fatal("top-level must NOT flag third-party")
	}
	if d.HasNonSysExtension {
		t.Fatal(".sys must NOT flag oddball extension")
	}
}

func TestAnnotateVendorSubdirDriver(t *testing.T) {
	d := Driver{
		ParentSubdir:  "Intel",
		FileExtension: ".sys",
	}
	AnnotateSecurity(&d)
	if d.IsTopLevel {
		t.Fatal("non-empty subdir must NOT flag top-level")
	}
	if !d.IsThirdPartySubdir {
		t.Fatal("vendor subdir must flag third-party")
	}
}

func TestAnnotateInternalSubdirNotThirdParty(t *testing.T) {
	d := Driver{ParentSubdir: "UMDF", FileExtension: ".dll"}
	AnnotateSecurity(&d)
	if d.IsThirdPartySubdir {
		t.Fatal("UMDF is Microsoft-internal; must NOT flag third-party")
	}
}

func TestAnnotateOddExtensionFlags(t *testing.T) {
	d := Driver{FileExtension: ".exe"}
	AnnotateSecurity(&d)
	if !d.HasNonSysExtension {
		t.Fatal(".exe in drivers tree must flag oddball")
	}
	d2 := Driver{FileExtension: ".inf"}
	AnnotateSecurity(&d2)
	if d2.HasNonSysExtension {
		t.Fatal(".inf is a legit companion; must NOT flag")
	}
	d3 := Driver{FileExtension: ".cat"}
	AnnotateSecurity(&d3)
	if d3.HasNonSysExtension {
		t.Fatal(".cat is a legit signed manifest; must NOT flag")
	}
}

// -- collector end-to-end -------------------------------------------

func TestFileCollectorWalksRecursively(t *testing.T) {
	tmp := t.TempDir()
	// Mimic: drivers/ntfs.sys, drivers/UMDF/foo.dll, drivers/Intel/iastor.sys
	must(t, os.WriteFile(filepath.Join(tmp, "ntfs.sys"), []byte("ntfs-body"), 0o644))

	umdfDir := filepath.Join(tmp, "UMDF")
	must(t, os.MkdirAll(umdfDir, 0o755))
	must(t, os.WriteFile(filepath.Join(umdfDir, "WUDFRd.sys"), []byte("wudf-body"), 0o644))

	intelDir := filepath.Join(tmp, "Intel")
	must(t, os.MkdirAll(intelDir, 0o755))
	must(t, os.WriteFile(filepath.Join(intelDir, "iastor.sys"), []byte("iastor-body"), 0o644))
	// .exe sitting in vendor subdir → oddball + third-party.
	must(t, os.WriteFile(filepath.Join(intelDir, "installer.exe"), []byte("exe-body"), 0o644))

	// .ini companion — legit.
	must(t, os.WriteFile(filepath.Join(tmp, "ntfs.ini"), []byte("ini"), 0o644))

	// Hidden file should be skipped.
	must(t, os.WriteFile(filepath.Join(tmp, ".hidden.sys"), []byte("skip"), 0o644))

	c := &fileCollector{
		roots:    []rootSeed{{path: tmp, kind: SourceSystem32Drivers}},
		readFile: os.ReadFile,
		readDir:  os.ReadDir,
		statFile: os.Stat,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 5 {
		t.Fatalf("want 5 (skip .hidden), got %d: %+v", len(got), got)
	}

	byName := map[string]Driver{}
	for _, d := range got {
		byName[d.FileName] = d
	}

	// ntfs.sys at top level.
	ntfs := byName["ntfs.sys"]
	if !ntfs.IsTopLevel || ntfs.IsThirdPartySubdir {
		t.Fatalf("ntfs.sys: %+v", ntfs)
	}
	if ntfs.FileHash == "" {
		t.Fatal("ntfs.sys hash must be populated")
	}

	// WUDFRd.sys under UMDF (Microsoft internal).
	wudf := byName["WUDFRd.sys"]
	if wudf.IsThirdPartySubdir {
		t.Fatal("UMDF subdir must NOT flag third-party")
	}
	if wudf.ParentSubdir != "UMDF" {
		t.Fatalf("parent=%q", wudf.ParentSubdir)
	}

	// iastor.sys under Intel — third-party.
	intel := byName["iastor.sys"]
	if !intel.IsThirdPartySubdir {
		t.Fatal("Intel subdir must flag third-party")
	}

	// installer.exe under Intel — third-party + oddball.
	inst := byName["installer.exe"]
	if !inst.HasNonSysExtension {
		t.Fatal(".exe in drivers tree must flag oddball")
	}

	// ntfs.ini — .ini is a companion, NOT oddball.
	ini := byName["ntfs.ini"]
	if ini.HasNonSysExtension {
		t.Fatal(".ini must NOT flag oddball")
	}
}

func TestFileCollectorMissingRootsOK(t *testing.T) {
	c := &fileCollector{
		roots:    []rootSeed{{path: "/nope-a", kind: SourceSystem32Drivers}},
		readFile: os.ReadFile,
		readDir:  os.ReadDir,
		statFile: os.Stat,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("missing must not error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want empty, got %d", len(got))
	}
}

func TestFileCollectorSkipsOversizedHash(t *testing.T) {
	// Create a fake "driver" whose stat returns a size > limit so
	// the hash branch is skipped. We mock readFile/statFile to
	// force a deterministic outcome rather than allocating a real
	// 64-MB file.
	c := &fileCollector{
		roots: []rootSeed{{path: "/fake-root", kind: SourceSystem32Drivers}},
		readDir: func(p string) ([]os.DirEntry, error) {
			if p == "/fake-root" {
				return []os.DirEntry{fakeEntry{name: "huge.sys"}}, nil
			}
			return nil, os.ErrNotExist
		},
		readFile: func(string) ([]byte, error) {
			t.Fatal("readFile must NOT be called for oversized files")
			return nil, nil
		},
		statFile: func(string) (os.FileInfo, error) {
			return fakeFileInfo{size: MaxFileBytesForHash + 1}, nil
		},
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 row, got %d", len(got))
	}
	if got[0].FileHash != "" {
		t.Fatalf("oversized file must NOT be hashed: hash=%q", got[0].FileHash)
	}
	if got[0].FileSizeBytes <= MaxFileBytesForHash {
		t.Fatalf("expected size>limit, got %d", got[0].FileSizeBytes)
	}
}

// -- SortDrivers ----------------------------------------------------

func TestSortDriversDeterministic(t *testing.T) {
	in := []Driver{
		{FilePath: `C:\drivers\zzz.sys`},
		{FilePath: `C:\drivers\aaa.sys`},
	}
	SortDrivers(in)
	if in[0].FilePath != `C:\drivers\aaa.sys` {
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

// fakeEntry / fakeFileInfo are minimal stubs for the oversize test.
type fakeEntry struct {
	name string
}

func (f fakeEntry) Name() string               { return f.name }
func (fakeEntry) IsDir() bool                  { return false }
func (fakeEntry) Type() os.FileMode            { return 0 }
func (f fakeEntry) Info() (os.FileInfo, error) { return fakeFileInfo{}, nil }

type fakeFileInfo struct {
	size int64
}

func (fakeFileInfo) Name() string       { return "huge.sys" }
func (f fakeFileInfo) Size() int64      { return f.size }
func (fakeFileInfo) Mode() os.FileMode  { return 0 }
func (fakeFileInfo) ModTime() time.Time { return time.Time{} }
func (fakeFileInfo) IsDir() bool        { return false }
func (fakeFileInfo) Sys() any           { return nil }
