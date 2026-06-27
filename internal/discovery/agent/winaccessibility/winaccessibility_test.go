package winaccessibility

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHashContentsDeterministic(t *testing.T) {
	a := HashContents([]byte("binary-body"))
	b := HashContents([]byte("binary-body"))
	if a != b || len(a) != 64 {
		t.Fatalf("a=%q b=%q", a, b)
	}
}

func TestCuratedBinariesIncludesAllTargets(t *testing.T) {
	want := []string{
		"sethc.exe", "Utilman.exe", "osk.exe",
		"Magnify.exe", "Narrator.exe", "atbroker.exe",
		"DisplaySwitch.exe",
	}
	got := CuratedBinaries()
	if len(got) != len(want) {
		t.Fatalf("count=%d want %d", len(got), len(want))
	}
	for i, n := range want {
		if got[i] != n {
			t.Fatalf("CuratedBinaries[%d]=%q want %q", i, got[i], n)
		}
	}
}

func TestSizeMatchesReferenceExact(t *testing.T) {
	if !SizeMatchesReference(CmdSizeBytes, CmdSizeBytes) {
		t.Fatal("exact match must flag")
	}
}

func TestSizeMatchesReferenceWithinTolerance(t *testing.T) {
	// Within +5% of CmdSizeBytes — well inside the ±10% window.
	within := CmdSizeBytes + (CmdSizeBytes * 5 / 100)
	if !SizeMatchesReference(within, CmdSizeBytes) {
		t.Fatalf("%d should be within ±10%% of %d", within, CmdSizeBytes)
	}
}

func TestSizeMatchesReferenceOutsideTolerance(t *testing.T) {
	// +15% — outside the ±10% window.
	outside := CmdSizeBytes + (CmdSizeBytes * 15 / 100)
	if SizeMatchesReference(outside, CmdSizeBytes) {
		t.Fatalf("%d should be outside ±10%% of %d", outside, CmdSizeBytes)
	}
}

func TestSizeMatchesReferenceZeros(t *testing.T) {
	if SizeMatchesReference(0, CmdSizeBytes) {
		t.Fatal("zero actual must NOT flag")
	}
	if SizeMatchesReference(CmdSizeBytes, 0) {
		t.Fatal("zero reference must NOT flag")
	}
}

// -- AnnotateSecurity end-to-end -------------------------------------

func TestAnnotateCmdReplacedSethc(t *testing.T) {
	b := Binary{
		FileName:      "sethc.exe",
		FileSizeBytes: CmdSizeBytes, // exact replacement
	}
	AnnotateSecurity(&b)
	if !b.IsCmdSizeMatch {
		t.Fatal("cmd-size match must flag")
	}
	if !b.IsReplacementSuspect {
		t.Fatal("cmd replacement must flag suspect")
	}
}

func TestAnnotatePowerShellReplaced(t *testing.T) {
	b := Binary{
		FileName:      "Utilman.exe",
		FileSizeBytes: PowerShellSizeBytes,
	}
	AnnotateSecurity(&b)
	if !b.IsPowerShellSizeMatch || !b.IsReplacementSuspect {
		t.Fatalf("powershell replacement must flag: %+v", b)
	}
}

func TestAnnotateNormalAccessibilityBinary(t *testing.T) {
	// Real sethc.exe is ~120 KB — well outside both reference
	// windows.
	b := Binary{
		FileName:      "sethc.exe",
		FileSizeBytes: 120_000,
	}
	AnnotateSecurity(&b)
	if b.IsCmdSizeMatch || b.IsPowerShellSizeMatch {
		t.Fatalf("normal binary must NOT flag size match: %+v", b)
	}
	if b.IsReplacementSuspect {
		t.Fatal("normal binary must NOT flag replacement")
	}
}

func TestAnnotateMissingBinary(t *testing.T) {
	b := Binary{
		FileName:  "osk.exe",
		IsMissing: true,
		// FileSizeBytes defaults to 0; ensure size flags stay
		// cleared regardless.
	}
	AnnotateSecurity(&b)
	if b.IsCmdSizeMatch || b.IsPowerShellSizeMatch || b.IsReplacementSuspect {
		t.Fatalf("missing binary must NOT flag any size heuristic: %+v", b)
	}
}

// -- collector end-to-end -------------------------------------------

func TestFileCollectorEmitsRowForEveryCuratedBinary(t *testing.T) {
	tmp := t.TempDir()
	// Only place sethc.exe + Utilman.exe; the rest are missing.
	must(t, os.WriteFile(filepath.Join(tmp, "sethc.exe"),
		make([]byte, CmdSizeBytes), 0o644)) // cmd-size replacement
	must(t, os.WriteFile(filepath.Join(tmp, "Utilman.exe"),
		make([]byte, 120_000), 0o644)) // normal-sized

	c := &fileCollector{
		root:     tmp,
		readFile: os.ReadFile,
		statFile: os.Stat,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	// Every curated binary should produce a row, present or not.
	if len(got) != len(CuratedBinaries()) {
		t.Fatalf("want %d rows, got %d: %+v",
			len(CuratedBinaries()), len(got), got)
	}

	byName := map[string]Binary{}
	for _, b := range got {
		byName[b.FileName] = b
	}

	// sethc.exe replaced by cmd-sized blob → suspect.
	sethc := byName["sethc.exe"]
	if !sethc.IsCmdSizeMatch || !sethc.IsReplacementSuspect {
		t.Fatalf("sethc replacement not flagged: %+v", sethc)
	}
	if sethc.FileHash == "" {
		t.Fatal("sethc hash must be populated")
	}
	if sethc.IsMissing {
		t.Fatal("sethc exists; must NOT flag missing")
	}

	// Utilman.exe normal → clean.
	util := byName["Utilman.exe"]
	if util.IsReplacementSuspect || util.IsMissing {
		t.Fatalf("Utilman must be clean: %+v", util)
	}

	// osk.exe missing → flagged.
	osk := byName["osk.exe"]
	if !osk.IsMissing {
		t.Fatal("osk.exe should flag missing")
	}
	if osk.FileHash != "" {
		t.Fatalf("missing binary must NOT have hash: %q", osk.FileHash)
	}
}

func TestFileCollectorMissingRootEmitsAllMissing(t *testing.T) {
	c := &fileCollector{
		root: "/nope-system32",
		readFile: func(string) ([]byte, error) {
			return nil, fs.ErrNotExist
		},
		statFile: os.Stat,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("missing root must not error: %v", err)
	}
	if len(got) != len(CuratedBinaries()) {
		t.Fatalf("want %d missing rows, got %d", len(CuratedBinaries()), len(got))
	}
	for _, b := range got {
		if !b.IsMissing {
			t.Fatalf("%s should be missing: %+v", b.FileName, b)
		}
	}
}

// -- SortBinaries ---------------------------------------------------

func TestSortBinariesDeterministic(t *testing.T) {
	in := []Binary{
		{FilePath: "z"},
		{FilePath: "a"},
	}
	SortBinaries(in)
	if in[0].FilePath != "a" {
		t.Fatalf("first=%+v", in[0])
	}
}

// -- spot-check: curated set names are System32-compatible ----------

func TestCuratedBinariesAllEndInExe(t *testing.T) {
	for _, n := range CuratedBinaries() {
		if !strings.EqualFold(filepath.Ext(n), ".exe") {
			t.Fatalf("curated %q must end in .exe", n)
		}
	}
}

// -- helpers --------------------------------------------------------

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
