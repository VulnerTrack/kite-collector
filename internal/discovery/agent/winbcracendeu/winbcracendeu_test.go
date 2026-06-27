package winbcracendeu

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(SnapshotConsolidated), "consolidated"},
		{string(SnapshotPerEntity), "per-entity"},
		{string(SnapshotPadron), "padron"},
		{string(SnapshotUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestSnapshotKindFromName(t *testing.T) {
	cases := map[string]SnapshotKind{
		"cendeu_202506.csv":                SnapshotConsolidated,
		"central_deudores_202506.txt":      SnapshotConsolidated,
		"cendeu_30712345678.csv":           SnapshotPerEntity,
		"central-deudores-30712345678.txt": SnapshotPerEntity,
		"padron_deudores_202506.zip":       SnapshotPadron,
		"padron-deudores_202506.zip":       SnapshotPadron,
		"random.csv":                       SnapshotUnknown,
		"":                                 SnapshotUnknown,
		"deudores_202506.csv":              SnapshotConsolidated,
	}
	for in, want := range cases {
		if got := SnapshotKindFromName(in); got != want {
			t.Fatalf("SnapshotKindFromName(%q)=%q want %q", in, got, want)
		}
	}
}

func TestIsCandidateName(t *testing.T) {
	yes := []string{
		"cendeu_202506.csv",
		"central_deudores_30712345678.txt",
		"padron_deudores_202506.zip",
		"DEUDORES-SF-202506.txt",
	}
	no := []string{
		"random.csv",
		"",
		"facturas_202506.csv",
	}
	for _, v := range yes {
		if !IsCandidateName(v) {
			t.Fatalf("expected candidate: %q", v)
		}
	}
	for _, v := range no {
		if IsCandidateName(v) {
			t.Fatalf("expected NOT candidate: %q", v)
		}
	}
}

func TestCuitFingerprintFromName(t *testing.T) {
	cases := []struct {
		in, pfx, sfx4 string
	}{
		{"cendeu_30712345678.csv", "30", "5678"},
		{"cendeu_30-71234567-8.csv", "30", "5678"},
		{"no-cuit.csv", "", ""},
		{"cendeu_11-12345678-9.csv", "", ""}, // invalid prefix
	}
	for _, c := range cases {
		gotP, gotS := CuitFingerprintFromName(c.in)
		if gotP != c.pfx || gotS != c.sfx4 {
			t.Fatalf("CuitFingerprintFromName(%q)=(%q,%q) want (%q,%q)",
				c.in, gotP, gotS, c.pfx, c.sfx4)
		}
	}
}

func TestPeriodFromName(t *testing.T) {
	cases := map[string]string{
		"cendeu_202506.csv":    "202506",
		"cendeu_2025-06.csv":   "202506",
		"cendeu_2025_06.csv":   "202506",
		"cendeu_no_period.csv": "",
		"cendeu_2025-13.csv":   "", // invalid month
	}
	for in, want := range cases {
		if got := PeriodFromName(in); got != want {
			t.Fatalf("PeriodFromName(%q)=%q want %q", in, got, want)
		}
	}
}

// -- AnnotateSecurity ----------------------------------------------

func TestAnnotateHighRiskExposure(t *testing.T) {
	r := Row{
		SnapshotKind: SnapshotConsolidated,
		FileMode:     0o644,
		FileSize:     5 << 20,
		MaxSituacion: 5,
	}
	AnnotateSecurity(&r)
	if !r.IsHighValueFile {
		t.Fatal("5 MiB must flag high-value")
	}
	if !r.HasHighRiskDebtors {
		t.Fatal("situacion 5 must flag high-risk")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("consolidated + readable must flag exposure")
	}
}

func TestAnnotateNormalSituacionClean(t *testing.T) {
	r := Row{
		SnapshotKind: SnapshotConsolidated,
		FileMode:     0o600,
		MaxSituacion: 2,
	}
	AnnotateSecurity(&r)
	if r.HasHighRiskDebtors {
		t.Fatal("situacion 2 must NOT flag high-risk")
	}
	if r.IsCredentialExposureRisk {
		t.Fatal("0o600 must NOT flag exposure")
	}
}

func TestAnnotateMaxSit4Borderline(t *testing.T) {
	r := Row{
		SnapshotKind: SnapshotPerEntity,
		FileMode:     0o644,
		MaxSituacion: 4,
	}
	AnnotateSecurity(&r)
	if !r.HasHighRiskDebtors {
		t.Fatal("situacion 4 is borderline-insolvent and must flag")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("per-entity + readable must flag exposure")
	}
}

func TestAnnotateUnknownKindNoExposure(t *testing.T) {
	r := Row{
		SnapshotKind: SnapshotUnknown,
		FileMode:     0o644,
		MaxSituacion: 5,
	}
	AnnotateSecurity(&r)
	if r.IsCredentialExposureRisk {
		t.Fatal("unknown-kind must NOT flag exposure even if readable")
	}
}

// -- ParseCENDEUSnapshot -------------------------------------------

func TestParseCENDEUSnapshotTypical(t *testing.T) {
	body := []byte(`# header line
30712345678,1000,3,SUC-001
30000000007,5000,5,SUC-002
20111111112,200,1,SUC-003
30000000007,50,4,SUC-002
# end
cheques rechazados: 2
`)
	stats := ParseCENDEUSnapshot(body)
	// 4 data rows + 1 footer line counted as record
	if stats.RecordCount != 5 {
		t.Fatalf("RecordCount=%d want 5", stats.RecordCount)
	}
	// Distinct CUITs: 3.
	if stats.DistinctEntityCount != 3 {
		t.Fatalf("DistinctEntityCount=%d want 3", stats.DistinctEntityCount)
	}
	if stats.MaxSituacion != 5 {
		t.Fatalf("MaxSituacion=%d want 5", stats.MaxSituacion)
	}
	if !stats.HasChequesRechazados {
		t.Fatal("must detect cheques rechazados")
	}
}

func TestParseCENDEUSnapshotExplicitSituacionField(t *testing.T) {
	body := []byte(`cuit=30712345678 situacion=6
cuit=30000000007 sit=2
`)
	stats := ParseCENDEUSnapshot(body)
	if stats.MaxSituacion != 6 {
		t.Fatalf("MaxSituacion=%d want 6", stats.MaxSituacion)
	}
	if stats.DistinctEntityCount != 2 {
		t.Fatalf("DistinctEntityCount=%d want 2", stats.DistinctEntityCount)
	}
}

func TestParseCENDEUSnapshotBOMTolerance(t *testing.T) {
	body := append([]byte{0xEF, 0xBB, 0xBF},
		[]byte("30712345678,1\n")...)
	stats := ParseCENDEUSnapshot(body)
	if stats.RecordCount != 1 {
		t.Fatalf("RecordCount=%d want 1", stats.RecordCount)
	}
	if stats.MaxSituacion != 1 {
		t.Fatalf("MaxSituacion=%d want 1", stats.MaxSituacion)
	}
}

func TestParseCENDEUSnapshotEmpty(t *testing.T) {
	stats := ParseCENDEUSnapshot([]byte(""))
	if stats.RecordCount != 0 || stats.DistinctEntityCount != 0 {
		t.Fatalf("empty must return zero stats: %+v", stats)
	}
}

// -- collector end-to-end -----------------------------------------

func TestCollectorWalksBCRA(t *testing.T) {
	tmp := t.TempDir()
	root := filepath.Join(tmp, "BCRA", "CENDEU")
	must(t, os.MkdirAll(root, 0o755))

	// Consolidated snapshot, world-readable, high-risk inside.
	consolPath := filepath.Join(root, "cendeu_202506.csv")
	must(t, os.WriteFile(consolPath, []byte(`# BCRA CENDEU
30712345678,1000,3
30000000007,5000,5
20111111112,200,1
`), 0o644))

	// Per-entity locked-down.
	perEntPath := filepath.Join(root, "cendeu_30712345678.csv")
	must(t, os.WriteFile(perEntPath, []byte(`30712345678,500,2
`), 0o600))

	// Padrón, world-readable.
	padronPath := filepath.Join(root, "padron_deudores_202506.zip")
	must(t, os.WriteFile(padronPath, []byte("PK\x03\x04 fake zip"), 0o644))

	// Unrelated file — must be ignored.
	must(t, os.WriteFile(filepath.Join(root, "random.csv"),
		[]byte("x"), 0o644))

	c := &fileCollector{
		installRoots: []string{filepath.Join(tmp, "BCRA")},
		getenv:       func(string) string { return "" },
		readFile:     os.ReadFile,
		readDir:      os.ReadDir,
		statFile:     os.Stat,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("want 3 (consol+per-entity+padron), got %d: %+v", len(got), got)
	}

	var consol, perEnt, padron Row
	for _, r := range got {
		switch r.FilePath {
		case consolPath:
			consol = r
		case perEntPath:
			perEnt = r
		case padronPath:
			padron = r
		}
	}
	if consol.SnapshotKind != SnapshotConsolidated || consol.PeriodYYYYMM != "202506" {
		t.Fatalf("consol: %+v", consol)
	}
	if !consol.HasHighRiskDebtors {
		t.Fatalf("consol must flag high-risk: %+v", consol)
	}
	if !consol.IsCredentialExposureRisk {
		t.Fatalf("consol + readable must flag exposure: %+v", consol)
	}
	if consol.DistinctEntityCount != 3 {
		t.Fatalf("consol distinct=%d want 3", consol.DistinctEntityCount)
	}

	if perEnt.SnapshotKind != SnapshotPerEntity {
		t.Fatalf("perEnt kind=%q", perEnt.SnapshotKind)
	}
	if perEnt.TargetCuitPrefix != "30" || perEnt.TargetCuitSuffix4 != "5678" {
		t.Fatalf("perEnt cuit: %+v", perEnt)
	}
	if perEnt.IsCredentialExposureRisk {
		t.Fatalf("0o600 must NOT flag: %+v", perEnt)
	}

	if padron.SnapshotKind != SnapshotPadron {
		t.Fatalf("padron kind=%q", padron.SnapshotKind)
	}
	if !padron.IsCredentialExposureRisk {
		t.Fatalf("padron + readable must flag exposure: %+v", padron)
	}
}

func TestCollectorRespectsBCRAEnv(t *testing.T) {
	tmp := t.TempDir()
	envDir := filepath.Join(tmp, "custom-bcra")
	must(t, os.MkdirAll(envDir, 0o755))
	must(t, os.WriteFile(filepath.Join(envDir, "cendeu_202506.csv"),
		[]byte("30712345678,1,3\n"), 0o644))

	c := &fileCollector{
		installRoots: nil,
		getenv: func(k string) string {
			if k == "BCRA_HOME" {
				return envDir
			}
			return ""
		},
		readFile: os.ReadFile,
		readDir:  os.ReadDir,
		statFile: os.Stat,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 1 || got[0].SnapshotKind != SnapshotConsolidated {
		t.Fatalf("env-root: %+v", got)
	}
}

func TestCollectorMissingRootsOK(t *testing.T) {
	c := &fileCollector{
		installRoots: []string{"/nope/BCRA"},
		getenv:       func(string) string { return "" },
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

func TestSortRowsDeterministic(t *testing.T) {
	in := []Row{
		{FilePath: "z", PeriodYYYYMM: "202506"},
		{FilePath: "a", PeriodYYYYMM: "202506"},
		{FilePath: "a", PeriodYYYYMM: "202505"},
	}
	SortRows(in)
	if in[0].FilePath != "a" || in[0].PeriodYYYYMM != "202505" {
		t.Fatalf("first=%+v", in[0])
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
