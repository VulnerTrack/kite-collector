package winanses

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindCUILIndividual), "cuil-individual"},
		{string(KindCUILBatch), "cuil-batch"},
		{string(KindAuditLog), "audit-log"},
		{string(KindAportesHist), "aportes-historial"},
		{string(KindGrupoFamiliar), "grupo-familiar"},
		{string(KindAUHStatus), "auh-status"},
		{string(KindJubilacion), "jubilacion-status"},
		{string(KindPadron), "padron"},
		{string(KindOther), "other"},
		{string(KindUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestIsCandidateName(t *testing.T) {
	yes := []string{
		"anses_consulta_20111111110.json",
		"consulta_cuil_20111111110.xml",
		"grupo_familiar_20111111110.json",
		"aportes_alice.xml",
		"auh_alice.json",
		"jubilacion_status_alice.json",
		"mias_anses_202506.csv",
		"padron_anses_202506.txt",
		"rrhh_anses_2024.csv",
	}
	no := []string{"", "factura.pdf", "cv.docx"}
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

func TestConsultationKindFromName(t *testing.T) {
	cases := map[string]ConsultationKind{
		"jubilacion_alice.json":         KindJubilacion,
		"pension_alice.json":            KindJubilacion,
		"auh_alice.json":                KindAUHStatus,
		"asignacion_universal_2024.csv": KindAUHStatus,
		"grupo_familiar_alice.json":     KindGrupoFamiliar,
		"aportes_alice_2024.xml":        KindAportesHist,
		"anses_audit_202506.jsonl":      KindAuditLog,
		"log_anses_2024.txt":            KindAuditLog,
		"batch_anses_2024.csv":          KindCUILBatch,
		"lote_anses_2024.csv":           KindCUILBatch,
		"padron_anses_202506.csv":       KindPadron,
		"consulta_cuil_alice.json":      KindCUILIndividual,
		"anses_consulta_alice.json":     KindCUILIndividual,
		"rrhh_general.txt":              KindOther,
		"random.json":                   KindUnknown,
		"":                              KindUnknown,
	}
	for in, want := range cases {
		if got := ConsultationKindFromName(in); got != want {
			t.Fatalf("ConsultationKindFromName(%q)=%q want %q", in, got, want)
		}
	}
}

func TestCuilFingerprint(t *testing.T) {
	cases := []struct {
		in, pfx, sfx4 string
	}{
		{"consulta_cuil_20111111110.xml", "20", "1110"},
		{"anses_27111111114.json", "27", "1114"},
		{"_30-71234567-8_.xml", "", ""}, // 30 is juridical, not natural-person
		{"no-cuil.txt", "", ""},
		{"", "", ""},
	}
	for _, c := range cases {
		gotP, gotS := CuilFingerprint(c.in)
		if gotP != c.pfx || gotS != c.sfx4 {
			t.Fatalf("CuilFingerprint(%q)=(%q,%q) want (%q,%q)",
				c.in, gotP, gotS, c.pfx, c.sfx4)
		}
	}
}

func TestIsValidCuilPrefix(t *testing.T) {
	yes := []string{"20", "23", "24", "27"}
	no := []string{"", "30", "33", "34", "11"}
	for _, v := range yes {
		if !IsValidCuilPrefix(v) {
			t.Fatalf("expected valid: %q", v)
		}
	}
	for _, v := range no {
		if IsValidCuilPrefix(v) {
			t.Fatalf("expected invalid: %q", v)
		}
	}
}

func TestContainsAnyTokenAUH(t *testing.T) {
	yes := [][]byte{
		[]byte(`{"auh":"alta"}`),
		[]byte("status: Asignación Universal por Hijo"),
		[]byte("plan social activo"),
		[]byte("Tarjeta Alimentar"),
	}
	no := [][]byte{[]byte(""), []byte("nothing"), []byte("regular salary")}
	for _, b := range yes {
		if !ContainsAnyToken(b, AUHTokens()) {
			t.Fatalf("expected AUH: %q", b)
		}
	}
	for _, b := range no {
		if ContainsAnyToken(b, AUHTokens()) {
			t.Fatalf("expected NOT AUH: %q", b)
		}
	}
}

func TestContainsAnyTokenJubilacion(t *testing.T) {
	yes := [][]byte{
		[]byte(`{"jubilacion":"activa"}`),
		[]byte("Jubilado/a"),
		[]byte("haber previsional 2024"),
		[]byte("haber jubilatorio"),
	}
	for _, b := range yes {
		if !ContainsAnyToken(b, JubilacionTokens()) {
			t.Fatalf("expected jubilación: %q", b)
		}
	}
}

func TestContainsMinorDate(t *testing.T) {
	yes := [][]byte{
		[]byte(`{"fecha_nacimiento":"2015-06-15"}`),
		[]byte("nacimiento: 2020/01/01"),
		[]byte("hijo nacido 2010-12-31"),
	}
	no := [][]byte{
		[]byte(""),
		[]byte("nacimiento: 1980-01-01"),
		[]byte("year 2007 graduate"), // 2007 < threshold 2008
	}
	for _, b := range yes {
		if !ContainsMinorDate(b) {
			t.Fatalf("expected minor: %q", b)
		}
	}
	for _, b := range no {
		if ContainsMinorDate(b) {
			t.Fatalf("expected NOT minor: %q", b)
		}
	}
}

func TestCountDependents(t *testing.T) {
	cases := map[string]int{
		`<dependiente>x</dependiente><dependiente>y</dependiente>`: 2,
		`{"familiares":[{"hijo":"a"},{"hijo":"b"},{"hijo":"c"}]}`:  3,
		`<root><x/></root>`: 0,
		"":                  0,
	}
	for in, want := range cases {
		if got := CountDependents([]byte(in)); got != want {
			t.Fatalf("CountDependents(%q)=%d want %d", in, got, want)
		}
	}
}

func TestCountLinesAsLog(t *testing.T) {
	cases := map[string]int{
		"":        0,
		"a":       1,
		"a\n":     1,
		"a\nb":    2,
		"a\nb\n":  2,
		"a\nb\nc": 3,
	}
	for in, want := range cases {
		if got := CountLinesAsLog([]byte(in)); got != want {
			t.Fatalf("CountLinesAsLog(%q)=%d want %d", in, got, want)
		}
	}
}

// -- AnnotateSecurity ----------------------------------------------

func TestAnnotateJubilacionExposure(t *testing.T) {
	r := Row{
		ConsultationKind: KindJubilacion,
		TargetCuilPrefix: "27",
		FileMode:         0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasJubilacionStatus {
		t.Fatal("jubilacion kind must flag")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("readable jubilación = exposure")
	}
}

func TestAnnotateBatchAuditLog(t *testing.T) {
	r := Row{
		ConsultationKind:  KindAuditLog,
		ConsultationCount: 100,
		FileMode:          0o600,
	}
	AnnotateSecurity(&r)
	if !r.IsAuditLog || !r.IsBatch {
		t.Fatalf("audit-log + count must flag both: %+v", r)
	}
	if r.IsCredentialExposureRisk {
		t.Fatal("0o600 must NOT flag exposure")
	}
}

func TestAnnotateGrupoFamiliarFromDependentCount(t *testing.T) {
	r := Row{
		ConsultationKind: KindCUILIndividual,
		DependentCount:   2,
		FileMode:         0o600,
	}
	AnnotateSecurity(&r)
	if !r.HasGrupoFamiliar {
		t.Fatal("dependent_count > 0 must flag has_grupo_familiar")
	}
}

func TestAnnotateUnknownReadableNoExposure(t *testing.T) {
	r := Row{ConsultationKind: KindUnknown, FileMode: 0o644}
	AnnotateSecurity(&r)
	if r.IsCredentialExposureRisk {
		t.Fatal("unknown kind must NOT flag exposure")
	}
}

// -- collector end-to-end -----------------------------------------

func TestCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")
	dir := filepath.Join(usersBase, "alice", "Documents", "ANSES")
	must(t, os.MkdirAll(dir, 0o755))

	// Grupo familiar with minor dependent, world-readable.
	famPath := filepath.Join(dir, "grupo_familiar_27111111114.json")
	must(t, os.WriteFile(famPath, []byte(`{
"familiares":[
  {"hijo":"a","fecha_nacimiento":"2015-06-15"},
  {"hijo":"b","fecha_nacimiento":"2018-01-01"}
]
}`), 0o644))

	// Jubilación, locked-down.
	jubPath := filepath.Join(dir, "jubilacion_27000000007.json")
	must(t, os.WriteFile(jubPath, []byte(`{"jubilacion":"activa","haber":50000}`), 0o600))

	// AUH, world-readable.
	auhPath := filepath.Join(dir, "auh_alice.json")
	must(t, os.WriteFile(auhPath, []byte(`{"auh":"alta","monto":40000}`), 0o644))

	// Random — ignored.
	must(t, os.WriteFile(filepath.Join(dir, "random.json"), []byte(`{}`), 0o644))

	// Public — skipped.
	pub := filepath.Join(usersBase, "Public", "Documents", "ANSES")
	must(t, os.MkdirAll(pub, 0o755))
	must(t, os.WriteFile(filepath.Join(pub, "anses_skip.json"), []byte(`{}`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   []string{usersBase},
		getenv:       func(string) string { return "" },
		readFile:     os.ReadFile,
		readDir:      os.ReadDir,
		statFile:     os.Stat,
		now:          func() time.Time { return time.Now() },
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("want 3, got %d: %+v", len(got), got)
	}

	var fam, jub, auh Row
	for _, r := range got {
		switch r.FilePath {
		case famPath:
			fam = r
		case jubPath:
			jub = r
		case auhPath:
			auh = r
		}
	}
	if !fam.HasGrupoFamiliar || fam.DependentCount < 2 {
		t.Fatalf("fam must flag grupo familiar with 2 deps: %+v", fam)
	}
	if !fam.HasMinorDependent {
		t.Fatalf("fam must flag minor dependent: %+v", fam)
	}
	if !fam.IsCredentialExposureRisk {
		t.Fatalf("fam + readable = exposure: %+v", fam)
	}
	if fam.TargetCuilPrefix != "27" || fam.TargetCuilSuffix4 != "1114" {
		t.Fatalf("fam cuil: %+v", fam)
	}

	if !jub.HasJubilacionStatus {
		t.Fatalf("jub must flag jubilacion: %+v", jub)
	}
	if jub.IsCredentialExposureRisk {
		t.Fatalf("0o600 must NOT flag: %+v", jub)
	}

	if !auh.HasAUHStatus {
		t.Fatalf("auh must flag: %+v", auh)
	}
}

func TestCollectorRespectsEnv(t *testing.T) {
	tmp := t.TempDir()
	envDir := filepath.Join(tmp, "custom-anses")
	must(t, os.MkdirAll(envDir, 0o755))
	must(t, os.WriteFile(filepath.Join(envDir, "anses_consulta_27111111114.json"),
		[]byte(`{"auh":"alta"}`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "ANSES_DIR" {
				return envDir
			}
			return ""
		},
		readFile: os.ReadFile,
		readDir:  os.ReadDir,
		statFile: os.Stat,
		now:      func() time.Time { return time.Now() },
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 1 || !got[0].HasAUHStatus {
		t.Fatalf("env-supplied: %+v", got)
	}
}

func TestCollectorMissingPathsOK(t *testing.T) {
	c := &fileCollector{
		installRoots: []string{"/nope-anses"},
		usersBases:   []string{"/nope-users"},
		getenv:       func(string) string { return "" },
		readFile:     os.ReadFile,
		readDir:      os.ReadDir,
		statFile:     os.Stat,
		now:          func() time.Time { return time.Now() },
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
		{FilePath: "z", ConsultationKind: KindAuditLog, TargetCuilPrefix: "20", TargetCuilSuffix4: "1111"},
		{FilePath: "a", ConsultationKind: KindCUILIndividual, TargetCuilPrefix: "27", TargetCuilSuffix4: "1111"},
		{FilePath: "a", ConsultationKind: KindAuditLog, TargetCuilPrefix: "20", TargetCuilSuffix4: "2222"},
	}
	SortRows(in)
	if in[0].FilePath != "a" || in[0].ConsultationKind != KindAuditLog {
		t.Fatalf("first=%+v", in[0])
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
