package winpjn

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindCedula), "cedula"},
		{string(KindProvidencia), "providencia"},
		{string(KindSentencia), "sentencia"},
		{string(KindOficio), "oficio"},
		{string(KindRequerimiento), "requerimiento"},
		{string(KindDemanda), "demanda"},
		{string(KindContestacion), "contestacion"},
		{string(KindOther), "other"},
		{string(KindUnknown), "unknown"},
		{string(ProcesoConcursoPreventivo), "concurso-preventivo"},
		{string(ProcesoQuiebra), "quiebra"},
		{string(ProcesoEjecucion), "ejecucion"},
		{string(ProcesoEmbargo), "embargo"},
		{string(ProcesoInhibicion), "inhibicion"},
		{string(ProcesoAlimentos), "alimentos"},
		{string(ProcesoLaboral), "laboral"},
		{string(ProcesoCivil), "civil"},
		{string(ProcesoComercial), "comercial"},
		{string(ProcesoPenal), "penal"},
		{string(ProcesoOtro), "otro"},
		{string(ProcesoUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestNotificationKindFromName(t *testing.T) {
	cases := map[string]NotificationKind{
		"cedula_001.pdf":             KindCedula,
		"cédula_002.xml":             KindCedula,
		"providencia_2024_123.xml":   KindProvidencia,
		"sentencia_acme.pdf":         KindSentencia,
		"oficio_banco.pdf":           KindOficio,
		"requerimiento_005.xml":      KindRequerimiento,
		"demanda_actor.pdf":          KindDemanda,
		"contestacion_demandado.xml": KindContestacion,
		"contestación.pdf":           KindContestacion,
		"notif_2024.pdf":             KindOther,
		"pjn_001.pdf":                KindOther,
		"cuij_30712345678.xml":       KindOther,
		"random.pdf":                 KindUnknown,
		"":                           KindUnknown,
	}
	for in, want := range cases {
		if got := NotificationKindFromName(in); got != want {
			t.Fatalf("NotificationKindFromName(%q)=%q want %q", in, got, want)
		}
	}
}

func TestTipoProcesoFromText(t *testing.T) {
	cases := map[string]TipoProceso{
		"concurso preventivo de ACME S.A.":        ProcesoConcursoPreventivo,
		"Concurso-Preventivo":                     ProcesoConcursoPreventivo,
		"QUIEBRA de Beta S.R.L.":                  ProcesoQuiebra,
		"juicio ejecutivo s/ ejecución prendaria": ProcesoEjecucion,
		"embargo preventivo":                      ProcesoEmbargo,
		"INHIBICIÓN GENERAL DE BIENES":            ProcesoInhibicion,
		"inhibicion":                              ProcesoInhibicion,
		"alimentos provisorios":                   ProcesoAlimentos,
		"reclamación laboral s/ despido":          ProcesoLaboral,
		"fuero comercial":                         ProcesoComercial,
		"civil ordinario":                         ProcesoCivil,
		"querella penal":                          ProcesoPenal,
		"":                                        ProcesoUnknown,
		"otro tema":                               ProcesoUnknown,
	}
	for in, want := range cases {
		if got := TipoProcesoFromText(in); got != want {
			t.Fatalf("TipoProcesoFromText(%q)=%q want %q", in, got, want)
		}
	}
}

func TestIsInsolvencyAndSeizureKind(t *testing.T) {
	insolv := []TipoProceso{ProcesoConcursoPreventivo, ProcesoQuiebra}
	notInsolv := []TipoProceso{
		ProcesoEjecucion, ProcesoEmbargo, ProcesoInhibicion,
		ProcesoLaboral, ProcesoCivil, ProcesoUnknown,
	}
	for _, t1 := range insolv {
		if !IsInsolvencyKind(t1) {
			t.Fatalf("expected insolvency: %q", t1)
		}
	}
	for _, t1 := range notInsolv {
		if IsInsolvencyKind(t1) {
			t.Fatalf("expected NOT insolvency: %q", t1)
		}
	}
	seize := []TipoProceso{ProcesoEmbargo, ProcesoInhibicion}
	notSeize := []TipoProceso{ProcesoConcursoPreventivo, ProcesoEjecucion, ProcesoCivil}
	for _, t1 := range seize {
		if !IsAssetSeizureKind(t1) {
			t.Fatalf("expected seizure: %q", t1)
		}
	}
	for _, t1 := range notSeize {
		if IsAssetSeizureKind(t1) {
			t.Fatalf("expected NOT seizure: %q", t1)
		}
	}
}

func TestIsCandidateName(t *testing.T) {
	yes := []string{
		"cedula_001.pdf",
		"NOTIF_002.xml",
		"providencia.pdf",
		"cuij_30712345678.xml",
		"lex-doctor-001.pdf",
	}
	no := []string{
		"factura.pdf",
		"",
		"contract.docx",
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

func TestCuitFingerprint(t *testing.T) {
	cases := []struct {
		in, pfx, sfx4 string
	}{
		{"cedula_30712345678.pdf", "30", "5678"},
		{"cedula_30-71234567-8.pdf", "30", "5678"},
		{"cedula_no_cuit.pdf", "", ""},
		{"cedula_11-12345678-9.pdf", "", ""}, // invalid prefix
	}
	for _, c := range cases {
		gotP, gotS := CuitFingerprint(c.in)
		if gotP != c.pfx || gotS != c.sfx4 {
			t.Fatalf("CuitFingerprint(%q)=(%q,%q) want (%q,%q)",
				c.in, gotP, gotS, c.pfx, c.sfx4)
		}
	}
}

func TestCuijFingerprint(t *testing.T) {
	// Modern 13-digit: type(1) + circ(2) + año(4) + corr(6)
	year, sfx := CuijFingerprint("expte_1012024000123.pdf")
	if year != "2024" || sfx != "0123" {
		t.Fatalf("modern: year=%q sfx=%q", year, sfx)
	}
	// Legacy NNNNN/YYYY
	year, sfx = CuijFingerprint("expte_12345/2024.pdf")
	if year != "2024" || sfx != "2345" {
		t.Fatalf("legacy: year=%q sfx=%q", year, sfx)
	}
	// No match
	year, sfx = CuijFingerprint("nothing.pdf")
	if year != "" || sfx != "" {
		t.Fatalf("no-match: year=%q sfx=%q", year, sfx)
	}
}

func TestTruncateString(t *testing.T) {
	if TruncateString("a", 10) != "a" {
		t.Fatal("short pass-through")
	}
	if TruncateString("abcdefghij", 4) != "abcd" {
		t.Fatal("ascii truncate")
	}
}

// -- AnnotateSecurity ----------------------------------------------

func TestAnnotateInsolvencyExposure(t *testing.T) {
	r := Row{
		NotificationKind: KindSentencia,
		TipoProceso:      ProcesoQuiebra,
		TargetCuitPrefix: "30",
		FileMode:         0o644,
	}
	AnnotateSecurity(&r)
	if !r.IsInsolvencyProceeding {
		t.Fatal("quiebra must flag insolvency")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("CUIT + readable must flag exposure")
	}
}

func TestAnnotateSeizure(t *testing.T) {
	r := Row{
		NotificationKind: KindOficio,
		TipoProceso:      ProcesoEmbargo,
		Juzgado:          "Juzgado Civil 10",
		FileMode:         0o644,
	}
	AnnotateSecurity(&r)
	if !r.IsAssetSeizure {
		t.Fatal("embargo must flag seizure")
	}
	if r.IsInsolvencyProceeding {
		t.Fatal("embargo is NOT insolvency proceeding")
	}
}

func TestAnnotate0600Clean(t *testing.T) {
	r := Row{
		NotificationKind: KindCedula,
		TipoProceso:      ProcesoCivil,
		TargetCuitPrefix: "30",
		FileMode:         0o600,
	}
	AnnotateSecurity(&r)
	if r.IsCredentialExposureRisk {
		t.Fatal("0o600 must NOT flag exposure")
	}
}

// -- ParseSiblingMetadata ------------------------------------------

func TestParseSiblingMetadataXML(t *testing.T) {
	body := []byte(`<?xml version="1.0"?>
<notificacion>
  <caratula>ACME SA s/ Quiebra</caratula>
  <tipoProceso>Quiebra</tipoProceso>
  <juzgado>Juzgado Nacional de Primera Instancia en lo Comercial 5</juzgado>
  <secretaria>Sec. 10</secretaria>
  <cuit>30-71234567-8</cuit>
  <cuij>2012024000123</cuij>
  <fecha>2024-06-15</fecha>
</notificacion>`)
	f, ok := ParseSiblingMetadata(body)
	if !ok {
		t.Fatal("must parse")
	}
	if f.TipoProcesoText != "Quiebra" {
		t.Fatalf("tipo=%q", f.TipoProcesoText)
	}
	if f.JuzgadoText == "" || f.CuitRaw != "30-71234567-8" {
		t.Fatalf("fields: %+v", f)
	}
	if f.CuijRaw != "2012024000123" || f.FechaText != "2024-06-15" {
		t.Fatalf("cuij/fecha: %+v", f)
	}
}

func TestParseSiblingMetadataTextScrape(t *testing.T) {
	body := []byte(`Tipo de Proceso: Concurso Preventivo
Juzgado: Comercial 5
Secretaría: Sec. 10
CUIT: 30-71234567-8
CUIJ: 12345/2024
Fecha: 2024-06-15
Carátula: ACME SA s/ Concurso
`)
	f, ok := ParseSiblingMetadata(body)
	if !ok {
		t.Fatal("must parse")
	}
	if f.TipoProcesoText != "Concurso Preventivo" {
		t.Fatalf("tipo=%q", f.TipoProcesoText)
	}
	if f.CuitRaw != "30-71234567-8" {
		t.Fatalf("cuit=%q", f.CuitRaw)
	}
	if f.CuijRaw != "12345/2024" {
		t.Fatalf("cuij=%q", f.CuijRaw)
	}
	if f.Caratula == "" {
		t.Fatal("caratula missing")
	}
}

func TestParseSiblingMetadataEmpty(t *testing.T) {
	if _, ok := ParseSiblingMetadata([]byte("")); ok {
		t.Fatal("empty must NOT parse")
	}
}

// -- collector end-to-end -----------------------------------------

func TestCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")
	alice := filepath.Join(usersBase, "alice", "Downloads")
	must(t, os.MkdirAll(alice, 0o755))

	// Cedula PDF with insolvency tipo from filename + CUIT in name.
	quiebraPath := filepath.Join(alice, "cedula_quiebra_30712345678_001.pdf")
	must(t, os.WriteFile(quiebraPath, []byte("%PDF-fake"), 0o644))

	// Providencia XML with embargo from sibling metadata.
	embPath := filepath.Join(alice, "providencia_embargo_001.xml")
	must(t, os.WriteFile(embPath, []byte(`<notificacion>
<tipoProceso>Embargo Preventivo</tipoProceso>
<juzgado>Juzgado Civil 5</juzgado>
<cuit>30000000007</cuit>
<cuij>2012024000456</cuij>
</notificacion>`), 0o644))

	// Lock-down a non-PJN file — must be ignored.
	must(t, os.WriteFile(filepath.Join(alice, "random.pdf"), []byte("x"), 0o644))

	// Public must be skipped.
	pubDir := filepath.Join(usersBase, "Public", "Downloads")
	must(t, os.MkdirAll(pubDir, 0o755))
	must(t, os.WriteFile(filepath.Join(pubDir, "cedula_skip.pdf"),
		[]byte("x"), 0o644))

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
	if len(got) != 2 {
		t.Fatalf("want 2 (quiebra+embargo), got %d: %+v", len(got), got)
	}

	var qui, emb Row
	for _, r := range got {
		switch r.FilePath {
		case quiebraPath:
			qui = r
		case embPath:
			emb = r
		}
	}
	if qui.FilePath == "" || emb.FilePath == "" {
		t.Fatalf("missing rows: %+v", got)
	}
	if !qui.IsInsolvencyProceeding {
		t.Fatalf("quiebra must flag insolvency: %+v", qui)
	}
	if qui.TargetCuitPrefix != "30" || qui.TargetCuitSuffix4 != "5678" {
		t.Fatalf("qui cuit: %+v", qui)
	}
	if !qui.IsCredentialExposureRisk {
		t.Fatalf("qui CUIT + readable must flag: %+v", qui)
	}
	if !qui.IsRecent {
		t.Fatalf("qui recently-written must flag recent: %+v", qui)
	}

	if !emb.IsAssetSeizure {
		t.Fatalf("embargo XML must flag seizure: %+v", emb)
	}
	if emb.TargetCuitPrefix != "30" {
		t.Fatalf("emb cuit from XML: %+v", emb)
	}
	if emb.CuijYear != "2024" {
		t.Fatalf("emb cuij year from XML: %+v", emb)
	}
	if emb.Juzgado == "" {
		t.Fatalf("emb juzgado from XML: %+v", emb)
	}
}

func TestCollectorRespectsPJNHomeEnv(t *testing.T) {
	tmp := t.TempDir()
	envDir := filepath.Join(tmp, "custom-pjn")
	must(t, os.MkdirAll(envDir, 0o755))
	must(t, os.WriteFile(filepath.Join(envDir, "cedula_quiebra_30712345678.pdf"),
		[]byte("%PDF"), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "PJN_HOME" {
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
	if len(got) != 1 {
		t.Fatalf("want 1, got %d: %+v", len(got), got)
	}
	if !got[0].IsInsolvencyProceeding {
		t.Fatalf("env-supplied quiebra must flag: %+v", got[0])
	}
}

func TestCollectorMissingPathsOK(t *testing.T) {
	c := &fileCollector{
		installRoots: []string{"/nope-pjn"},
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

func TestRecentlyWindowFlagsOld(t *testing.T) {
	tmp := t.TempDir()
	envDir := filepath.Join(tmp, "old")
	must(t, os.MkdirAll(envDir, 0o755))
	oldPath := filepath.Join(envDir, "cedula_quiebra_30712345678.pdf")
	must(t, os.WriteFile(oldPath, []byte("%PDF"), 0o644))
	past := time.Now().Add(-200 * 24 * time.Hour)
	must(t, os.Chtimes(oldPath, past, past))

	c := &fileCollector{
		installRoots: []string{envDir},
		usersBases:   nil,
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
	if len(got) != 1 {
		t.Fatalf("want 1, got %d", len(got))
	}
	if got[0].IsRecent {
		t.Fatal("200-day-old must NOT flag recent")
	}
}

func TestSortRowsDeterministic(t *testing.T) {
	in := []Row{
		{FilePath: "z", TargetCuitPrefix: "30", TargetCuitSuffix4: "1111"},
		{FilePath: "a", TargetCuitPrefix: "30", TargetCuitSuffix4: "2222"},
		{FilePath: "a", TargetCuitPrefix: "20", TargetCuitSuffix4: "0001"},
	}
	SortRows(in)
	if in[0].FilePath != "a" || in[0].TargetCuitPrefix != "20" {
		t.Fatalf("first=%+v", in[0])
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
