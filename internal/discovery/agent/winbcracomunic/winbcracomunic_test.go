package winbcracomunic

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindA), "tipo-a"},
		{string(KindB), "tipo-b"},
		{string(KindC), "tipo-c"},
		{string(KindP), "tipo-p"},
		{string(KindOther), "other"},
		{string(KindUnknown), "unknown"},
		{string(MateriaCambios), "cambios"},
		{string(MateriaPrevencionLavado), "prevencion-lavado"},
		{string(MateriaComercioExterior), "comercio-exterior"},
		{string(MateriaEncajes), "encajes"},
		{string(MateriaCapitalMinimo), "capital-minimo"},
		{string(MateriaTasas), "tasas"},
		{string(MateriaMonetaria), "monetaria"},
		{string(MateriaDepositos), "depositos"},
		{string(MateriaCreditos), "creditos"},
		{string(MateriaSeguros), "seguros"},
		{string(MateriaCooperativas), "cooperativas"},
		{string(MateriaNormativaGeneral), "normativa-general"},
		{string(MateriaOther), "other"},
		{string(MateriaUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestIsCandidateName(t *testing.T) {
	yes := []string{
		"Coma8137.pdf",
		"comb1234.pdf",
		"comunicacion_a_8137.xml",
		"BCRA_A8137.pdf",
		"normativa_bcra_2024.pdf",
		"comunicacion-p-001.xml",
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

func TestParseNumeroAndFormat(t *testing.T) {
	cases := []struct {
		in        string
		wantKind  ComunicacionKind
		wantSerie int
	}{
		{"Coma8137.pdf", KindA, 8137},
		{"comunicacion_a_8137.xml", KindA, 8137},
		{"comunicacion-a-8137", KindA, 8137},
		{"bcra_b_12345.pdf", KindB, 12345},
		{"COMP_999.pdf", KindP, 999},
		{"random.pdf", KindUnknown, 0},
	}
	for _, c := range cases {
		gotK, gotS := ParseNumero(c.in)
		if gotK != c.wantKind || gotS != c.wantSerie {
			t.Fatalf("ParseNumero(%q)=(%q,%d) want (%q,%d)",
				c.in, gotK, gotS, c.wantKind, c.wantSerie)
		}
	}
	if FormatNumero(KindA, 8137) != "A 8137" {
		t.Fatal("FormatNumero(A,8137)")
	}
	if FormatNumero(KindP, 12) != "P 12" {
		t.Fatal("FormatNumero(P,12)")
	}
	if FormatNumero(KindUnknown, 0) != "" {
		t.Fatal("unknown must format empty")
	}
}

func TestMateriaFromText(t *testing.T) {
	cases := map[string]Materia{
		"Prevención del Lavado de Activos":             MateriaPrevencionLavado,
		"prevencion del financiamiento del terrorismo": MateriaPrevencionLavado,
		"UIF — alcance":                                MateriaPrevencionLavado,
		"Comercio Exterior — importaciones":            MateriaComercioExterior,
		"importaciones y pagos al exterior":            MateriaComercioExterior,
		"Régimen MULC":                                 MateriaCambios,
		"Mercado de cambios":                           MateriaCambios,
		"Tasas de interés activas":                     MateriaTasas,
		"Encajes mínimos":                              MateriaEncajes,
		"Capital mínimo de entidades financieras":      MateriaCapitalMinimo,
		"Depósitos a plazo fijo":                       MateriaDepositos,
		"Créditos hipotecarios":                        MateriaCreditos,
		"Política monetaria":                           MateriaMonetaria,
		"Seguros":                                      MateriaSeguros,
		"Cooperativas y mutuales":                      MateriaCooperativas,
		"":                                             MateriaUnknown,
		"reunión informativa":                          MateriaOther,
	}
	for in, want := range cases {
		if got := MateriaFromText(in); got != want {
			t.Fatalf("MateriaFromText(%q)=%q want %q", in, got, want)
		}
	}
}

func TestIsForexAndAmlMateria(t *testing.T) {
	forex := []Materia{MateriaCambios, MateriaComercioExterior}
	notForex := []Materia{MateriaCreditos, MateriaTasas, MateriaUnknown}
	for _, m := range forex {
		if !IsForexMateria(m) {
			t.Fatalf("expected forex: %q", m)
		}
	}
	for _, m := range notForex {
		if IsForexMateria(m) {
			t.Fatalf("expected NOT forex: %q", m)
		}
	}
	if !IsAmlMateria(MateriaPrevencionLavado) {
		t.Fatal("prevencion-lavado must be AML")
	}
	if IsAmlMateria(MateriaCambios) {
		t.Fatal("cambios must NOT be AML")
	}
}

func TestMaxStringLen(t *testing.T) {
	if MaxStringLen("abc", 10) != "abc" {
		t.Fatal("short pass-through")
	}
	if MaxStringLen("abcdefghij", 4) != "abcd" {
		t.Fatal("ascii truncate")
	}
}

// -- AnnotateSecurity ----------------------------------------------

func TestAnnotateForex(t *testing.T) {
	r := Row{
		ComunicacionKind: KindA,
		Numero:           "A 8137",
		Materia:          MateriaCambios,
		FileMode:         0o644,
	}
	AnnotateSecurity(&r)
	if !r.IsForexRegulation {
		t.Fatal("cambios must flag forex")
	}
	if r.IsAmlRegulation {
		t.Fatal("cambios must NOT flag aml")
	}
	if !r.IsWorldReadable {
		t.Fatal("0o644 must flag world-readable")
	}
}

func TestAnnotateAml(t *testing.T) {
	r := Row{Materia: MateriaPrevencionLavado, FileMode: 0o644}
	AnnotateSecurity(&r)
	if !r.IsAmlRegulation {
		t.Fatal("prevencion-lavado must flag aml")
	}
}

// -- ParseComunicacion ---------------------------------------------

func TestParseComunicacionXML(t *testing.T) {
	body := []byte(`<?xml version="1.0"?>
<comunicacion>
  <numero>A 8137</numero>
  <asunto>Régimen de Comercio Exterior</asunto>
  <materia>Comercio Exterior</materia>
  <fecha_emision>2024-12-15</fecha_emision>
  <fecha_vigencia>2025-01-01</fecha_vigencia>
  <sustituye_a>A 7916</sustituye_a>
</comunicacion>`)
	f, ok := ParseComunicacion(body)
	if !ok {
		t.Fatal("must parse")
	}
	if f.Numero != "A 8137" {
		t.Fatalf("numero=%q", f.Numero)
	}
	if f.AsuntoText == "" {
		t.Fatal("asunto missing")
	}
	if f.MateriaText != "Comercio Exterior" {
		t.Fatalf("materia=%q", f.MateriaText)
	}
	if f.SustituyeA != "A 7916" {
		t.Fatalf("sustituye=%q", f.SustituyeA)
	}
}

func TestParseComunicacionHTMLScrape(t *testing.T) {
	body := []byte(`<html><body>
<p>Comunicación "A" 8137 — Régimen MULC</p>
<p>Asunto: Liquidación de divisas</p>
<p>Materia: cambios</p>
<p>Fecha: 2024-12-15</p>
<p>Sustituye a: A 7916</p>
</body></html>`)
	f, ok := ParseComunicacion(body)
	if !ok {
		t.Fatal("must parse")
	}
	if f.Numero != "A 8137" {
		t.Fatalf("numero=%q", f.Numero)
	}
	if f.AsuntoText == "" || f.MateriaText == "" {
		t.Fatalf("scrape: %+v", f)
	}
}

func TestParseComunicacionEmpty(t *testing.T) {
	if _, ok := ParseComunicacion([]byte("")); ok {
		t.Fatal("empty must NOT parse")
	}
}

// -- collector end-to-end -----------------------------------------

func TestCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")
	dir := filepath.Join(usersBase, "alice", "Documents", "BCRA", "Comunicaciones")
	must(t, os.MkdirAll(dir, 0o755))

	// Forex Com. A 8137 XML.
	forexPath := filepath.Join(dir, "comunicacion_a_8137.xml")
	must(t, os.WriteFile(forexPath, []byte(`<comunicacion>
<numero>A 8137</numero>
<asunto>Régimen de Comercio Exterior - MULC</asunto>
<materia>cambios</materia>
</comunicacion>`), 0o644))

	// AML Com. A 7800 HTML.
	amlPath := filepath.Join(dir, "BCRA_A7800.html")
	must(t, os.WriteFile(amlPath, []byte(`<html><body>
Comunicación "A" 7800
Asunto: Prevención del Lavado de Activos
Materia: prevencion-lavado
</body></html>`), 0o644))

	// PDF — filename-only classification.
	pdfPath := filepath.Join(dir, "Coma8200.pdf")
	must(t, os.WriteFile(pdfPath, []byte("%PDF"), 0o644))

	// Random — ignored.
	must(t, os.WriteFile(filepath.Join(dir, "random.pdf"),
		[]byte("%PDF"), 0o644))

	// Public — skipped.
	pub := filepath.Join(usersBase, "Public", "Documents", "BCRA")
	must(t, os.MkdirAll(pub, 0o755))
	must(t, os.WriteFile(filepath.Join(pub, "Coma9999.pdf"),
		[]byte("%PDF"), 0o644))

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
		t.Fatalf("want 3 (forex+aml+pdf), got %d: %+v", len(got), got)
	}

	var forex, aml, pdf Row
	for _, r := range got {
		switch r.FilePath {
		case forexPath:
			forex = r
		case amlPath:
			aml = r
		case pdfPath:
			pdf = r
		}
	}
	if forex.ComunicacionKind != KindA || forex.NumeroSerie != 8137 {
		t.Fatalf("forex numero: %+v", forex)
	}
	if !forex.IsForexRegulation {
		t.Fatalf("forex must flag forex: %+v", forex)
	}
	if !aml.IsAmlRegulation {
		t.Fatalf("aml must flag aml: %+v", aml)
	}
	if aml.NumeroSerie != 7800 {
		t.Fatalf("aml serie: %+v", aml)
	}
	if pdf.NumeroSerie != 8200 {
		t.Fatalf("pdf filename-only serie: %+v", pdf)
	}
}

func TestCollectorRespectsEnv(t *testing.T) {
	tmp := t.TempDir()
	envDir := filepath.Join(tmp, "custom-bcra")
	must(t, os.MkdirAll(envDir, 0o755))
	must(t, os.WriteFile(filepath.Join(envDir, "Coma8137.pdf"),
		[]byte("%PDF"), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "BCRA_COM_DIR" {
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
	if len(got) != 1 || got[0].NumeroSerie != 8137 {
		t.Fatalf("env-supplied: %+v", got)
	}
}

func TestCollectorMissingPathsOK(t *testing.T) {
	c := &fileCollector{
		installRoots: []string{"/nope-bcra"},
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
		{FilePath: "z", ComunicacionKind: KindA, NumeroSerie: 100},
		{FilePath: "a", ComunicacionKind: KindB, NumeroSerie: 100},
		{FilePath: "a", ComunicacionKind: KindA, NumeroSerie: 200},
	}
	SortRows(in)
	if in[0].FilePath != "a" || in[0].ComunicacionKind != KindA {
		t.Fatalf("first=%+v", in[0])
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
