package winigj

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(ActoActaConstitutiva), "acta-constitutiva"},
		{string(ActoEstatutoSocial), "estatuto-social"},
		{string(ActoReformaEstatuto), "reforma-estatuto"},
		{string(ActoDesignacionDirectorio), "designacion-directorio"},
		{string(ActoAsambleaOrdinaria), "asamblea-ordinaria"},
		{string(ActoAsambleaExtraord), "asamblea-extraordinaria"},
		{string(ActoReorganizacion), "reorganizacion"},
		{string(ActoDisolucion), "disolucion"},
		{string(ActoLiquidacion), "liquidacion"},
		{string(ActoBalance), "balance"},
		{string(ActoOther), "other"},
		{string(ActoUnknown), "unknown"},
		{string(EstadoTramite), "tramite"},
		{string(EstadoInscripto), "inscripto"},
		{string(EstadoObservado), "observado"},
		{string(EstadoRechazado), "rechazado"},
		{string(EstadoDesistido), "desistido"},
		{string(EstadoUnknown), "unknown"},
		{string(TipoSA), "sa"},
		{string(TipoSRL), "srl"},
		{string(TipoSAS), "sas"},
		{string(TipoAsociacion), "asociacion"},
		{string(TipoFundacion), "fundacion"},
		{string(TipoCooperativa), "cooperativa"},
		{string(TipoOther), "other"},
		{string(TipoUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestIsCandidateName(t *testing.T) {
	yes := []string{
		"acta_constitutiva_acme.pdf",
		"estatuto_social_acme.pdf",
		"designacion_directorio_2024.xml",
		"asamblea_ordinaria_2024.pdf",
		"asamblea_extraordinaria_2024.pdf",
		"reorganizacion_fusion_2024.pdf",
		"disolucion_acme.pdf",
		"liquidacion_acme.pdf",
		"IGJ_1234567.pdf",
		"sociedad_anonima_acme.pdf",
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

func TestActoKindFromName(t *testing.T) {
	cases := map[string]ActoKind{
		"acta_constitutiva_acme.pdf":       ActoActaConstitutiva,
		"acta-constitutiva.pdf":            ActoActaConstitutiva,
		"estatuto_social.pdf":              ActoEstatutoSocial,
		"reforma_estatuto_2024.pdf":        ActoReformaEstatuto,
		"designacion_directorio_2024.pdf":  ActoDesignacionDirectorio,
		"asamblea_extraordinaria_2024.pdf": ActoAsambleaExtraord,
		"asamblea_ordinaria_2024.pdf":      ActoAsambleaOrdinaria,
		"asamblea_2024.pdf":                ActoAsambleaOrdinaria,
		"fusion_acme_beta.pdf":             ActoReorganizacion,
		"escision_acme.pdf":                ActoReorganizacion,
		"reorganizacion_2024.pdf":          ActoReorganizacion,
		"liquidacion_acme.pdf":             ActoLiquidacion,
		"disolucion_acme.pdf":              ActoDisolucion,
		"balance_2024.pdf":                 ActoBalance,
		"IGJ_1234567.pdf":                  ActoOther,
		"random.pdf":                       ActoUnknown,
		"":                                 ActoUnknown,
	}
	for in, want := range cases {
		if got := ActoKindFromName(in); got != want {
			t.Fatalf("ActoKindFromName(%q)=%q want %q", in, got, want)
		}
	}
}

func TestTipoSocietarioFromText(t *testing.T) {
	cases := map[string]TipoSocietario{
		"ACME S.A.":                TipoSA,
		"Sociedad Anónima":         TipoSA,
		"Beta S.R.L.":              TipoSRL,
		"Responsabilidad Limitada": TipoSRL,
		"Acme SAS":                 TipoSAS,
		"Acciones Simplificada":    TipoSAS,
		"Asociación Civil":         TipoAsociacion,
		"Fundación X":              TipoFundacion,
		"Cooperativa Y":            TipoCooperativa,
		"":                         TipoUnknown,
		"otra cosa":                TipoOther,
	}
	for in, want := range cases {
		if got := TipoSocietarioFromText(in); got != want {
			t.Fatalf("TipoSocietarioFromText(%q)=%q want %q", in, got, want)
		}
	}
}

func TestEstadoFromText(t *testing.T) {
	cases := map[string]Estado{
		"Inscripto":  EstadoInscripto,
		"Registered": EstadoInscripto,
		"En trámite": EstadoTramite,
		"pending":    EstadoTramite,
		"Observado":  EstadoObservado,
		"Rechazado":  EstadoRechazado,
		"Desistido":  EstadoDesistido,
		"":           EstadoUnknown,
		"otra":       EstadoUnknown,
	}
	for in, want := range cases {
		if got := EstadoFromText(in); got != want {
			t.Fatalf("EstadoFromText(%q)=%q want %q", in, got, want)
		}
	}
}

func TestCuitFingerprint(t *testing.T) {
	cases := []struct {
		in, pfx, sfx4 string
	}{
		{"acta_constitutiva_30712345678.pdf", "30", "5678"},
		{"30-71234567-8", "30", "5678"},
		{"no-cuit", "", ""},
		{"11-12345678-9", "", ""},
	}
	for _, c := range cases {
		gotP, gotS := CuitFingerprint(c.in)
		if gotP != c.pfx || gotS != c.sfx4 {
			t.Fatalf("CuitFingerprint(%q)=(%q,%q) want (%q,%q)",
				c.in, gotP, gotS, c.pfx, c.sfx4)
		}
	}
}

func TestCorrelativoFromText(t *testing.T) {
	cases := map[string]string{
		"IGJ_1234567.pdf":      "1234567",
		"IGJ-1234567.pdf":      "1234567",
		"expte_igj_999999.pdf": "999999",
		"random.pdf":           "",
		"":                     "",
	}
	for in, want := range cases {
		if got := CorrelativoFromText(in); got != want {
			t.Fatalf("CorrelativoFromText(%q)=%q want %q", in, got, want)
		}
	}
}

// -- AnnotateSecurity ----------------------------------------------

func TestAnnotateDirectorioChange(t *testing.T) {
	r := Row{
		ActoKind:           ActoDesignacionDirectorio,
		SociedadCuitPrefix: "30",
		FileMode:           0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasDirectorioChange {
		t.Fatal("designacion-directorio must flag directorio change")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("PII + readable must flag exposure")
	}
}

func TestAnnotateReorganizacion(t *testing.T) {
	r := Row{ActoKind: ActoReorganizacion, SociedadCuitPrefix: "30", FileMode: 0o600}
	AnnotateSecurity(&r)
	if !r.IsReorganizacion {
		t.Fatal("reorganizacion must flag")
	}
	if !r.HasCapitalChange {
		t.Fatal("reorganizacion implies capital change")
	}
}

func TestAnnotateDisolucion(t *testing.T) {
	r := Row{ActoKind: ActoLiquidacion, SociedadCuitPrefix: "30", FileMode: 0o600}
	AnnotateSecurity(&r)
	if !r.HasDisolucion {
		t.Fatal("liquidacion must flag disolucion")
	}
	if r.IsCredentialExposureRisk {
		t.Fatal("0o600 must NOT flag exposure")
	}
}

func TestAnnotateReformaCapitalChange(t *testing.T) {
	r := Row{ActoKind: ActoReformaEstatuto, FileMode: 0o600}
	AnnotateSecurity(&r)
	if !r.HasCapitalChange {
		t.Fatal("reforma estatuto must flag capital change (heuristic)")
	}
}

func TestAnnotateActaConstitutivaNoFlags(t *testing.T) {
	r := Row{ActoKind: ActoActaConstitutiva, FileMode: 0o600}
	AnnotateSecurity(&r)
	if r.HasCapitalChange || r.HasDirectorioChange || r.IsReorganizacion {
		t.Fatalf("acta constitutiva must NOT flag deltas: %+v", r)
	}
}

// -- ParseIGJActo --------------------------------------------------

func TestParseIGJActoXML(t *testing.T) {
	body := []byte(`<?xml version="1.0"?>
<actoSocietario>
  <cuitSociedad>30-71234567-8</cuitSociedad>
  <denominacion>ACME S.A.</denominacion>
  <tipoSocietario>SA</tipoSocietario>
  <estado>Inscripto</estado>
  <fecha_acto>2024-06-15</fecha_acto>
  <fecha_inscripcion>2024-07-01</fecha_inscripcion>
  <igj_correlativo>1234567</igj_correlativo>
  <igj_legajo>1850123</igj_legajo>
</actoSocietario>`)
	f, ok := ParseIGJActo(body)
	if !ok {
		t.Fatal("must parse")
	}
	if f.SociedadCuitRaw != "30-71234567-8" {
		t.Fatalf("cuit=%q", f.SociedadCuitRaw)
	}
	if f.SociedadDenominacion != "ACME S.A." {
		t.Fatalf("denom=%q", f.SociedadDenominacion)
	}
	if f.IgjCorrelativo != "1234567" {
		t.Fatalf("correlativo=%q", f.IgjCorrelativo)
	}
}

func TestParseIGJActoHTML(t *testing.T) {
	body := []byte(`<html><body>
<p>Sociedad: ACME S.A.</p>
<p>CUIT: 30-71234567-8</p>
<p>Tipo Societario: SA</p>
<p>Estado: Inscripto</p>
<p>Fecha del Acto: 2024-06-15</p>
<p>Correlativo IGJ: 1234567</p>
</body></html>`)
	f, ok := ParseIGJActo(body)
	if !ok {
		t.Fatal("must parse")
	}
	if f.SociedadCuitRaw != "30-71234567-8" || f.IgjCorrelativo != "1234567" {
		t.Fatalf("scrape: %+v", f)
	}
}

func TestParseIGJActoEmpty(t *testing.T) {
	if _, ok := ParseIGJActo([]byte("")); ok {
		t.Fatal("empty must NOT parse")
	}
}

// -- collector end-to-end -----------------------------------------

func TestCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")
	dir := filepath.Join(usersBase, "alice", "Documents", "IGJ")
	must(t, os.MkdirAll(dir, 0o755))

	// Reorganización XML, world-readable.
	reorgPath := filepath.Join(dir, "reorganizacion_fusion_30712345678.xml")
	must(t, os.WriteFile(reorgPath, []byte(`<actoSocietario>
<cuitSociedad>30712345678</cuitSociedad>
<denominacion>ACME S.A.</denominacion>
<tipoSocietario>SA</tipoSocietario>
<estado>Inscripto</estado>
</actoSocietario>`), 0o644))

	// Directorio change PDF, locked-down (no body parse).
	dirPath := filepath.Join(dir, "designacion_directorio_30000000007_2024.pdf")
	must(t, os.WriteFile(dirPath, []byte("%PDF"), 0o600))

	// Disolución HTML.
	disolPath := filepath.Join(dir, "disolucion_acme.html")
	must(t, os.WriteFile(disolPath, []byte(`<html><body>
CUIT: 30-71234567-8
Sociedad: ACME S.A.
Estado: Inscripto
</body></html>`), 0o644))

	// Random — ignored.
	must(t, os.WriteFile(filepath.Join(dir, "random.pdf"), []byte("%PDF"), 0o644))

	// Public — skipped.
	pub := filepath.Join(usersBase, "Public", "Documents", "IGJ")
	must(t, os.MkdirAll(pub, 0o755))
	must(t, os.WriteFile(filepath.Join(pub, "acta_constitutiva_skip.pdf"),
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
		t.Fatalf("want 3, got %d: %+v", len(got), got)
	}

	var reorg, dirRow, disol Row
	for _, r := range got {
		switch r.FilePath {
		case reorgPath:
			reorg = r
		case dirPath:
			dirRow = r
		case disolPath:
			disol = r
		}
	}
	if !reorg.IsReorganizacion || !reorg.HasCapitalChange {
		t.Fatalf("reorg flags: %+v", reorg)
	}
	if reorg.SociedadDenominacion != "ACME S.A." {
		t.Fatalf("reorg denom=%q", reorg.SociedadDenominacion)
	}
	if reorg.TipoSocietario != TipoSA {
		t.Fatalf("reorg tipo=%q", reorg.TipoSocietario)
	}
	if !reorg.IsCredentialExposureRisk {
		t.Fatalf("reorg + readable must flag exposure: %+v", reorg)
	}

	if !dirRow.HasDirectorioChange {
		t.Fatalf("dir must flag directorio change: %+v", dirRow)
	}
	if dirRow.SociedadCuitPrefix != "30" || dirRow.SociedadCuitSuffix4 != "0007" {
		t.Fatalf("dir cuit: %+v", dirRow)
	}

	if !disol.HasDisolucion {
		t.Fatalf("disol must flag disolucion: %+v", disol)
	}
}

func TestCollectorRespectsEnv(t *testing.T) {
	tmp := t.TempDir()
	envDir := filepath.Join(tmp, "custom-igj")
	must(t, os.MkdirAll(envDir, 0o755))
	must(t, os.WriteFile(filepath.Join(envDir, "designacion_directorio_30712345678.pdf"),
		[]byte("%PDF"), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "IGJ_DIR" {
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
	if len(got) != 1 || !got[0].HasDirectorioChange {
		t.Fatalf("env: %+v", got)
	}
}

func TestCollectorMissingPathsOK(t *testing.T) {
	c := &fileCollector{
		installRoots: []string{"/nope-igj"},
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
		{FilePath: "z", SociedadCuitPrefix: "30", SociedadCuitSuffix4: "1111"},
		{FilePath: "a", SociedadCuitPrefix: "30", SociedadCuitSuffix4: "9999"},
		{FilePath: "a", SociedadCuitPrefix: "20", SociedadCuitSuffix4: "0001"},
	}
	SortRows(in)
	if in[0].FilePath != "a" || in[0].SociedadCuitPrefix != "20" {
		t.Fatalf("first=%+v", in[0])
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
