package winargcnvhr

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(FilingHechoRelevante), "hecho-relevante"},
		{string(FilingComunicacion), "comunicacion"},
		{string(FilingInfoFinanciera), "info-financiera"},
		{string(FilingAnuncio), "anuncio"},
		{string(FilingOther), "other"},
		{string(FilingUnknown), "unknown"},
		{string(HechoDefault), "default"},
		{string(HechoCesacionPagos), "cesacion-pagos"},
		{string(HechoMNA), "mna"},
		{string(HechoCambioControl), "cambio-control"},
		{string(HechoOfertaPublica), "oferta-publica"},
		{string(HechoDividendos), "dividendos"},
		{string(HechoCapitalAumento), "capital-aumento"},
		{string(HechoCapitalReduccion), "capital-reduccion"},
		{string(HechoAprobacionEECC), "aprobacion-eecc"},
		{string(HechoCalificacionRiesgo), "calificacion-riesgo"},
		{string(HechoCambioManagement), "cambio-management"},
		{string(HechoOfertaCanje), "oferta-canje"},
		{string(HechoAsamblea), "asamblea"},
		{string(HechoSancion), "sancion"},
		{string(HechoOther), "other"},
		{string(HechoUnknown), "unknown"},
		{string(RelevanciaAlta), "alta"},
		{string(RelevanciaMedia), "media"},
		{string(RelevanciaBaja), "baja"},
		{string(RelevanciaUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestIsCandidateName(t *testing.T) {
	yes := []string{
		"HR_YPFD_20240615.pdf",
		"hecho_relevante_001.xml",
		"comunicacion_acme.xml",
		"info_financiera_2024.pdf",
		"asamblea_anual.pdf",
	}
	no := []string{
		"factura.pdf",
		"",
		"cv.docx",
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

func TestFilingKindFromName(t *testing.T) {
	cases := map[string]FilingKind{
		"HR_YPFD_001.pdf":          FilingHechoRelevante,
		"hechorelevante_acme.pdf":  FilingHechoRelevante,
		"comunicacion_001.xml":     FilingComunicacion,
		"info-financiera_2024.pdf": FilingInfoFinanciera,
		"memoria_2024.pdf":         FilingInfoFinanciera,
		"anuncio_dividendos.pdf":   FilingAnuncio,
		"cnv_001.xml":              FilingOther,
		"random.pdf":               FilingUnknown,
		"":                         FilingUnknown,
	}
	for in, want := range cases {
		if got := FilingKindFromName(in); got != want {
			t.Fatalf("FilingKindFromName(%q)=%q want %q", in, got, want)
		}
	}
}

func TestTipoHechoFromText(t *testing.T) {
	cases := map[string]TipoHecho{
		"cesación de pagos formal":               HechoCesacionPagos,
		"default en pago de intereses":           HechoDefault,
		"cambio de control accionario":           HechoCambioControl,
		"fusión por absorción de subsidiaria":    HechoMNA,
		"M&A acquisition complete":               HechoMNA,
		"OPA por hasta el 100% del capital":      HechoOfertaPublica,
		"oferta pública de adquisición":          HechoOfertaPublica,
		"oferta de canje de obligaciones":        HechoOfertaCanje,
		"aumento de capital por suscripción":     HechoCapitalAumento,
		"reducción de capital voluntaria":        HechoCapitalReduccion,
		"distribución de dividendos en efectivo": HechoDividendos,
		"aprobación de EECC anuales":             HechoAprobacionEECC,
		"calificación de riesgo AAA":             HechoCalificacionRiesgo,
		"cambio de CEO":                          HechoCambioManagement,
		"cambio en el directorio":                HechoCambioManagement,
		"asamblea ordinaria":                     HechoAsamblea,
		"sanción de CNV":                         HechoSancion,
		"":                                       HechoUnknown,
		"reunión informativa":                    HechoUnknown,
	}
	for in, want := range cases {
		if got := TipoHechoFromText(in); got != want {
			t.Fatalf("TipoHechoFromText(%q)=%q want %q", in, got, want)
		}
	}
}

func TestIsHighImpact(t *testing.T) {
	yes := []TipoHecho{
		HechoDefault, HechoCesacionPagos, HechoMNA,
		HechoCambioControl, HechoOfertaPublica,
	}
	no := []TipoHecho{
		HechoDividendos, HechoAsamblea, HechoCalificacionRiesgo,
		HechoCambioManagement, HechoUnknown,
	}
	for _, t1 := range yes {
		if !IsHighImpact(t1) {
			t.Fatalf("expected high-impact: %q", t1)
		}
	}
	for _, t1 := range no {
		if IsHighImpact(t1) {
			t.Fatalf("expected NOT high-impact: %q", t1)
		}
	}
}

func TestRelevanciaFromText(t *testing.T) {
	cases := map[string]Relevancia{
		"Alta":   RelevanciaAlta,
		"HIGH":   RelevanciaAlta,
		"media":  RelevanciaMedia,
		"medium": RelevanciaMedia,
		"baja":   RelevanciaBaja,
		"low":    RelevanciaBaja,
		"":       RelevanciaUnknown,
		"otra":   RelevanciaUnknown,
	}
	for in, want := range cases {
		if got := RelevanciaFromText(in); got != want {
			t.Fatalf("RelevanciaFromText(%q)=%q want %q", in, got, want)
		}
	}
}

func TestCuitFingerprint(t *testing.T) {
	cases := []struct {
		in, pfx, sfx4 string
	}{
		{"HR_30712345678_20240615.pdf", "30", "5678"},
		{"30-71234567-8", "30", "5678"},
		{"no-cuit", "", ""},
		{"11-12345678-9", "", ""}, // invalid prefix
	}
	for _, c := range cases {
		gotP, gotS := CuitFingerprint(c.in)
		if gotP != c.pfx || gotS != c.sfx4 {
			t.Fatalf("CuitFingerprint(%q)=(%q,%q) want (%q,%q)",
				c.in, gotP, gotS, c.pfx, c.sfx4)
		}
	}
}

func TestTickerFromName(t *testing.T) {
	cases := map[string]string{
		"HR_YPFD_20240615.pdf":     "YPFD",
		"hr_GGAL_2024.pdf":         "GGAL",
		"HR_BMA_001.pdf":           "BMA",
		"hecho_relevante_acme.pdf": "", // lowercase
		"random_NOTICKER123.pdf":   "", // has digit
		"":                         "",
	}
	for in, want := range cases {
		if got := TickerFromName(in); got != want {
			t.Fatalf("TickerFromName(%q)=%q want %q", in, got, want)
		}
	}
}

// -- AnnotateSecurity ----------------------------------------------

func TestAnnotateHighImpactExposure(t *testing.T) {
	r := Row{
		FilingKind:        FilingHechoRelevante,
		TipoHecho:         HechoDefault,
		IssuerCuitPrefix:  "30",
		IssuerCuitSuffix4: "5678",
		FileMode:          0o644,
	}
	AnnotateSecurity(&r)
	if !r.IsHighImpactEvent {
		t.Fatal("default must flag high-impact")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("issuer + readable must flag exposure")
	}
}

func TestAnnotateDividendos0600Clean(t *testing.T) {
	r := Row{
		FilingKind:       FilingHechoRelevante,
		TipoHecho:        HechoDividendos,
		IssuerCuitPrefix: "30",
		FileMode:         0o600,
	}
	AnnotateSecurity(&r)
	if r.IsHighImpactEvent {
		t.Fatal("dividendos must NOT flag high-impact")
	}
	if r.IsCredentialExposureRisk {
		t.Fatal("0o600 must NOT flag exposure")
	}
}

// -- ParseSiblingMetadata ------------------------------------------

func TestParseSiblingMetadataXML(t *testing.T) {
	body := []byte(`<?xml version="1.0"?>
<comunicacion>
  <tipoHecho>Default</tipoHecho>
  <relevancia>Alta</relevancia>
  <cuit>30-71234567-8</cuit>
  <ticker>YPFD</ticker>
  <denominacion>YPF S.A.</denominacion>
  <fecha>2024-06-15</fecha>
</comunicacion>`)
	f, ok := ParseSiblingMetadata(body)
	if !ok {
		t.Fatal("must parse")
	}
	if f.TipoHechoText != "Default" || f.RelevanciaText != "Alta" {
		t.Fatalf("tipo/relevancia: %+v", f)
	}
	if f.IssuerCuitRaw != "30-71234567-8" || f.IssuerTicker != "YPFD" {
		t.Fatalf("cuit/ticker: %+v", f)
	}
	if f.IssuerDenominacion != "YPF S.A." || f.FechaText != "2024-06-15" {
		t.Fatalf("denom/fecha: %+v", f)
	}
}

func TestParseSiblingMetadataJSON(t *testing.T) {
	body := []byte(`{
  "tipoHecho": "Cesación de Pagos",
  "relevancia": "Alta",
  "cuit": "30712345678",
  "ticker": "ACME",
  "denominacion": "ACME S.A."
}`)
	f, ok := ParseSiblingMetadata(body)
	if !ok {
		t.Fatal("must parse")
	}
	if f.TipoHechoText != "Cesación de Pagos" || f.IssuerTicker != "ACME" {
		t.Fatalf("fields: %+v", f)
	}
}

func TestParseSiblingMetadataTextScrape(t *testing.T) {
	body := []byte(`Tipo de Hecho: Cambio de Control
Relevancia: Alta
CUIT: 30-71234567-8
Ticker: YPFD
Denominación: YPF S.A.
Fecha: 2024-06-15
Vinculado: 30-00000000-7
`)
	f, ok := ParseSiblingMetadata(body)
	if !ok {
		t.Fatal("must parse")
	}
	if f.TipoHechoText != "Cambio de Control" {
		t.Fatalf("tipo=%q", f.TipoHechoText)
	}
	if f.VinculadoCuitRaw != "30-00000000-7" {
		t.Fatalf("vinculado=%q", f.VinculadoCuitRaw)
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

	// High-impact PDF via filename heuristic (default + CUIT).
	defPath := filepath.Join(alice, "HR_YPFD_default_30712345678_20240615.pdf")
	must(t, os.WriteFile(defPath, []byte("%PDF"), 0o644))

	// MNA XML with sibling metadata.
	mnaPath := filepath.Join(alice, "comunicacion_GGAL_001.xml")
	must(t, os.WriteFile(mnaPath, []byte(`<comunicacion>
<tipoHecho>Fusión por Absorción</tipoHecho>
<relevancia>Alta</relevancia>
<cuit>30000000007</cuit>
<ticker>GGAL</ticker>
<denominacion>Grupo Galicia</denominacion>
</comunicacion>`), 0o644))

	// Non-CNV file — ignored.
	must(t, os.WriteFile(filepath.Join(alice, "random.pdf"), []byte("x"), 0o644))

	// Public profile — skipped.
	pub := filepath.Join(usersBase, "Public", "Downloads")
	must(t, os.MkdirAll(pub, 0o755))
	must(t, os.WriteFile(filepath.Join(pub, "HR_skip.pdf"), []byte("x"), 0o644))

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
		t.Fatalf("want 2 (default+mna), got %d: %+v", len(got), got)
	}

	var def, mna Row
	for _, r := range got {
		switch r.FilePath {
		case defPath:
			def = r
		case mnaPath:
			mna = r
		}
	}
	if !def.IsHighImpactEvent {
		t.Fatalf("default must flag high-impact: %+v", def)
	}
	if def.IssuerCuitPrefix != "30" || def.IssuerCuitSuffix4 != "5678" {
		t.Fatalf("def cuit: %+v", def)
	}
	if def.IssuerTicker != "YPFD" {
		t.Fatalf("def ticker=%q", def.IssuerTicker)
	}
	if !def.IsCredentialExposureRisk || !def.IsRecent {
		t.Fatalf("def flags: %+v", def)
	}

	if !mna.IsHighImpactEvent {
		t.Fatalf("mna must flag high-impact: %+v", mna)
	}
	if mna.IssuerTicker != "GGAL" {
		t.Fatalf("mna ticker=%q", mna.IssuerTicker)
	}
	if mna.IssuerDenominacion != "Grupo Galicia" {
		t.Fatalf("mna denom=%q", mna.IssuerDenominacion)
	}
	if mna.Relevancia != RelevanciaAlta {
		t.Fatalf("mna relevancia=%q", mna.Relevancia)
	}
}

func TestCollectorRespectsEnv(t *testing.T) {
	tmp := t.TempDir()
	envDir := filepath.Join(tmp, "custom-cnv")
	must(t, os.MkdirAll(envDir, 0o755))
	must(t, os.WriteFile(filepath.Join(envDir, "HR_ACME_default_30712345678.pdf"),
		[]byte("%PDF"), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "CNV_HR_DIR" {
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
	if len(got) != 1 || !got[0].IsHighImpactEvent {
		t.Fatalf("env-supplied default must flag: %+v", got)
	}
}

func TestCollectorMissingPathsOK(t *testing.T) {
	c := &fileCollector{
		installRoots: []string{"/nope-cnv"},
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
		{FilePath: "z", IssuerCuitPrefix: "30", IssuerCuitSuffix4: "5678"},
		{FilePath: "a", IssuerCuitPrefix: "30", IssuerCuitSuffix4: "9999"},
		{FilePath: "a", IssuerCuitPrefix: "20", IssuerCuitSuffix4: "1111"},
	}
	SortRows(in)
	if in[0].FilePath != "a" || in[0].IssuerCuitPrefix != "20" {
		t.Fatalf("first=%+v", in[0])
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
