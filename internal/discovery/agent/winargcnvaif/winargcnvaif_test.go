package winargcnvaif

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindProspectoEmision), "prospecto-emision"},
		{string(KindSuplementoProspecto), "suplemento-prospecto"},
		{string(KindActaAsamblea), "acta-asamblea"},
		{string(KindDesignacionDirect), "designacion-directorio"},
		{string(KindConvocatoriaAsamblea), "convocatoria-asamblea"},
		{string(KindDDJJAutoridades), "ddjj-autoridades"},
		{string(KindDDJJAccionistas), "ddjj-accionistas"},
		{string(KindDDJJBeneficiarios), "ddjj-beneficiarios"},
		{string(KindContratoFideicomiso), "contrato-fideicomiso"},
		{string(KindReglamentoGestion), "reglamento-gestion"},
		{string(KindAdenda), "adenda"},
		{string(KindOther), "other"},
		{string(KindUnknown), "unknown"},
		{string(TipoONCorporativa), "on-corporativa"},
		{string(TipoFCI), "fci"},
		{string(TipoFideicomiso), "fideicomiso"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestIsCandidateName(t *testing.T) {
	yes := []string{
		"prospecto_emision_YPFD_001.pdf",
		"suplemento_prospecto_002.xml",
		"acta_asamblea_30712345678.xml",
		"designacion_directorio_005.xml",
		"convocatoria_asamblea_2026.xml",
		"ddjj_autoridades_001.xml",
		"ddjj_accionistas_002.xml",
		"ddjj_beneficiarios_003.xml",
		"contrato_fideicomiso_004.xml",
		"reglamento_gestion_FCI69.xml",
		"adenda_ON_001.xml",
		"cnv_aif_dump.xml",
	}
	no := []string{"", "factura.xml", "cv.docx", "random.txt"}
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

func TestArtifactKindFromName(t *testing.T) {
	cases := map[string]ArtifactKind{
		"prospecto_emision_YPFD.pdf":     KindProspectoEmision,
		"suplemento_prospecto_002.xml":   KindSuplementoProspecto,
		"acta_asamblea_001.xml":          KindActaAsamblea,
		"designacion_directorio_005.xml": KindDesignacionDirect,
		"convocatoria_asamblea_001.xml":  KindConvocatoriaAsamblea,
		"ddjj_autoridades_001.xml":       KindDDJJAutoridades,
		"ddjj_accionistas_002.xml":       KindDDJJAccionistas,
		"ddjj_beneficiarios_003.xml":     KindDDJJBeneficiarios,
		"contrato_fideicomiso_004.xml":   KindContratoFideicomiso,
		"reglamento_gestion_FCI69.xml":   KindReglamentoGestion,
		"adenda_ON_001.xml":              KindAdenda,
		"cnv_aif_dump.xml":               KindOther,
		"":                               KindUnknown,
	}
	for in, want := range cases {
		if got := ArtifactKindFromName(in); got != want {
			t.Fatalf("ArtifactKindFromName(%q)=%q want %q", in, got, want)
		}
	}
}

func TestTipoEmisionFromText(t *testing.T) {
	cases := map[string]TipoEmision{
		"obligacion negociable": TipoONCorporativa,
		"ON":                    TipoONCorporativa,
		"FCI":                   TipoFCI,
		"fondo comun":           TipoFCI,
		"fideicomiso":           TipoFideicomiso,
		"acciones":              TipoAcciones,
		"pagare":                TipoPagare,
		"cedear":                TipoCEDEAR,
		"":                      TipoUnknown,
		"otra cosa":             TipoOther,
	}
	for in, want := range cases {
		if got := TipoEmisionFromText(in); got != want {
			t.Fatalf("TipoEmisionFromText(%q)=%q want %q", in, got, want)
		}
	}
}

func TestEmisorCuitFingerprint(t *testing.T) {
	cases := []struct {
		in, pfx, sfx4 string
	}{
		{"acta_30712345678.xml", "30", "5678"},
		{"33-22222222-3", "33", "2223"},
		{"natural 27-11111111-4 must be empty", "", ""},
		{"no cuit", "", ""},
	}
	for _, c := range cases {
		gotP, gotS := EmisorCuitFingerprint(c.in)
		if gotP != c.pfx || gotS != c.sfx4 {
			t.Fatalf("EmisorCuitFingerprint(%q)=(%q,%q) want (%q,%q)",
				c.in, gotP, gotS, c.pfx, c.sfx4)
		}
	}
}

func TestAnyNaturalPersonCuit(t *testing.T) {
	yes := []string{"acta con 27-11111111-4", "lista 20111111119"}
	no := []string{"30-71234567-8", "no cuits", ""}
	for _, v := range yes {
		if !AnyNaturalPersonCuit(v) {
			t.Fatalf("expected natural: %q", v)
		}
	}
	for _, v := range no {
		if AnyNaturalPersonCuit(v) {
			t.Fatalf("expected NOT natural: %q", v)
		}
	}
}

func TestTickerFromText(t *testing.T) {
	cases := map[string]string{
		"ticker YPFD":   "YPFD",
		"simbolo: GGAL": "GGAL",
		"símbolo TGS":   "TGS",
		"no ticker":     "",
		"":              "",
	}
	for in, want := range cases {
		if got := TickerFromText(in); got != want {
			t.Fatalf("TickerFromText(%q)=%q want %q", in, got, want)
		}
	}
}

func TestDocumentoAIFIDFromText(t *testing.T) {
	cases := map[string]string{
		"folio 12345":  "12345",
		"AIF_ID 99999": "99999",
		"N°AIF 333333": "333333",
		"no folio":     "",
		"":             "",
	}
	for in, want := range cases {
		if got := DocumentoAIFIDFromText(in); got != want {
			t.Fatalf("DocumentoAIFIDFromText(%q)=%q want %q", in, got, want)
		}
	}
}

// -- AnnotateSecurity ---------------------------------------------

func TestAnnotateBeneficialOwnerExposure(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC) }
	r := Row{
		ArtifactKind:         KindDDJJBeneficiarios,
		EmisorCuitPrefix:     "30",
		EmisorCuitSuffix4:    "5678",
		BeneficialOwnerCount: 3,
		FileMode:             0o644,
	}
	AnnotateSecurityWithClock(&r, now)
	if !r.HasBeneficialOwner {
		t.Fatal("BO count > 0 must flag")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("emisor + BO + readable = exposure")
	}
}

func TestAnnotateDirectorioExposure(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC) }
	r := Row{
		ArtifactKind:        KindDesignacionDirect,
		EmisorCuitPrefix:    "30",
		EmisorCuitSuffix4:   "5678",
		HasDirectorioChange: true,
		FileMode:            0o644,
	}
	AnnotateSecurityWithClock(&r, now)
	if !r.IsCredentialExposureRisk {
		t.Fatal("emisor + directorio change + readable = exposure")
	}
}

func TestAnnotateActiveOffering(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC) }
	r := Row{
		ArtifactKind:  KindProspectoEmision,
		VigenciaDesde: "2026-01-01",
		VigenciaHasta: "2027-01-01",
		FileMode:      0o600,
	}
	AnnotateSecurityWithClock(&r, now)
	if !r.IsActiveOffering {
		t.Fatal("now within vigencia must flag active")
	}
}

func TestAnnotateExpiredOffering(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC) }
	r := Row{
		ArtifactKind:  KindProspectoEmision,
		VigenciaDesde: "2020-01-01",
		VigenciaHasta: "2021-01-01",
		FileMode:      0o600,
	}
	AnnotateSecurityWithClock(&r, now)
	if r.IsActiveOffering {
		t.Fatal("past vigencia must NOT flag active")
	}
}

func TestAnnotateLockedDownClean(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC) }
	r := Row{
		ArtifactKind:         KindDDJJBeneficiarios,
		EmisorCuitPrefix:     "30",
		BeneficialOwnerCount: 3,
		FileMode:             0o600,
	}
	AnnotateSecurityWithClock(&r, now)
	if r.IsCredentialExposureRisk {
		t.Fatal("0o600 must NOT flag exposure")
	}
}

// -- ParseAIFArtifact ---------------------------------------------

func TestParseAIFProspectoXML(t *testing.T) {
	body := []byte(`<?xml version="1.0"?>
<prospecto>
  <cuit_emisor>30712345678</cuit_emisor>
  <ticker>YPFD</ticker>
  <documento_aif_id>123456</documento_aif_id>
  <tipo_emision>obligacion negociable</tipo_emision>
  <fecha_aprobacion>2026-01-15</fecha_aprobacion>
  <vigencia_desde>2026-02-01</vigencia_desde>
  <vigencia_hasta>2027-02-01</vigencia_hasta>
  <monto_ars>10000000000.00</monto_ars>
  <monto_usd>50000000.00</monto_usd>
</prospecto>`)
	f, ok := ParseAIFArtifact(body)
	if !ok {
		t.Fatal("must parse")
	}
	if f.EmisorCuitRaw != "30712345678" {
		t.Fatalf("emisor=%q", f.EmisorCuitRaw)
	}
	if f.Ticker != "YPFD" {
		t.Fatalf("ticker=%q", f.Ticker)
	}
	if f.DocumentoAIFID != "123456" {
		t.Fatalf("folio=%q", f.DocumentoAIFID)
	}
	if f.TipoEmisionText != "obligacion negociable" {
		t.Fatalf("tipo=%q", f.TipoEmisionText)
	}
	if DecimalToCents(f.MontoARSText) != 1_000_000_000_000 {
		t.Fatalf("monto ARS=%d", DecimalToCents(f.MontoARSText))
	}
	if DecimalToCents(f.MontoUSDText) != 5_000_000_000 {
		t.Fatalf("monto USD=%d", DecimalToCents(f.MontoUSDText))
	}
}

func TestParseAIFDDJJBeneficiariosXML(t *testing.T) {
	body := []byte(`<ddjj>
<cuit_emisor>30712345678</cuit_emisor>
<beneficiario_final><cuit>20111111119</cuit><pct>25</pct></beneficiario_final>
<beneficiario_final><cuit>27222222227</cuit><pct>15</pct></beneficiario_final>
</ddjj>`)
	f, ok := ParseAIFArtifact(body)
	if !ok {
		t.Fatal("must parse")
	}
	if f.BeneficialOwnerCount != 2 {
		t.Fatalf("BO count=%d", f.BeneficialOwnerCount)
	}
}

func TestParseAIFActaDirectorioNarrative(t *testing.T) {
	body := []byte(`<acta>
<cuit_emisor>30712345678</cuit_emisor>
<texto>Se aprueba la designacion de directorio: Juan Perez como Presidente.</texto>
</acta>`)
	f, ok := ParseAIFArtifact(body)
	if !ok {
		t.Fatal("must parse")
	}
	if !f.HasDirectorioChange {
		t.Fatal("narrative must flag directorio change")
	}
}

func TestParseAIFActaCapitalNarrative(t *testing.T) {
	body := []byte(`<acta>
<cuit_emisor>30712345678</cuit_emisor>
<texto>Se aprueba aumento de capital por 10 M ARS.</texto>
</acta>`)
	f, ok := ParseAIFArtifact(body)
	if !ok {
		t.Fatal("must parse")
	}
	if !f.HasCapitalChange {
		t.Fatal("narrative must flag capital change")
	}
}

func TestParseAIFEmpty(t *testing.T) {
	if _, ok := ParseAIFArtifact([]byte("")); ok {
		t.Fatal("empty must NOT parse")
	}
}

// -- collector end-to-end -----------------------------------------

func TestCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")
	dir := filepath.Join(usersBase, "alice", "Documents", "CNV", "AIF")
	must(t, os.MkdirAll(dir, 0o755))

	// DDJJ beneficiarios with PII, world-readable, active vigencia.
	boPath := filepath.Join(dir, "ddjj_beneficiarios_30712345678.xml")
	must(t, os.WriteFile(boPath, []byte(`<?xml version="1.0"?>
<ddjj>
<cuit_emisor>30712345678</cuit_emisor>
<ticker>YPFD</ticker>
<vigencia_desde>2026-01-01</vigencia_desde>
<vigencia_hasta>2027-01-01</vigencia_hasta>
<beneficiario_final><cuit>20111111119</cuit><pct>25</pct></beneficiario_final>
<beneficiario_final><cuit>27222222227</cuit><pct>15</pct></beneficiario_final>
</ddjj>`), 0o644))

	// Prospecto, locked down.
	pPath := filepath.Join(dir, "prospecto_emision_30712345678.xml")
	must(t, os.WriteFile(pPath, []byte(`<prospecto>
<cuit_emisor>30712345678</cuit_emisor>
<ticker>YPFD</ticker>
<tipo_emision>obligacion negociable</tipo_emision>
<monto_ars>10000000000.00</monto_ars>
</prospecto>`), 0o600))

	// Random ignored.
	must(t, os.WriteFile(filepath.Join(dir, "random.xml"),
		[]byte(`<x/>`), 0o644))

	// Public skipped.
	pub := filepath.Join(usersBase, "Public", "Documents", "CNV", "AIF")
	must(t, os.MkdirAll(pub, 0o755))
	must(t, os.WriteFile(filepath.Join(pub, "prospecto_skip.xml"),
		[]byte(`<p/>`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   []string{usersBase},
		getenv:       func(string) string { return "" },
		readFile:     os.ReadFile,
		readDir:      os.ReadDir,
		statFile:     os.Stat,
		now:          func() time.Time { return time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC) },
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 (bo+prospecto), got %d: %+v", len(got), got)
	}

	var bo, p Row
	for _, r := range got {
		switch r.FilePath {
		case boPath:
			bo = r
		case pPath:
			p = r
		}
	}
	if bo.ArtifactKind != KindDDJJBeneficiarios {
		t.Fatalf("bo kind=%q", bo.ArtifactKind)
	}
	if bo.EmisorCuitPrefix != "30" || bo.EmisorCuitSuffix4 != "5678" {
		t.Fatalf("bo emisor: %+v", bo)
	}
	if bo.EmisorTicker != "YPFD" {
		t.Fatalf("bo ticker=%q", bo.EmisorTicker)
	}
	if bo.BeneficialOwnerCount < 2 {
		t.Fatalf("bo count=%d", bo.BeneficialOwnerCount)
	}
	if !bo.HasBeneficialOwner {
		t.Fatalf("must flag BO: %+v", bo)
	}
	if !bo.IsActiveOffering {
		t.Fatalf("vigencia must flag active: %+v", bo)
	}
	if !bo.IsCredentialExposureRisk {
		t.Fatalf("readable + emisor + BO = exposure: %+v", bo)
	}

	if p.ArtifactKind != KindProspectoEmision {
		t.Fatalf("p kind=%q", p.ArtifactKind)
	}
	if p.TipoEmision != TipoONCorporativa {
		t.Fatalf("p tipo=%q", p.TipoEmision)
	}
	if !p.HasCapitalChange {
		t.Fatalf("prospecto auto-flags capital: %+v", p)
	}
	if p.IsCredentialExposureRisk {
		t.Fatalf("0o600 must NOT flag: %+v", p)
	}
}

func TestCollectorRespectsEnv(t *testing.T) {
	tmp := t.TempDir()
	envDir := filepath.Join(tmp, "custom-aif")
	must(t, os.MkdirAll(envDir, 0o755))
	must(t, os.WriteFile(filepath.Join(envDir, "prospecto_emision_001.xml"),
		[]byte(`<prospecto><cuit_emisor>30712345678</cuit_emisor></prospecto>`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "CNV_AIF_DIR" {
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
	if len(got) != 1 || got[0].ArtifactKind != KindProspectoEmision {
		t.Fatalf("env: %+v", got)
	}
}

func TestCollectorMissingPathsOK(t *testing.T) {
	c := &fileCollector{
		installRoots: []string{"/nope-aif"},
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
		{FilePath: "z", ArtifactKind: KindProspectoEmision},
		{FilePath: "a", ArtifactKind: KindDDJJBeneficiarios},
		{FilePath: "a", ArtifactKind: KindActaAsamblea},
	}
	SortRows(in)
	if in[0].FilePath != "a" || in[0].ArtifactKind != KindActaAsamblea {
		t.Fatalf("first=%+v", in[0])
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
