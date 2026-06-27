package winargmav

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindTerminalConfig), "mav-terminal-config"},
		{string(KindRuedaData), "mav-rueda-data"},
		{string(KindInstrumentCache), "mav-instrument-cache"},
		{string(KindSGRPortfolio), "mav-sgr-portfolio"},
		{string(KindAvalLetter), "mav-aval-letter"},
		{string(KindPyMEListing), "mav-pyme-listing"},
		{string(KindSettlement), "mav-settlement"},
		{string(KindFideicomiso), "mav-fideicomiso"},
		{string(KindInstaller), "mav-installer"},
		{string(KindOther), "other"},
		{string(KindUnknown), "unknown"},
		{string(MemberALYC), "alyc-broker"},
		{string(MemberSGR), "sgr"},
		{string(MemberPyMEIssuer), "pyme-issuer"},
		{string(MemberFideicomisoAdmin), "fideicomiso-admin"},
		{string(MemberOther), "other"},
		{string(MemberUnknown), "unknown"},
		{string(InstChPD), "chpd"},
		{string(InstPagareBursatil), "pagare-bursatil"},
		{string(InstObligacionNegociable), "obligacion-negociable"},
		{string(InstFCEMiPyME), "fce-mipyme"},
		{string(InstLetraProvincial), "letra-provincial"},
		{string(InstONSustentable), "on-sustentable"},
		{string(InstFideicomiso), "fideicomiso"},
		{string(InstOther), "other"},
		{string(InstUnknown), "unknown"},
		{string(MonedaARS), "ARS"},
		{string(MonedaUSD), "USD"},
		{string(MonedaEUR), "EUR"},
		{string(MonedaUVA), "UVA"},
		{string(MonedaCER), "CER"},
		{string(MonedaOther), "other"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestIsCandidateName(t *testing.T) {
	yes := []string{
		"mav.ini",
		"rueda_mav_20260615.xml",
		"catalogo_mav_20260615.csv",
		"sgr_portfolio_001.csv",
		"carta_aval_001.pdf",
		"pyme_listing_30712345678.xml",
		"settlement_mav_20260615.xml",
		"fideicomiso_FF001.xml",
		"chpd_BR338_20260615.xml",
		"pagare_bursatil_001.xml",
		"on_pyme_001.xml",
		"fce_mipyme_001.xml",
		"letra_provincial_CBA_20260615.xml",
		"on_sustentable_001.xml",
	}
	no := []string{"", "factura.xml", "random.txt"}
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
		"mav.ini":                      KindTerminalConfig,
		"rueda_mav_20260615.xml":       KindRuedaData,
		"catalogo_mav_20260615.csv":    KindInstrumentCache,
		"sgr_portfolio_001.csv":        KindSGRPortfolio,
		"carta_aval_001.pdf":           KindAvalLetter,
		"pyme_listing_30712345678.xml": KindPyMEListing,
		"settlement_mav_20260615.xml":  KindSettlement,
		"fideicomiso_FF001.xml":        KindFideicomiso,
		"mav_v8_installer.msi":         KindInstaller,
		"":                             KindUnknown,
	}
	for in, want := range cases {
		if got := ArtifactKindFromName(in); got != want {
			t.Fatalf("ArtifactKindFromName(%q)=%q want %q", in, got, want)
		}
	}
}

func TestMemberKindFromPath(t *testing.T) {
	cases := map[string]MemberKind{
		`C:\SGR\MAV\portfolio.csv`:   MemberSGR,
		`C:\PyME\MAV\listing.xml`:    MemberPyMEIssuer,
		`C:\Fideicomisos\MAV\ff.xml`: MemberFideicomisoAdmin,
		`C:\Broker\MAV\rueda.xml`:    MemberALYC,
		`C:\MAV\generic.xml`:         MemberOther,
		`C:\Random\path.xml`:         MemberUnknown,
		"":                           MemberUnknown,
	}
	for in, want := range cases {
		if got := MemberKindFromPath(in); got != want {
			t.Fatalf("MemberKindFromPath(%q)=%q want %q", in, got, want)
		}
	}
}

func TestInstrumentClassFromName(t *testing.T) {
	cases := map[string]InstrumentClass{
		"chpd_BR338_20260615.xml":           InstChPD,
		"pagare_bursatil_001.xml":           InstPagareBursatil,
		"on_pyme_001.xml":                   InstObligacionNegociable,
		"fce_mipyme_001.xml":                InstFCEMiPyME,
		"letra_provincial_CBA_20260615.xml": InstLetraProvincial,
		"on_sustentable_001.xml":            InstONSustentable,
		"fideicomiso_FF001.xml":             InstFideicomiso,
		"random.xml":                        InstUnknown,
		"":                                  InstUnknown,
	}
	for in, want := range cases {
		if got := InstrumentClassFromName(in); got != want {
			t.Fatalf("InstrumentClassFromName(%q)=%q want %q", in, got, want)
		}
	}
}

func TestIsArgentineProvince(t *testing.T) {
	yes := []string{"Buenos Aires", "Córdoba", "Mendoza", "CABA", "Santa Fe"}
	no := []string{"", "Madrid", "Brasil"}
	for _, v := range yes {
		if !IsArgentineProvince(v) {
			t.Fatalf("expected province: %q", v)
		}
	}
	for _, v := range no {
		if IsArgentineProvince(v) {
			t.Fatalf("expected NOT province: %q", v)
		}
	}
}

func TestNormalizeMoneda(t *testing.T) {
	cases := map[string]Moneda{
		"ARS":   MonedaARS,
		"AR$":   MonedaARS,
		"pesos": MonedaARS,
		"USD":   MonedaUSD,
		"U$S":   MonedaUSD,
		"DOLAR": MonedaUSD,
		"EUR":   MonedaEUR,
		"UVA":   MonedaUVA,
		"CER":   MonedaCER,
		"":      MonedaNone,
		"BTC":   MonedaOther,
	}
	for in, want := range cases {
		if got := NormalizeMoneda(in); got != want {
			t.Fatalf("NormalizeMoneda(%q)=%q want %q", in, got, want)
		}
	}
}

func TestCuitFingerprint(t *testing.T) {
	cases := []struct {
		in, pfx, sfx4 string
	}{
		{"cliente 27-11111111-4", "27", "1114"},
		{"empresa 30-71234567-8", "30", "5678"},
		{"no cuit", "", ""},
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

func TestMatriculaFromText(t *testing.T) {
	cases := map[string]string{
		"matricula 338":         "338",
		"mav_matricula 999":     "999",
		"member_matricula 1234": "1234",
		"no matricula":          "",
	}
	for in, want := range cases {
		if got := MatriculaFromText(in); got != want {
			t.Fatalf("MatriculaFromText(%q)=%q want %q", in, got, want)
		}
	}
}

func TestPeriodFromFilename(t *testing.T) {
	if PeriodFromFilename("rueda_mav_202506.xml") != "202506" {
		t.Fatal("period mismatch")
	}
	if PeriodFromFilename("random.xml") != "" {
		t.Fatal("non-period must be empty")
	}
}

func TestIsHighSensitivityKind(t *testing.T) {
	yes := []ArtifactKind{
		KindAvalLetter, KindPyMEListing, KindSGRPortfolio,
		KindFideicomiso, KindRuedaData, KindSettlement,
	}
	no := []ArtifactKind{
		KindTerminalConfig, KindInstrumentCache,
		KindInstaller, KindOther, KindUnknown,
	}
	for _, k := range yes {
		if !IsHighSensitivityKind(k) {
			t.Fatalf("expected high-sensitivity: %q", k)
		}
	}
	for _, k := range no {
		if IsHighSensitivityKind(k) {
			t.Fatalf("expected NOT high-sensitivity: %q", k)
		}
	}
}

func TestIsOverdueDate(t *testing.T) {
	now := time.Date(2026, 6, 24, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		date string
		want bool
	}{
		{"2026-05-01", true},  // past
		{"2026-07-01", false}, // future
		{"", false},
		{"garbage", false},
	}
	for _, c := range cases {
		if got := IsOverdueDate(c.date, now); got != c.want {
			t.Fatalf("IsOverdueDate(%q)=%v want %v", c.date, got, c.want)
		}
	}
}

// -- AnnotateSecurity ---------------------------------------------

func TestAnnotateSGRAval(t *testing.T) {
	r := Row{
		ArtifactKind: KindAvalLetter,
		SGRName:      "Garantizar SGR",
		FileMode:     0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasSGRAval {
		t.Fatal("SGR name must flag aval")
	}
}

func TestAnnotateHighValue(t *testing.T) {
	r := Row{
		ArtifactKind:  KindRuedaData,
		MontoARSCents: 2_000_000_000, // 20 M ARS
		FileMode:      0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasHighValue {
		t.Fatal("20M ARS must flag high-value")
	}
}

func TestAnnotateForeignCurrency(t *testing.T) {
	r := Row{
		ArtifactKind: KindRuedaData,
		Moneda:       MonedaUSD,
		FileMode:     0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasForeignCurrency {
		t.Fatal("USD must flag foreign currency")
	}
}

func TestAnnotateConcentration(t *testing.T) {
	r := Row{
		ArtifactKind:        KindSGRPortfolio,
		MaxConcentrationPct: 75,
		FileMode:            0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasConcentration {
		t.Fatal("75% must flag concentration")
	}
}

func TestAnnotateClientePIIExposure(t *testing.T) {
	r := Row{
		ArtifactKind:       KindAvalLetter,
		ClienteCuitPrefix:  "27",
		ClienteCuitSuffix4: "1114",
		FileMode:           0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasClienteCuit {
		t.Fatal("cliente cuit must flag")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatalf("readable + cliente + aval = exposure: %+v", r)
	}
}

func TestAnnotateLockedDownClean(t *testing.T) {
	r := Row{
		ArtifactKind:       KindAvalLetter,
		ClienteCuitPrefix:  "27",
		ClienteCuitSuffix4: "1114",
		FileMode:           0o600,
	}
	AnnotateSecurity(&r)
	if r.IsCredentialExposureRisk {
		t.Fatal("0o600 must NOT flag exposure")
	}
}

// -- ParseMAVArtifact ---------------------------------------------

func TestParseMAVArtifactChPD(t *testing.T) {
	body := []byte(`<?xml version="1.0"?>
<chpd>
  <matricula>338</matricula>
  <librador_cuit>30-71234567-8</librador_cuit>
  <receptor_cuit>27-11111111-4</receptor_cuit>
  <sgr_name>Garantizar SGR</sgr_name>
  <moneda>ARS</moneda>
  <monto>15000000.00</monto>
  <fecha_vencimiento>2026-09-15</fecha_vencimiento>
  <fecha_libramiento>2026-03-15</fecha_libramiento>
</chpd>`)
	f := ParseMAVArtifact(body)
	if f.MemberMatricula != "338" {
		t.Fatalf("matricula=%q", f.MemberMatricula)
	}
	if f.LibradorCuitRaw == "" {
		t.Fatal("librador missing")
	}
	if f.ReceptorCuitRaw == "" {
		t.Fatal("receptor missing")
	}
	if f.SGRName == "" {
		t.Fatalf("sgr missing: %+v", f)
	}
	if f.Moneda != MonedaARS {
		t.Fatalf("moneda=%q", f.Moneda)
	}
	if f.MontoCents != 1_500_000_000 {
		t.Fatalf("monto=%d want 1_500_000_000", f.MontoCents)
	}
	if f.FechaVencimiento != "2026-09-15" {
		t.Fatalf("vencimiento=%q", f.FechaVencimiento)
	}
	if f.FechaLibramiento != "2026-03-15" {
		t.Fatalf("libramiento=%q", f.FechaLibramiento)
	}
}

func TestParseMAVArtifactDefaultMarker(t *testing.T) {
	body := []byte(`{
  "matricula": "338",
  "status": "moroso",
  "incumplimiento_pago": true
}`)
	f := ParseMAVArtifact(body)
	if !f.HasDefaultMarker {
		t.Fatal("moroso must flag default")
	}
}

func TestParseMAVArtifactProvincialDefault(t *testing.T) {
	body := []byte(`{
  "provincia": "Buenos Aires",
  "alert": "default provincial flagged",
  "rating_downgrade": "BB to B"
}`)
	f := ParseMAVArtifact(body)
	if !f.HasProvDefaultMarker {
		t.Fatal("provincial default marker must flag")
	}
	if f.Provincia != "Buenos Aires" {
		t.Fatalf("provincia=%q", f.Provincia)
	}
}

func TestParseMAVArtifactEmpty(t *testing.T) {
	f := ParseMAVArtifact(nil)
	if f.MemberMatricula != "" || f.SGRName != "" {
		t.Fatalf("empty must be zero: %+v", f)
	}
}

// -- collector end-to-end -----------------------------------------

func TestCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")
	dir := filepath.Join(usersBase, "alice", "Documents", "Broker", "MAV")
	must(t, os.MkdirAll(dir, 0o755))

	// ChPD with SGR aval + cliente CUIT, world-readable.
	chpdPath := filepath.Join(dir, "chpd_BR338_20260615.xml")
	must(t, os.WriteFile(chpdPath, []byte(`<?xml version="1.0"?>
<chpd>
  <matricula>338</matricula>
  <cliente_cuit>27-11111111-4</cliente_cuit>
  <sgr_name>Garantizar SGR</sgr_name>
  <moneda>ARS</moneda>
  <monto>15000000.00</monto>
  <fecha_vencimiento>2026-05-15</fecha_vencimiento>
  <fecha_libramiento>2026-03-15</fecha_libramiento>
</chpd>`), 0o644))

	// SGR portfolio with concentration, locked down.
	sgrPath := filepath.Join(dir, "sgr_portfolio_GARZ.csv")
	must(t, os.WriteFile(sgrPath, []byte(`{
  "matricula": "338",
  "sgr_name": "Garantizar SGR",
  "concentration_pct": "75"
}`), 0o600))

	// Letra provincial in default.
	letraPath := filepath.Join(dir, "letra_provincial_CBA_20260615.xml")
	must(t, os.WriteFile(letraPath, []byte(`<?xml version="1.0"?>
<letra>
  <provincia>Córdoba</provincia>
  <alert>default provincial flagged</alert>
  <monto>5000000.00</monto>
</letra>`), 0o644))

	// Random ignored.
	must(t, os.WriteFile(filepath.Join(dir, "random.txt"),
		[]byte(`nope`), 0o644))

	// Public skipped.
	pub := filepath.Join(usersBase, "Public", "Documents", "Broker", "MAV")
	must(t, os.MkdirAll(pub, 0o755))
	must(t, os.WriteFile(filepath.Join(pub, "chpd_skip.xml"),
		[]byte(`<chpd/>`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   []string{usersBase},
		getenv:       func(string) string { return "" },
		readFile:     os.ReadFile,
		readDir:      os.ReadDir,
		statFile:     os.Stat,
		now:          func() time.Time { return time.Date(2026, 6, 24, 0, 0, 0, 0, time.UTC) },
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("want 3 (chpd+sgr+letra), got %d: %+v", len(got), got)
	}

	var chpd, sgr, letra Row
	for _, r := range got {
		switch r.FilePath {
		case chpdPath:
			chpd = r
		case sgrPath:
			sgr = r
		case letraPath:
			letra = r
		}
	}

	if chpd.ArtifactKind != KindOther && chpd.InstrumentClass != InstChPD {
		t.Fatalf("chpd inst class=%q", chpd.InstrumentClass)
	}
	if !chpd.HasSGRAval {
		t.Fatalf("chpd must flag SGR aval: %+v", chpd)
	}
	if !chpd.HasHighValue {
		t.Fatalf("15M ARS must flag high-value: %+v", chpd)
	}
	if !chpd.HasOverdueLibramiento {
		t.Fatalf("chpd libramiento 2026-03-15 must flag overdue: %+v", chpd)
	}
	if !chpd.HasDefaultRisk {
		t.Fatalf("chpd vencimiento 2026-05-15 must flag default: %+v", chpd)
	}
	if !chpd.HasClienteCuit {
		t.Fatalf("chpd cliente cuit must flag: %+v", chpd)
	}
	if !chpd.IsCredentialExposureRisk {
		t.Fatalf("readable + cliente + chpd = exposure: %+v", chpd)
	}

	if sgr.ArtifactKind != KindSGRPortfolio {
		t.Fatalf("sgr kind=%q", sgr.ArtifactKind)
	}
	if !sgr.HasConcentration {
		t.Fatalf("75%% must flag concentration: %+v", sgr)
	}
	if sgr.IsCredentialExposureRisk {
		t.Fatalf("0o600 must NOT flag: %+v", sgr)
	}

	if letra.InstrumentClass != InstLetraProvincial {
		t.Fatalf("letra inst class=%q", letra.InstrumentClass)
	}
	if letra.Provincia != "Córdoba" {
		t.Fatalf("provincia=%q", letra.Provincia)
	}
	if !letra.HasProvincialDefaultRisk {
		t.Fatalf("letra must flag provincial default: %+v", letra)
	}
}

func TestCollectorRespectsEnv(t *testing.T) {
	tmp := t.TempDir()
	envDir := filepath.Join(tmp, "custom-mav")
	must(t, os.MkdirAll(envDir, 0o755))
	must(t, os.WriteFile(filepath.Join(envDir, "rueda_mav_20260615.xml"),
		[]byte(`<rueda><matricula>338</matricula></rueda>`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "MAV_DIR" {
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
	if len(got) != 1 || got[0].ArtifactKind != KindRuedaData {
		t.Fatalf("env: %+v", got)
	}
}

func TestCollectorMissingPathsOK(t *testing.T) {
	c := &fileCollector{
		installRoots: []string{"/nope-mav"},
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
		{FilePath: "z", ArtifactKind: KindRuedaData},
		{FilePath: "a", ArtifactKind: KindSGRPortfolio},
		{FilePath: "a", ArtifactKind: KindRuedaData},
	}
	SortRows(in)
	if in[0].FilePath != "a" || in[0].ArtifactKind != KindRuedaData {
		t.Fatalf("first=%+v", in[0])
	}
}

func TestHashContents(t *testing.T) {
	a := HashContents([]byte("mav"))
	b := HashContents([]byte("mav"))
	c := HashContents([]byte("MAV"))
	if a != b {
		t.Fatal("hash drift")
	}
	if a == c {
		t.Fatal("hash collision case-insensitive")
	}
	if len(a) != 64 {
		t.Fatalf("hash len=%d", len(a))
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
