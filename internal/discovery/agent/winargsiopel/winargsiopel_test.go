package winargsiopel

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindSIOPELConfig), "siopel-config"},
		{string(KindRuedaData), "siopel-rueda-data"},
		{string(KindSessionLog), "siopel-session-log"},
		{string(KindOperatorProfile), "siopel-operator-profile"},
		{string(KindPrecierre), "siopel-precierre"},
		{string(KindSIOPELCache), "siopel-cache"},
		{string(KindMAEClearExport), "maeclear-export"},
		{string(KindMAEBCRAForexAuct), "mae-bcra-forex"},
		{string(KindSIOPELInstaller), "siopel-installer"},
		{string(KindOther), "other"},
		{string(KindUnknown), "unknown"},
		{string(VenueMAE), "mae"},
		{string(VenueMAV), "mav"},
		{string(VenueBCRA), "bcra"},
		{string(VenueOther), "other"},
		{string(VenueUnknown), "unknown"},
		{string(RuedaCambio), "rueda-cambio"},
		{string(RuedaMEP), "rueda-mep"},
		{string(RuedaBono), "rueda-bono"},
		{string(RuedaLeliq), "rueda-leliq"},
		{string(RuedaRofexBridge), "rueda-rofex-bridge"},
		{string(RuedaCaucion), "rueda-caucion"},
		{string(RuedaCheque), "rueda-cheque"},
		{string(RuedaLetes), "rueda-letes"},
		{string(RuedaPMD), "rueda-pmd"},
		{string(RuedaOther), "other"},
		{string(RuedaUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestIsCandidateName(t *testing.T) {
	yes := []string{
		"siopel.ini",
		"siopel.cfg",
		"rueda_cambio_20260615.xml",
		"rueda_caucion_20260615.csv",
		"sesion_BR338_20260615.log",
		"operador_338.usr",
		"precierre_20260615.csv",
		"maeclear_settlement_20260615.xml",
		"bcra_subasta_forex_20260615.csv",
		"concertacion_20260615.xml",
		"leliq_oferta.dat",
		"mep_ccl_arbitraje.log",
	}
	no := []string{"", "factura.xml", "random.txt", "report.pdf"}
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
		"siopel.ini":                       KindSIOPELConfig,
		"siopel.cfg":                       KindSIOPELConfig,
		"rueda_cambio_20260615.xml":        KindRuedaData,
		"rueda_caucion_20260615.csv":       KindRuedaData,
		"concertacion_20260615.xml":        KindRuedaData,
		"sesion_BR338_20260615.log":        KindSessionLog,
		"siopel_audit_20260615.log":        KindSessionLog,
		"operador_338.usr":                 KindOperatorProfile,
		"precierre_20260615.csv":           KindPrecierre,
		"maeclear_settlement_20260615.xml": KindMAEClearExport,
		"bcra_subasta_forex_20260615.csv":  KindMAEBCRAForexAuct,
		"rueda_data.dat":                   KindRuedaData,
		"siopel_v8_installer.msi":          KindSIOPELInstaller,
		"":                                 KindUnknown,
	}
	for in, want := range cases {
		if got := ArtifactKindFromName(in); got != want {
			t.Fatalf("ArtifactKindFromName(%q)=%q want %q", in, got, want)
		}
	}
}

func TestVenueFromPath(t *testing.T) {
	cases := map[string]Venue{
		`C:\SIOPEL\config\siopel.ini`:           VenueMAE,
		`C:\MAE\SIOPEL\ruedas\rueda_cambio.xml`: VenueMAE,
		`C:\MAEClear\settlement.xml`:            VenueMAE,
		`C:\MAV\SIOPEL\rueda_pmd.xml`:           VenueMAV,
		`C:\BCRA\SIOPEL\bcra_subasta_forex.csv`: VenueBCRA,
		`C:\Random\path\file.txt`:               VenueUnknown,
		"":                                      VenueUnknown,
	}
	for in, want := range cases {
		if got := VenueFromPath(in); got != want {
			t.Fatalf("VenueFromPath(%q)=%q want %q", in, got, want)
		}
	}
}

func TestRuedaKindFromName(t *testing.T) {
	cases := map[string]RuedaKind{
		"rueda_cambio_20260615.xml":  RuedaCambio,
		"rueda_mep_20260615.csv":     RuedaMEP,
		"rueda_caucion_20260615.csv": RuedaCaucion,
		"rueda_leliq_20260615.csv":   RuedaLeliq,
		"rueda_letes_20260615.csv":   RuedaLetes,
		"rueda_cheque_20260615.csv":  RuedaCheque,
		"rueda_rofex_20260615.csv":   RuedaRofexBridge,
		"rueda_bono_soberano.csv":    RuedaBono,
		"rueda_pmd_20260615.csv":     RuedaPMD,
		"rueda_random.csv":           RuedaUnknown,
		"":                           RuedaUnknown,
	}
	for in, want := range cases {
		if got := RuedaKindFromName(in); got != want {
			t.Fatalf("RuedaKindFromName(%q)=%q want %q", in, got, want)
		}
	}
}

func TestCuitFingerprint(t *testing.T) {
	cases := []struct {
		in, pfx, sfx4 string
	}{
		{"operador_20-12345678-9", "20", "6789"},
		{"cliente 27-11111111-4", "27", "1114"},
		{"juridico 30-71234567-8", "30", "5678"},
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

func TestIsOperatorCuitPrefix(t *testing.T) {
	yes := []string{"20", "23", "24", "27"}
	no := []string{"30", "33", "34", "", "11"}
	for _, v := range yes {
		if !IsOperatorCuitPrefix(v) {
			t.Fatalf("expected operator: %q", v)
		}
	}
	for _, v := range no {
		if IsOperatorCuitPrefix(v) {
			t.Fatalf("expected NOT operator: %q", v)
		}
	}
}

func TestMatriculaFromText(t *testing.T) {
	cases := map[string]string{
		"Operador=338":            "338",
		"operador 999":            "999",
		"matricula_operador 1234": "1234",
		"mae_matricula 88":        "88",
		"no matricula":            "",
		"":                        "",
	}
	for in, want := range cases {
		if got := MatriculaFromText(in); got != want {
			t.Fatalf("MatriculaFromText(%q)=%q want %q", in, got, want)
		}
	}
}

func TestDealerCodeFromText(t *testing.T) {
	cases := map[string]string{
		"dealer_code=ABCD":   "ABCD",
		"dealer-code: BANK":  "BANK",
		"codigo_dealer=ROFE": "ROFE",
		"cod_operador=XYZ":   "XYZ",
		"dealer=GAL":         "",
		"no dealer":          "",
	}
	for in, want := range cases {
		if got := DealerCodeFromText(in); got != want {
			t.Fatalf("DealerCodeFromText(%q)=%q want %q", in, got, want)
		}
	}
}

func TestPeriodFromFilename(t *testing.T) {
	if PeriodFromFilename("rueda_cambio_202506.xml") != "202506" {
		t.Fatal("period mismatch")
	}
	if PeriodFromFilename("random.xml") != "" {
		t.Fatal("non-period must be empty")
	}
}

func TestIsAfterHoursStamp(t *testing.T) {
	yes := []string{
		"2026-06-15 16:42",
		"16:42:01",
		"08:30",
		"15:00:00",
		"2026-06-15 23:59",
	}
	no := []string{
		"2026-06-15 11:30",
		"10:00:00",
		"14:59",
		"",
		"not a stamp",
	}
	for _, v := range yes {
		if !IsAfterHoursStamp(v) {
			t.Fatalf("expected after-hours: %q", v)
		}
	}
	for _, v := range no {
		if IsAfterHoursStamp(v) {
			t.Fatalf("expected within hours: %q", v)
		}
	}
}

// -- AnnotateSecurity ---------------------------------------------

func TestAnnotateExposureRisk(t *testing.T) {
	r := Row{
		ArtifactKind:        KindSIOPELConfig,
		OperatorCuitPrefix:  "20",
		OperatorCuitSuffix4: "5789",
		HasPasswordInConfig: true,
		FileMode:            0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasOperatorCuit {
		t.Fatal("operator CUIT must flag has_operator_cuit")
	}
	if !r.IsWorldReadable {
		t.Fatal("0o644 must flag world-readable")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatalf("readable + operator CUIT + password = exposure: %+v", r)
	}
}

func TestAnnotateCaucionFlag(t *testing.T) {
	r := Row{
		ArtifactKind:        KindRuedaData,
		RuedaKind:           RuedaCaucion,
		CaucionMaxTenorDays: 45,
		FileMode:            0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasCaucionRepo {
		t.Fatal("tenor 45 > 30 must flag caucion-repo")
	}
}

func TestAnnotateAfterHoursFromSession(t *testing.T) {
	r := Row{
		ArtifactKind:     KindSessionLog,
		SessionFirstSeen: "2026-06-15 16:42:01",
		FileMode:         0o644,
	}
	AnnotateSecurity(&r)
	if !r.IsAfterHours {
		t.Fatal("16:42 must flag after-hours")
	}
}

func TestAnnotateLockedDownClean(t *testing.T) {
	r := Row{
		ArtifactKind:        KindSIOPELConfig,
		OperatorCuitPrefix:  "20",
		HasPasswordInConfig: true,
		FileMode:            0o600,
	}
	AnnotateSecurity(&r)
	if r.IsCredentialExposureRisk {
		t.Fatal("0o600 must NOT flag exposure")
	}
}

func TestAnnotateNoOperatorClean(t *testing.T) {
	r := Row{
		ArtifactKind:        KindSIOPELConfig,
		HasPasswordInConfig: true,
		FileMode:            0o644,
	}
	AnnotateSecurity(&r)
	if r.IsCredentialExposureRisk {
		t.Fatal("no operator CUIT must NOT flag exposure")
	}
}

// -- ParseSIOPELConfig --------------------------------------------

func TestParseSIOPELConfigPassword(t *testing.T) {
	body := []byte(`[SIOPEL]
Operador=338
DealerCode=ABCD
Password=secret123
CuitOperador=20-12345678-9
`)
	f := ParseSIOPELConfig(body)
	if !f.HasPasswordInline {
		t.Fatal("Password= must flag")
	}
	if f.OperatorMatricula != "338" {
		t.Fatalf("matricula=%q", f.OperatorMatricula)
	}
	if f.DealerCode != "ABCD" {
		t.Fatalf("dealer=%q", f.DealerCode)
	}
	if f.OperatorCuitRaw == "" {
		t.Fatalf("operator CUIT missing: %+v", f)
	}
}

func TestParseSIOPELConfigClaveOp(t *testing.T) {
	body := []byte(`[SIOPEL]
Operador=999
ClaveOp=abc123
`)
	f := ParseSIOPELConfig(body)
	if !f.HasPasswordInline {
		t.Fatal("ClaveOp= must flag")
	}
}

func TestParseSIOPELConfigEmpty(t *testing.T) {
	f := ParseSIOPELConfig(nil)
	if f.HasPasswordInline {
		t.Fatal("empty must not flag password")
	}
}

// -- ParseSIOPELLog -----------------------------------------------

func TestParseSIOPELLogConcertacion(t *testing.T) {
	body := []byte(`2026-06-15 10:30:01 INFO  CONCERTACION-OK ID=1
2026-06-15 11:00:15 INFO  CONCERTACION OK ID=2
2026-06-15 11:15:00 INFO  Concertación realizada ID=3
2026-06-15 14:30:00 INFO  baja-OK ID=2
2026-06-15 14:45:00 INFO  Operador=338
`)
	f := ParseSIOPELLog(body)
	if f.ConcertacionCount != 3 {
		t.Fatalf("concertacion=%d want 3", f.ConcertacionCount)
	}
	if f.BajaCount != 1 {
		t.Fatalf("baja=%d want 1", f.BajaCount)
	}
	if f.TradeCount != 4 {
		t.Fatalf("trade=%d want 4", f.TradeCount)
	}
	if f.SessionFirstSeen == "" || f.SessionLastSeen == "" {
		t.Fatalf("session bounds: %+v", f)
	}
	if f.HasMEPCCLArbitrage {
		t.Fatal("no MEP/CCL tokens — must not flag")
	}
}

func TestParseSIOPELLogMEPCCL(t *testing.T) {
	body := []byte(`2026-06-15 10:30:00 INFO  MEP buy AL30D
2026-06-15 10:31:00 INFO  CCL sell AL30C
`)
	f := ParseSIOPELLog(body)
	if !f.HasMEPCCLArbitrage {
		t.Fatal("MEP + CCL same body must flag")
	}
}

// -- ParseSIOPELRueda ---------------------------------------------

func TestParseSIOPELRuedaXML(t *testing.T) {
	body := []byte(`<?xml version="1.0"?>
<rueda>
  <matricula_operador>338</matricula_operador>
  <cuit_operador>20-12345678-9</cuit_operador>
  <dealer_code>ABCD</dealer_code>
  <periodo>202506</periodo>
  <operacion>
    <fecha_hora>2026-06-15 11:00:00</fecha_hora>
    <importe>1500000.00</importe>
  </operacion>
  <operacion>
    <fecha_hora>2026-06-15 11:30:00</fecha_hora>
    <importe>500000.00</importe>
  </operacion>
  <baja><id>X</id></baja>
</rueda>`)
	f := ParseSIOPELRueda(body)
	if f.TradeCount != 2 {
		t.Fatalf("trade=%d want 2", f.TradeCount)
	}
	if f.ConcertacionCount != 2 {
		t.Fatalf("concertacion=%d want 2", f.ConcertacionCount)
	}
	if f.BajaCount != 1 {
		t.Fatalf("baja=%d want 1", f.BajaCount)
	}
	if f.MaxNotionalCents != 150_000_000 {
		t.Fatalf("max notional=%d want 150_000_000", f.MaxNotionalCents)
	}
	if f.OperatorMatricula != "338" {
		t.Fatalf("matricula=%q", f.OperatorMatricula)
	}
	if f.DealerCode != "ABCD" {
		t.Fatalf("dealer=%q", f.DealerCode)
	}
	if f.SessionLastSeen != "2026-06-15 11:30:00" {
		t.Fatalf("session last=%q", f.SessionLastSeen)
	}
}

func TestParseSIOPELRuedaCaucionTenor(t *testing.T) {
	body := []byte(`<?xml version="1.0"?>
<rueda>
  <operacion>
    <importe>1000000</importe>
    <plazo>45</plazo>
  </operacion>
  <operacion>
    <importe>500000</importe>
    <plazo>7</plazo>
  </operacion>
</rueda>`)
	f := ParseSIOPELRueda(body)
	if f.CaucionMaxTenorDays != 45 {
		t.Fatalf("max tenor=%d want 45", f.CaucionMaxTenorDays)
	}
}

func TestParseSIOPELRuedaCSV(t *testing.T) {
	body := []byte(`# rueda dump
2026-06-15 11:00:00|OP1|Importe=1500000,00|Plazo=10
2026-06-15 11:30:00|OP2|Importe=500000,00|Plazo=14
`)
	f := ParseSIOPELRueda(body)
	if f.TradeCount != 2 {
		t.Fatalf("trade=%d want 2 (one per non-empty line)", f.TradeCount)
	}
	if f.MaxNotionalCents != 150_000_000 {
		t.Fatalf("max notional=%d", f.MaxNotionalCents)
	}
	if f.CaucionMaxTenorDays != 14 {
		t.Fatalf("max tenor=%d want 14", f.CaucionMaxTenorDays)
	}
}

func TestParseSIOPELRuedaEmpty(t *testing.T) {
	f := ParseSIOPELRueda(nil)
	if f.TradeCount != 0 || f.MaxNotionalCents != 0 {
		t.Fatalf("empty must yield zero: %+v", f)
	}
}

// -- collector end-to-end -----------------------------------------

func TestCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")
	dir := filepath.Join(usersBase, "alice", "AppData", "Roaming", "SIOPEL")
	must(t, os.MkdirAll(dir, 0o755))

	// Config with cleartext password + operator CUIT, world-readable.
	cfgPath := filepath.Join(dir, "siopel.ini")
	must(t, os.WriteFile(cfgPath, []byte(`[SIOPEL]
Operador=338
DealerCode=ABCD
Password=secret123
CuitOperador=20-12345678-9
`), 0o644))

	// Rueda cambio with high-notional, locked down.
	ruedaPath := filepath.Join(dir, "rueda_cambio_202506.xml")
	must(t, os.WriteFile(ruedaPath, []byte(`<?xml version="1.0"?>
<rueda>
  <matricula_operador>338</matricula_operador>
  <cuit_operador>20-12345678-9</cuit_operador>
  <periodo>202506</periodo>
  <operacion>
    <fecha_hora>2026-06-15 11:00:00</fecha_hora>
    <importe>5000000.00</importe>
  </operacion>
</rueda>`), 0o600))

	// Caución rueda with > 30-day tenor.
	caucionPath := filepath.Join(dir, "rueda_caucion_202506.xml")
	must(t, os.WriteFile(caucionPath, []byte(`<?xml version="1.0"?>
<rueda>
  <operacion>
    <importe>2000000</importe>
    <plazo>60</plazo>
  </operacion>
</rueda>`), 0o644))

	// Session log after-hours.
	sesionPath := filepath.Join(dir, "sesion_338_202506.log")
	must(t, os.WriteFile(sesionPath, []byte(`2026-06-15 16:42:01 INFO  CONCERTACION-OK ID=1
2026-06-15 16:50:00 INFO  Operador=338
`), 0o644))

	// Random ignored.
	must(t, os.WriteFile(filepath.Join(dir, "random.txt"),
		[]byte(`nope`), 0o644))

	// Public skipped.
	pub := filepath.Join(usersBase, "Public", "AppData", "Roaming", "SIOPEL")
	must(t, os.MkdirAll(pub, 0o755))
	must(t, os.WriteFile(filepath.Join(pub, "siopel.ini"),
		[]byte(`[SIOPEL]`), 0o644))

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
	if len(got) != 4 {
		t.Fatalf("want 4 (cfg+rueda+caucion+sesion), got %d: %+v", len(got), got)
	}

	var cfg, rueda, caucion, sesion Row
	for _, r := range got {
		switch r.FilePath {
		case cfgPath:
			cfg = r
		case ruedaPath:
			rueda = r
		case caucionPath:
			caucion = r
		case sesionPath:
			sesion = r
		}
	}

	if cfg.ArtifactKind != KindSIOPELConfig {
		t.Fatalf("cfg kind=%q", cfg.ArtifactKind)
	}
	if !cfg.HasPasswordInConfig {
		t.Fatalf("cfg must flag password: %+v", cfg)
	}
	if cfg.OperatorMatricula != "338" {
		t.Fatalf("cfg matricula=%q", cfg.OperatorMatricula)
	}
	if cfg.OperatorCuitPrefix != "20" || cfg.OperatorCuitSuffix4 != "6789" {
		t.Fatalf("cfg operator: %+v", cfg)
	}
	if cfg.DealerCode != "ABCD" {
		t.Fatalf("cfg dealer=%q", cfg.DealerCode)
	}
	if !cfg.IsCredentialExposureRisk {
		t.Fatalf("readable + password + operator = exposure: %+v", cfg)
	}

	if rueda.ArtifactKind != KindRuedaData {
		t.Fatalf("rueda kind=%q", rueda.ArtifactKind)
	}
	if rueda.RuedaKind != RuedaCambio {
		t.Fatalf("rueda subkind=%q", rueda.RuedaKind)
	}
	if rueda.TradeCount != 1 {
		t.Fatalf("rueda trade=%d", rueda.TradeCount)
	}
	if rueda.MaxNotionalARSCents != 500_000_000 {
		t.Fatalf("rueda notional=%d", rueda.MaxNotionalARSCents)
	}
	if rueda.IsCredentialExposureRisk {
		t.Fatalf("0o600 must NOT flag: %+v", rueda)
	}
	if rueda.PeriodYYYYMM != "202506" {
		t.Fatalf("rueda period=%q", rueda.PeriodYYYYMM)
	}

	if caucion.RuedaKind != RuedaCaucion {
		t.Fatalf("caucion subkind=%q", caucion.RuedaKind)
	}
	if !caucion.HasCaucionRepo {
		t.Fatalf("60d tenor must flag caucion-repo: %+v", caucion)
	}

	if sesion.ArtifactKind != KindSessionLog {
		t.Fatalf("sesion kind=%q", sesion.ArtifactKind)
	}
	if !sesion.IsAfterHours {
		t.Fatalf("16:42 must flag after-hours: %+v", sesion)
	}
	if sesion.ConcertacionCount != 1 {
		t.Fatalf("sesion concertacion=%d", sesion.ConcertacionCount)
	}
}

func TestCollectorRespectsEnv(t *testing.T) {
	tmp := t.TempDir()
	envDir := filepath.Join(tmp, "custom-siopel")
	must(t, os.MkdirAll(envDir, 0o755))
	must(t, os.WriteFile(filepath.Join(envDir, "siopel.ini"),
		[]byte(`[SIOPEL]
Operador=338
Password=x
`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "SIOPEL_DIR" {
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
	if len(got) != 1 || got[0].ArtifactKind != KindSIOPELConfig {
		t.Fatalf("env: %+v", got)
	}
	if !got[0].HasPasswordInConfig {
		t.Fatalf("env file must flag password: %+v", got)
	}
}

func TestCollectorMissingPathsOK(t *testing.T) {
	c := &fileCollector{
		installRoots: []string{"/nope-siopel"},
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
		{FilePath: "z", ArtifactKind: KindSIOPELConfig},
		{FilePath: "a", ArtifactKind: KindRuedaData},
		{FilePath: "a", ArtifactKind: KindSIOPELConfig},
	}
	SortRows(in)
	if in[0].FilePath != "a" || in[0].ArtifactKind != KindSIOPELConfig {
		t.Fatalf("first=%+v", in[0])
	}
}

func TestCandidateExtAccepts(t *testing.T) {
	yes := []string{
		"file.ini", "file.cfg", "file.conf",
		"file.xml", "file.csv", "file.tsv",
		"file.dat", "file.usr",
		"file.log", "file.txt",
		"file.msi", "file.exe",
	}
	for _, v := range yes {
		if !IsCandidateExt(v) {
			t.Fatalf("expected ext: %q", v)
		}
	}
	if IsCandidateExt("file.pdf") {
		t.Fatal(".pdf must NOT match")
	}
}

func TestHashContents(t *testing.T) {
	a := HashContents([]byte("siopel"))
	b := HashContents([]byte("siopel"))
	c := HashContents([]byte("SIOPEL"))
	if a != b {
		t.Fatal("hash drift on identical input")
	}
	if a == c {
		t.Fatal("hash collision case-insensitive")
	}
	if len(a) != 64 {
		t.Fatalf("hash length=%d, want 64", len(a))
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
