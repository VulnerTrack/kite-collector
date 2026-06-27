package winargafiprg5193

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindRG5193Daily), "afip-rg5193-daily"},
		{string(KindRG5527Crypto), "afip-rg5527-crypto"},
		{string(KindCOTIInversiones), "afip-coti-inversiones"},
		{string(KindGananciasRetenciones), "afip-ganancias-retenciones"},
		{string(KindBienesPersonales), "afip-bienes-personales"},
		{string(KindF8125Transfer), "afip-f8125-transfer"},
		{string(KindExteriorizacion), "afip-exteriorizacion"},
		{string(KindSessionToken), "afip-session-token"},
		{string(KindConfig), "afip-config"},
		{string(KindInstaller), "afip-installer"},
		{string(KindOther), "other"},
		{string(KindUnknown), "unknown"},
		{string(ReporterALYC), "alyc"},
		{string(ReporterAsegurador), "asegurador"},
		{string(ReporterSociedadBolsa), "sociedad-bolsa"},
		{string(ReporterBankingCustodian), "banking-custodian"},
		{string(ReporterFCIManager), "fci-manager"},
		{string(ReporterFintech), "fintech"},
		{string(ReporterCriptoExchange), "cripto-exchange"},
		{string(ReporterOther), "other"},
		{string(ReporterUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestIsCandidateName(t *testing.T) {
	yes := []string{
		"afip_config.xml",
		"clave_fiscal.tok",
		"rg5193_daily_20260615.txt",
		"rg_5193_202506.txt",
		"rg5527_crypto_20260615.json",
		"coti_inversiones_202506.xml",
		"ganancias_retenciones_202506.csv",
		"bienes_personales_27111111114.xlsx",
		"f8125_transfer_202506.xml",
		"exteriorizacion_202506.xml",
		"arca_session.tok",
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
		"afip_config.xml":                    KindConfig,
		"arca_settings.json":                 KindConfig,
		"clave_fiscal.tok":                   KindSessionToken,
		"session_token.tok":                  KindSessionToken,
		"rg5193_daily_20260615.txt":          KindRG5193Daily,
		"rg_4838_legacy_20260615.txt":        KindRG5193Daily,
		"rg5527_crypto_20260615.json":        KindRG5527Crypto,
		"crypto_psav_20260615.json":          KindRG5527Crypto,
		"coti_inversiones_202506.xml":        KindCOTIInversiones,
		"ganancias_retenciones_202506.csv":   KindGananciasRetenciones,
		"bienes_personales_27111111114.xlsx": KindBienesPersonales,
		"f8125_transfer_202506.xml":          KindF8125Transfer,
		"exteriorizacion_202506.xml":         KindExteriorizacion,
		"afip_installer.msi":                 KindInstaller,
		"":                                   KindUnknown,
	}
	for in, want := range cases {
		if got := ArtifactKindFromName(in); got != want {
			t.Fatalf("ArtifactKindFromName(%q)=%q want %q", in, got, want)
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

func TestPeriodFromFilename(t *testing.T) {
	if PeriodFromFilename("rg5193_daily_202506.txt") != "202506" {
		t.Fatal("period mismatch")
	}
	if PeriodFromFilename("random.txt") != "" {
		t.Fatal("non-period must be empty")
	}
}

func TestIsJuridicalAndNaturalCuit(t *testing.T) {
	juridical := []string{"30", "33", "34"}
	natural := []string{"20", "23", "24", "27"}
	for _, p := range juridical {
		if !IsJuridicalCuitPrefix(p) {
			t.Fatalf("expected juridical: %q", p)
		}
		if IsNaturalCuitPrefix(p) {
			t.Fatalf("expected NOT natural: %q", p)
		}
	}
	for _, p := range natural {
		if !IsNaturalCuitPrefix(p) {
			t.Fatalf("expected natural: %q", p)
		}
		if IsJuridicalCuitPrefix(p) {
			t.Fatalf("expected NOT juridical: %q", p)
		}
	}
}

func TestDistinctClientesInBody(t *testing.T) {
	body := []byte(`27-11111111-4
30-71234567-8
27-11111111-4
20-99999999-1`)
	// 30 is juridical → excluded. 27+27 dedupes. 20 distinct.
	// Expected: 2 natural-person clients.
	if got := DistinctClientesInBody(body); got != 2 {
		t.Fatalf("distinct=%d want 2", got)
	}
}

func TestIsCredentialKind(t *testing.T) {
	yes := []ArtifactKind{
		KindConfig, KindSessionToken,
		KindRG5193Daily, KindRG5527Crypto,
		KindCOTIInversiones, KindGananciasRetenciones,
		KindBienesPersonales, KindF8125Transfer,
		KindExteriorizacion,
	}
	no := []ArtifactKind{
		KindInstaller, KindOther, KindUnknown,
	}
	for _, k := range yes {
		if !IsCredentialKind(k) {
			t.Fatalf("expected cred kind: %q", k)
		}
	}
	for _, k := range no {
		if IsCredentialKind(k) {
			t.Fatalf("expected NOT cred kind: %q", k)
		}
	}
}

func TestAnnotateExposure(t *testing.T) {
	r := Row{
		ArtifactKind:        KindRG5193Daily,
		HasAFIPSessionToken: true,
		ClienteCuitPrefix:   "27",
		ClienteCuitSuffix4:  "1114",
		FileMode:            0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasClienteCuit {
		t.Fatal("cliente cuit must flag")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("readable + AFIP token + cuit = exposure")
	}
}

func TestAnnotateLockedDown(t *testing.T) {
	r := Row{
		ArtifactKind:        KindRG5193Daily,
		HasAFIPSessionToken: true,
		ClienteCuitPrefix:   "27",
		ClienteCuitSuffix4:  "1114",
		FileMode:            0o600,
	}
	AnnotateSecurity(&r)
	if r.IsCredentialExposureRisk {
		t.Fatal("0o600 must NOT flag exposure")
	}
}

func TestAnnotateCrypto(t *testing.T) {
	r := Row{
		ArtifactKind:           KindRG5527Crypto,
		CryptoTransactionCount: 50,
	}
	AnnotateSecurity(&r)
	if !r.HasCryptoReporting {
		t.Fatal("crypto count must flag")
	}
}

func TestAnnotateHighValue(t *testing.T) {
	r := Row{
		ArtifactKind:   KindRG5193Daily,
		HighValueCount: 3,
	}
	AnnotateSecurity(&r)
	if !r.HasHighValueThreshold {
		t.Fatal("high value count must flag")
	}
}

func TestAnnotateCrossBorder(t *testing.T) {
	r := Row{
		ArtifactKind:     KindF8125Transfer,
		CrossBorderCount: 5,
	}
	AnnotateSecurity(&r)
	if !r.HasCrossBorderTransfer {
		t.Fatal("cross border count must flag")
	}
}

func TestAnnotateBienesAutoFlag(t *testing.T) {
	r := Row{
		ArtifactKind: KindBienesPersonales,
	}
	AnnotateSecurity(&r)
	if !r.HasBienesPersonales {
		t.Fatal("bienes-personales kind must auto-flag")
	}
}

func TestParseAFIPCredentials(t *testing.T) {
	body := []byte(`<AFIP>
<clave_fiscal>SuperSecretSession123456789012345</clave_fiscal>
<reporter_cuit>30-71234567-8</reporter_cuit>
<password>secret123</password>
<cliente_cuit>27-11111111-4</cliente_cuit>
</AFIP>`)
	f := ParseAFIPCredentials(body)
	if !f.HasPassword {
		t.Fatal("password must flag")
	}
	if f.AFIPToken == "" {
		t.Fatal("AFIP token must extract")
	}
	if f.ReporterCuitRaw == "" {
		t.Fatal("reporter cuit missing")
	}
	if f.ClienteCuitRaw == "" {
		t.Fatal("cliente cuit missing")
	}
}

func TestParseAFIPRG5193Daily(t *testing.T) {
	body := []byte(`reporter_cuit: 30-71234567-8
operacion_id=1 cliente_cuit=27-11111111-4 importe_ars=15000000.00 importe_usd=15000.00
operacion_id=2 cliente_cuit=27-22222222-5 importe_ars=8000000.00 importe_usd=8000.00
operacion_id=3 cliente_cuit=20-33333333-9 importe_ars=250000000000000.00 importe_usd=250000000.00
dni: 11222333 apellido_nombre: PEREZ JUAN
`)
	f := ParseAFIPRG5193Daily(body)
	if f.TransactionCount < 3 {
		t.Fatalf("txns=%d", f.TransactionCount)
	}
	if f.DistinctClientes < 3 {
		t.Fatalf("distinct=%d", f.DistinctClientes)
	}
	if f.ReporterCuitRaw == "" {
		t.Fatal("reporter cuit missing")
	}
	if f.HighValueCount < 1 {
		t.Fatalf("high value=%d want >=1", f.HighValueCount)
	}
	if !f.HasPIIBundle {
		t.Fatal("PII bundle must flag (DNI + name + natural CUIT)")
	}
}

func TestParseAFIPRG5527Crypto(t *testing.T) {
	body := []byte(`reporter_cuit: 30-71234567-8 (cripto-exchange PSAV)
operacion_id=1 cliente_cuit=27-11111111-4 wallet_address=0xabc btc usdt importe_usd=500000.00
operacion_id=2 cliente_cuit=27-22222222-5 wallet_address=0xdef eth importe_usd=300000.00
`)
	f := ParseAFIPRG5527Crypto(body)
	if !f.HasCryptoMarker {
		t.Fatal("crypto marker must flag")
	}
	if f.CryptoTransactions < 2 {
		t.Fatalf("crypto txns=%d", f.CryptoTransactions)
	}
	if f.HighValueCount < 1 {
		t.Fatalf("high value=%d want >=1", f.HighValueCount)
	}
}

func TestParseAFIPGananciasRetenciones(t *testing.T) {
	body := []byte(`rg830 ganancias_retencion
operacion_id=1 cliente_cuit=27-11111111-4 importe_ars=1000000.00 retencion_ganancias=10.5
operacion_id=2 cliente_cuit=27-22222222-5 importe_ars=500000.00 retencion_ganancias=10.5
`)
	f := ParseAFIPGananciasRetenciones(body)
	if !f.HasGanancias {
		t.Fatal("ganancias marker must flag")
	}
	if f.TransactionCount < 2 {
		t.Fatalf("txns=%d", f.TransactionCount)
	}
}

func TestParseAFIPBienesPersonales(t *testing.T) {
	body := []byte(`<bienes_personales>
<cliente_cuit>27-11111111-4</cliente_cuit>
<dni>11222333</dni>
<apellido_nombre>PEREZ JUAN</apellido_nombre>
<patrimonio_neto importe_ars=500000000.00 />
<alicuota_bienes>1.5</alicuota_bienes>
</bienes_personales>`)
	f := ParseAFIPBienesPersonales(body)
	if !f.HasBienes {
		t.Fatal("bienes marker must flag")
	}
	if !f.HasPIIBundle {
		t.Fatal("PII bundle must flag")
	}
	if f.ClienteCuitRaw == "" {
		t.Fatal("cliente cuit missing")
	}
}

func TestParseAFIPF8125Transfer(t *testing.T) {
	body := []byte(`transferencia_exterior swift_code=BSCHARBA iban=AR123456 importe_usd=500000.00
foreign_transfer cliente_cuit=27-11111111-4 cuenta_exterior=US456789 importe_usd=300000.00
`)
	f := ParseAFIPF8125Transfer(body)
	if f.CrossBorderCount < 2 {
		t.Fatalf("cross border=%d", f.CrossBorderCount)
	}
	if f.HighValueCount < 1 {
		t.Fatalf("high value=%d", f.HighValueCount)
	}
}

func TestParseAFIPEmpty(t *testing.T) {
	f := ParseAFIPCredentials(nil)
	if f.HasPassword || f.AFIPToken != "" {
		t.Fatalf("empty must yield zero: %+v", f)
	}
}

// -- collector end-to-end -----------------------------------------

func TestCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")
	dir := filepath.Join(usersBase, "alice", "AppData", "Roaming", "AFIP")
	must(t, os.MkdirAll(filepath.Join(dir, "reports"), 0o755))

	cfgPath := filepath.Join(dir, "afip_config.xml")
	must(t, os.WriteFile(cfgPath, []byte(`<AFIP>
<clave_fiscal>SuperSecretSessionTok123456789012</clave_fiscal>
<reporter_cuit>30-71234567-8</reporter_cuit>
<password>secret123</password>
<cliente_cuit>27-11111111-4</cliente_cuit>
</AFIP>`), 0o644))

	rg5193Path := filepath.Join(dir, "reports", "rg5193_daily_202506.txt")
	must(t, os.WriteFile(rg5193Path, []byte(`reporter_cuit: 30-71234567-8
operacion_id=1 cliente_cuit=27-11111111-4 importe_ars=15000000.00 importe_usd=15000.00
operacion_id=2 cliente_cuit=27-22222222-5 importe_ars=80000000.00 importe_usd=80000.00
operacion_id=3 cliente_cuit=20-33333333-9 importe_ars=2500000000000.00 importe_usd=250000000.00
dni: 11222333 apellido_nombre: PEREZ JUAN
`), 0o644))

	rg5527Path := filepath.Join(dir, "reports", "rg5527_crypto_202506.json")
	must(t, os.WriteFile(rg5527Path, []byte(`reporter_cuit: 30-71234567-8 cripto-exchange
operacion_id=1 cliente_cuit=27-11111111-4 wallet_address=0xabc btc importe_usd=500000.00
`), 0o644))

	bienesPath := filepath.Join(dir, "reports", "bienes_personales_27111111114.xlsx")
	must(t, os.WriteFile(bienesPath, []byte(`<bienes>
<cliente_cuit>27-11111111-4</cliente_cuit>
<dni>11222333</dni>
<apellido_nombre>PEREZ JUAN</apellido_nombre>
</bienes>`), 0o644))

	// Random ignored.
	must(t, os.WriteFile(filepath.Join(dir, "random.txt"),
		[]byte(`nope`), 0o644))

	// Public skipped.
	pub := filepath.Join(usersBase, "Public", "AppData", "Roaming", "AFIP")
	must(t, os.MkdirAll(pub, 0o755))
	must(t, os.WriteFile(filepath.Join(pub, "afip_config.xml"),
		[]byte(`<x/>`), 0o644))

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
	if len(got) != 4 {
		t.Fatalf("want 4 (cfg+rg5193+rg5527+bienes), got %d: %+v", len(got), got)
	}

	var cfg, rg5193, rg5527, bienes Row
	for _, r := range got {
		switch r.FilePath {
		case cfgPath:
			cfg = r
		case rg5193Path:
			rg5193 = r
		case rg5527Path:
			rg5527 = r
		case bienesPath:
			bienes = r
		}
	}

	if cfg.ArtifactKind != KindConfig {
		t.Fatalf("cfg kind=%q", cfg.ArtifactKind)
	}
	if !cfg.HasPasswordInConfig {
		t.Fatalf("cfg must flag password: %+v", cfg)
	}
	if !cfg.HasAFIPSessionToken {
		t.Fatalf("cfg must flag AFIP token: %+v", cfg)
	}
	if cfg.ReporterCuitPrefix != "30" {
		t.Fatalf("cfg reporter prefix=%q", cfg.ReporterCuitPrefix)
	}
	if !cfg.HasClienteCuit {
		t.Fatalf("cfg must flag cliente cuit: %+v", cfg)
	}
	if !cfg.IsCredentialExposureRisk {
		t.Fatalf("readable + AFIP token + password + cuit = exposure: %+v", cfg)
	}

	if rg5193.ArtifactKind != KindRG5193Daily {
		t.Fatalf("rg5193 kind=%q", rg5193.ArtifactKind)
	}
	if rg5193.TransactionCount < 3 {
		t.Fatalf("rg5193 txns=%d", rg5193.TransactionCount)
	}
	if !rg5193.HasHighValueThreshold {
		t.Fatalf("rg5193 must flag high value: %+v", rg5193)
	}
	if !rg5193.HasPIINaturalPerson {
		t.Fatalf("rg5193 must flag PII bundle: %+v", rg5193)
	}
	if rg5193.ReporterClass != ReporterALYC {
		t.Fatalf("rg5193 reporter=%q want alyc", rg5193.ReporterClass)
	}

	if rg5527.ArtifactKind != KindRG5527Crypto {
		t.Fatalf("rg5527 kind=%q", rg5527.ArtifactKind)
	}
	if !rg5527.HasCryptoReporting {
		t.Fatalf("rg5527 must flag crypto: %+v", rg5527)
	}
	if rg5527.ReporterClass != ReporterCriptoExchange {
		t.Fatalf("rg5527 reporter=%q want cripto-exchange", rg5527.ReporterClass)
	}

	if bienes.ArtifactKind != KindBienesPersonales {
		t.Fatalf("bienes kind=%q", bienes.ArtifactKind)
	}
}

func TestCollectorRespectsEnv(t *testing.T) {
	tmp := t.TempDir()
	envDir := filepath.Join(tmp, "custom-afip")
	must(t, os.MkdirAll(envDir, 0o755))
	must(t, os.WriteFile(filepath.Join(envDir, "afip_config.xml"),
		[]byte(`<AFIP><reporter_cuit>30-71234567-8</reporter_cuit></AFIP>`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "AFIP_DIR" {
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
	if len(got) != 1 || got[0].ArtifactKind != KindConfig {
		t.Fatalf("env: %+v", got)
	}
}

func TestCollectorMissingPathsOK(t *testing.T) {
	c := &fileCollector{
		installRoots: []string{"/nope-afip"},
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
		{FilePath: "z", ArtifactKind: KindConfig},
		{FilePath: "a", ArtifactKind: KindRG5193Daily},
		{FilePath: "a", ArtifactKind: KindConfig},
	}
	SortRows(in)
	if in[0].FilePath != "a" || in[0].ArtifactKind != KindConfig {
		t.Fatalf("first=%+v", in[0])
	}
}

func TestHashSecret(t *testing.T) {
	a := HashSecret("abc")
	b := HashSecret("abc")
	c := HashSecret("ABC")
	if a != b {
		t.Fatal("hash drift")
	}
	if a != c {
		t.Fatal("hash must be case-insensitive")
	}
	if len(a) != 64 {
		t.Fatalf("hash len=%d", len(a))
	}
}

func TestClassifyReporter(t *testing.T) {
	if classifyReporter(KindRG5527Crypto, AFIPFields{}) != ReporterCriptoExchange {
		t.Fatal("rg5527 -> cripto-exchange")
	}
	if classifyReporter(KindBienesPersonales, AFIPFields{}) != ReporterOther {
		t.Fatal("bienes -> other")
	}
	if classifyReporter(KindGananciasRetenciones, AFIPFields{HasGanancias: true}) != ReporterALYC {
		t.Fatal("ganancias -> alyc")
	}
	if classifyReporter(KindRG5193Daily, AFIPFields{}) != ReporterALYC {
		t.Fatal("rg5193 -> alyc")
	}
	if classifyReporter(KindConfig, AFIPFields{ReporterCuitRaw: "30-71234567-8"}) != ReporterALYC {
		t.Fatal("juridical cuit -> alyc")
	}
	if classifyReporter(KindConfig, AFIPFields{}) != ReporterUnknown {
		t.Fatal("unknown")
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
