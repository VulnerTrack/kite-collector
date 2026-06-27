package winargsintesis

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindConfig), "sintesis-config"},
		{string(KindCredentials), "sintesis-credentials"},
		{string(KindFCIDatabase), "sintesis-fci-database"},
		{string(KindNAVCalc), "sintesis-nav-calc"},
		{string(KindCuotaparteLedger), "sintesis-cuotaparte-ledger"},
		{string(KindSuscripcion), "sintesis-suscripcion"},
		{string(KindRescate), "sintesis-rescate"},
		{string(KindBCRAA5273), "sintesis-bcra-a5273"},
		{string(KindCNVHR), "sintesis-cnv-hr"},
		{string(KindValuationFile), "sintesis-valuation-file"},
		{string(KindPagoRescate), "sintesis-pago-rescate"},
		{string(KindInstaller), "sintesis-installer"},
		{string(KindOther), "other"},
		{string(KindUnknown), "unknown"},
		{string(AccountSociedadGerente), "sociedad-gerente"},
		{string(AccountSociedadDepositaria), "sociedad-depositaria"},
		{string(AccountComplianceOfficer), "compliance-officer"},
		{string(AccountOpsAdministrator), "ops-administrator"},
		{string(AccountAPI), "api"},
		{string(AccountDemo), "demo"},
		{string(AccountOther), "other"},
		{string(AccountUnknown), "unknown"},
		{string(ProductFCIMoneyMarket), "fci-money-market"},
		{string(ProductFCIRentaFija), "fci-renta-fija"},
		{string(ProductFCIRentaVariable), "fci-renta-variable"},
		{string(ProductFCIMixto), "fci-mixto"},
		{string(ProductFCIPyme), "fci-pyme"},
		{string(ProductFCIInfrastructure), "fci-infrastructure"},
		{string(ProductMultiFCI), "multi-fci"},
		{string(ProductOther), "other"},
		{string(ProductUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestIsCandidateName(t *testing.T) {
	yes := []string{
		"sintesis.cfg",
		"sintesis_credentials.json",
		"fci_200.sdb",
		"valor_cuota_20260615.nav",
		"cuotaparte_ledger_20260615.csv",
		"suscripcion_20260615.csv",
		"rescate_20260615.csv",
		"bcra_a5273_20260615.txt",
		"cnv_hr_20260615.xml",
		"hecho_relevante_fci200.xml",
		"valuacion_20260615.csv",
		"pago_rescate_20260615.txt",
		"sintesis_installer.msi",
		"fci_database.mdb",
	}
	no := []string{"", "factura.xml", "random.bin", "report.pdf"}
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
		"sintesis.cfg":               KindConfig,
		"sintesis_credentials.json":  KindCredentials,
		"sintesis_api_token.json":    KindCredentials,
		"fci_200.sdb":                KindFCIDatabase,
		"fci_database.mdb":           KindFCIDatabase,
		"valor_cuota_20260615.nav":   KindNAVCalc,
		"vc_20260615.csv":            KindNAVCalc,
		"cuotaparte_ledger.csv":      KindCuotaparteLedger,
		"cuotapartista_export.csv":   KindCuotaparteLedger,
		"suscripcion_20260615.csv":   KindSuscripcion,
		"rescate_20260615.csv":       KindRescate,
		"bcra_a5273_20260615.txt":    KindBCRAA5273,
		"a5273_composicion.txt":      KindBCRAA5273,
		"cnv_hr_20260615.xml":        KindCNVHR,
		"hecho_relevante_fci200.xml": KindCNVHR,
		"valuacion_20260615.csv":     KindValuationFile,
		"pago_rescate_20260615.txt":  KindPagoRescate,
		"sintesis_installer.msi":     KindInstaller,
		"":                           KindUnknown,
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
	if PeriodFromFilename("bcra_a5273_20260615.txt") != "202606" {
		t.Fatal("period mismatch")
	}
}

func TestReportingDateFromFilename(t *testing.T) {
	if got := ReportingDateFromFilename("bcra_a5273_20260615.txt"); got != "2026-06-15" {
		t.Fatalf("date=%q", got)
	}
}

func TestIsCredentialKind(t *testing.T) {
	yes := []ArtifactKind{
		KindConfig, KindCredentials, KindFCIDatabase,
		KindNAVCalc, KindCuotaparteLedger,
		KindSuscripcion, KindRescate, KindBCRAA5273, KindCNVHR,
		KindValuationFile, KindPagoRescate,
	}
	no := []ArtifactKind{KindInstaller, KindOther, KindUnknown}
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
		ArtifactKind:        KindConfig,
		HasPasswordInConfig: true,
		HasDBCredentials:    true,
		FileMode:            0o644,
	}
	AnnotateSecurity(&r)
	if !r.IsCredentialExposureRisk {
		t.Fatal("readable + password + DB creds = exposure")
	}
}

func TestAnnotateLockedDown(t *testing.T) {
	r := Row{
		ArtifactKind:        KindConfig,
		HasPasswordInConfig: true,
		FileMode:            0o600,
	}
	AnnotateSecurity(&r)
	if r.IsCredentialExposureRisk {
		t.Fatal("0o600 must NOT flag exposure")
	}
}

func TestAnnotateNAVAuto(t *testing.T) {
	r := Row{ArtifactKind: KindNAVCalc}
	AnnotateSecurity(&r)
	if !r.HasNAVCalcData {
		t.Fatal("NAV kind must auto-flag")
	}
}

func TestAnnotateCuotaparteRoster(t *testing.T) {
	r := Row{
		ArtifactKind:       KindCuotaparteLedger,
		CuotapartistaCount: CuotapartistaRosterThreshold + 1,
	}
	AnnotateSecurity(&r)
	if !r.HasCuotaparteLedger {
		t.Fatal("cuotaparte kind must flag")
	}
	if !r.HasClienteCuitExport {
		t.Fatal(">=10 cuotapartistas must flag client export")
	}
}

func TestAnnotateBCRAA5273Auto(t *testing.T) {
	r := Row{ArtifactKind: KindBCRAA5273}
	AnnotateSecurity(&r)
	if !r.HasBCRAA5273Report {
		t.Fatal("BCRA A5273 kind must auto-flag")
	}
}

func TestAnnotateCNVHRAuto(t *testing.T) {
	r := Row{ArtifactKind: KindCNVHR}
	AnnotateSecurity(&r)
	if !r.HasCNVHRFiling {
		t.Fatal("CNV HR kind must auto-flag")
	}
}

func TestAnnotatePagoRescateAuto(t *testing.T) {
	r := Row{ArtifactKind: KindPagoRescate}
	AnnotateSecurity(&r)
	if !r.HasPagoRescate {
		t.Fatal("pago rescate kind must auto-flag")
	}
}

func TestAnnotateHighAUM(t *testing.T) {
	r := Row{
		ArtifactKind: KindNAVCalc,
		AUMUSDCents:  HighAUMUSDCents + 1,
	}
	AnnotateSecurity(&r)
	if !r.HasHighAUM {
		t.Fatal("> 10 M USD must flag high AUM")
	}
}

func TestAnnotateConcentrated(t *testing.T) {
	r := Row{
		ArtifactKind: KindCuotaparteLedger,
		MaxHolderPct: ConcentratedHolderPct + 5,
	}
	AnnotateSecurity(&r)
	if !r.HasConcentratedCuotaparte {
		t.Fatal("> 50 % single holder must flag concentrated")
	}
}

func TestAnnotatePIIBundle(t *testing.T) {
	r := Row{
		ArtifactKind:   KindCuotaparteLedger,
		PIISignalCount: 2,
	}
	AnnotateSecurity(&r)
	if !r.HasPIIBundle {
		t.Fatal("PII signal >=2 must flag bundle")
	}
}

func TestParseSintesisConfig(t *testing.T) {
	body := []byte(`# Sintesis configuration
db_user=fci_admin
db_password=Secr3tP@ss
sintesis_password=AnotherSecret
fci_code=200
sociedad_gerente_cuit=30-71234567-8
Server=fcidb.local;UID=fci_admin;Pwd=secret123;Database=Sintesis
cliente_cuit=27-11111111-4
dni=12345678
`)
	f := ParseSintesisConfig(body)
	if !f.HasPassword {
		t.Fatal("password must flag")
	}
	if !f.HasDBCredentials {
		t.Fatal("DB connection string must flag")
	}
	if f.DBConnString == "" {
		t.Fatal("DB conn string must extract")
	}
	if f.FCICode != "200" {
		t.Fatalf("FCI=%q", f.FCICode)
	}
	if f.SociedadGerenteCUIT == "" {
		t.Fatal("sociedad gerente cuit missing")
	}
	if f.ClienteCuitRaw == "" {
		t.Fatal("cliente cuit missing")
	}
	if f.ClienteDNI == "" {
		t.Fatal("cliente DNI missing")
	}
}

func TestParseSintesisNAVCalc(t *testing.T) {
	body := []byte(`fci_code=200
valor_cuota=1234.5678
aum_usd=15000000
max_holder_pct=42
fecha=20260615
`)
	f := ParseSintesisNAVCalc(body)
	if f.FCICode != "200" {
		t.Fatalf("FCI=%q", f.FCICode)
	}
	if f.NAVARSCents < 100000 {
		t.Fatalf("NAV=%d", f.NAVARSCents)
	}
	if f.AUMUSDCents < 100000000 {
		t.Fatalf("AUM=%d", f.AUMUSDCents)
	}
	if f.MaxHolderPct != 42 {
		t.Fatalf("max holder pct=%d", f.MaxHolderPct)
	}
}

func TestParseSintesisCuotaparteLedger(t *testing.T) {
	body := []byte(`cuotapartista_id,titular_cuit,cuotapartes,valor_usd
1,27-11111111-4,150.50,5000
2,30-71234567-8,200.00,10000
3,20-22222222-9,500.00,25000
4,27-33333333-1,100.00,4000
5,30-44444444-2,200.00,8000
6,27-55555555-3,150.00,6000
7,20-66666666-4,300.00,12000
8,27-77777777-5,250.00,10000
9,30-88888888-6,400.00,16000
10,27-99999999-7,500.00,20000
11,55-22222222-9,300.00,12000
fci_code=200
max_holder_pct=22
`)
	f := ParseSintesisCuotaparteLedger(body)
	if f.CuotapartistaCount < CuotapartistaRosterThreshold {
		t.Fatalf("cuotapartistas=%d", f.CuotapartistaCount)
	}
	if !f.HasForeignResident {
		t.Fatal("55-prefix CUIT must flag foreign")
	}
}

func TestParseSintesisSuscripcion(t *testing.T) {
	body := []byte(`suscripcion_id,fci_code,monto,fecha
s-1,200,5000,20260615
s-2,200,10000,20260615
s-3,200,2500,20260616
`)
	f := ParseSintesisSuscripcion(body)
	if f.SuscripcionCount < 3 {
		t.Fatalf("suscripciones=%d", f.SuscripcionCount)
	}
}

func TestParseSintesisRescate(t *testing.T) {
	body := []byte(`rescate_id,fci_code,monto,fecha
r-1,200,2000,20260615
r-2,200,1500,20260616
`)
	f := ParseSintesisRescate(body)
	if f.RescateCount < 2 {
		t.Fatalf("rescates=%d", f.RescateCount)
	}
}

func TestParseSintesisBCRAA5273(t *testing.T) {
	body := []byte(`a5273
composicion_cartera_diaria
fci_code=200
sociedad_gerente_cuit=30-71234567-8
patrimonio_neto_diario=AR$ 1500000000
`)
	f := ParseSintesisBCRAA5273(body)
	if f.FCICode != "200" {
		t.Fatalf("FCI=%q", f.FCICode)
	}
}

func TestParseSintesisCNVHR(t *testing.T) {
	body := []byte(`<hecho_relevante>
<fci_code>200</fci_code>
<sociedad_gerente_cuit>30-71234567-8</sociedad_gerente_cuit>
<fecha_hecho>2026-06-15</fecha_hecho>
<descripcion>Modificación reglamento gestión</descripcion>
</hecho_relevante>`)
	f := ParseSintesisCNVHR(body)
	if f.FCICode != "200" {
		t.Fatalf("FCI=%q", f.FCICode)
	}
}

func TestParseSintesisPagoRescate(t *testing.T) {
	body := []byte(`pago_rescate
fci_code=200
liquidacion_rescate
rescate_id r-1 5000
rescate_id r-2 7500
sipap_settlement
`)
	f := ParseSintesisPagoRescate(body)
	if f.FCICode != "200" {
		t.Fatalf("FCI=%q", f.FCICode)
	}
	if f.RescateCount < 2 {
		t.Fatalf("rescates=%d", f.RescateCount)
	}
}

func TestParseSintesisEmpty(t *testing.T) {
	f := ParseSintesisConfig(nil)
	if f.HasPassword || f.HasDBCredentials {
		t.Fatalf("empty must yield zero: %+v", f)
	}
}

func TestClassifyAccount(t *testing.T) {
	if got := classifyAccount(Row{HasCNVHRFiling: true}); got != AccountComplianceOfficer {
		t.Fatalf("HR -> compliance, got %q", got)
	}
	if got := classifyAccount(Row{HasBCRAA5273Report: true}); got != AccountComplianceOfficer {
		t.Fatalf("BCRA -> compliance, got %q", got)
	}
	if got := classifyAccount(Row{ArtifactKind: KindFCIDatabase}); got != AccountSociedadGerente {
		t.Fatalf("DB -> sociedad-gerente, got %q", got)
	}
	if got := classifyAccount(Row{HasNAVCalcData: true}); got != AccountSociedadGerente {
		t.Fatalf("NAV -> sociedad-gerente, got %q", got)
	}
	if got := classifyAccount(Row{HasPagoRescate: true}); got != AccountOpsAdministrator {
		t.Fatalf("pago rescate -> ops, got %q", got)
	}
	if got := classifyAccount(Row{}); got != AccountUnknown {
		t.Fatalf("unknown, got %q", got)
	}
}

func TestClassifyProduct(t *testing.T) {
	if got := classifyProduct(Row{DistinctFCIsCount: 3}); got != ProductMultiFCI {
		t.Fatalf("multi -> multi-fci, got %q", got)
	}
	if got := classifyProduct(Row{FilePath: "money_market_200.csv"}); got != ProductFCIMoneyMarket {
		t.Fatalf("money_market -> fci-money-market, got %q", got)
	}
	if got := classifyProduct(Row{FilePath: "renta_fija_300.csv"}); got != ProductFCIRentaFija {
		t.Fatalf("renta_fija -> fci-renta-fija, got %q", got)
	}
	if got := classifyProduct(Row{FilePath: "renta_variable_400.csv"}); got != ProductFCIRentaVariable {
		t.Fatalf("renta_variable -> fci-renta-variable, got %q", got)
	}
	if got := classifyProduct(Row{FilePath: "mixto_500.csv"}); got != ProductFCIMixto {
		t.Fatalf("mixto -> fci-mixto, got %q", got)
	}
	if got := classifyProduct(Row{FilePath: "pyme_600.csv"}); got != ProductFCIPyme {
		t.Fatalf("pyme -> fci-pyme, got %q", got)
	}
	if got := classifyProduct(Row{FilePath: "infrastructure.csv"}); got != ProductFCIInfrastructure {
		t.Fatalf("infrastructure -> fci-infrastructure, got %q", got)
	}
	if got := classifyProduct(Row{}); got != ProductUnknown {
		t.Fatalf("unknown, got %q", got)
	}
}

// -- collector end-to-end -----------------------------------------

func TestCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")
	dir := filepath.Join(usersBase, "alice", "Documents", "Sintesis")
	must(t, os.MkdirAll(dir, 0o755))

	cfgPath := filepath.Join(dir, "sintesis.cfg")
	must(t, os.WriteFile(cfgPath, []byte(`db_user=fci_admin
db_password=Secr3tP@ss
fci_code=200
sociedad_gerente_cuit=30-71234567-8
Server=fcidb.local;UID=fci_admin;Pwd=secret123;Database=Sintesis
`), 0o644))

	navPath := filepath.Join(dir, "valor_cuota_20260615.nav")
	must(t, os.WriteFile(navPath, []byte(`fci_code=200
valor_cuota=1234.5678
aum_usd=15000000
max_holder_pct=42
`), 0o644))

	hrPath := filepath.Join(dir, "hecho_relevante_fci200.xml")
	must(t, os.WriteFile(hrPath, []byte(`<hecho_relevante>
<fci_code>200</fci_code>
<sociedad_gerente_cuit>30-71234567-8</sociedad_gerente_cuit>
<fecha_hecho>2026-06-15</fecha_hecho>
</hecho_relevante>`), 0o644))

	// Random ignored.
	must(t, os.WriteFile(filepath.Join(dir, "random.txt"),
		[]byte(`nope`), 0o644))

	// Public skipped.
	pub := filepath.Join(usersBase, "Public", "Documents", "Sintesis")
	must(t, os.MkdirAll(pub, 0o755))
	must(t, os.WriteFile(filepath.Join(pub, "sintesis.cfg"),
		[]byte(`fci_code=999`), 0o644))

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
		t.Fatalf("want 3 (cfg+nav+hr), got %d: %+v", len(got), got)
	}

	var cfg, nav, hr Row
	for _, r := range got {
		switch r.FilePath {
		case cfgPath:
			cfg = r
		case navPath:
			nav = r
		case hrPath:
			hr = r
		}
	}

	if cfg.ArtifactKind != KindConfig {
		t.Fatalf("cfg kind=%q", cfg.ArtifactKind)
	}
	if !cfg.HasPasswordInConfig {
		t.Fatalf("cfg must flag password: %+v", cfg)
	}
	if !cfg.HasDBCredentials {
		t.Fatalf("cfg must flag DB creds: %+v", cfg)
	}
	if !cfg.IsCredentialExposureRisk {
		t.Fatalf("readable + password + DB = exposure: %+v", cfg)
	}

	if nav.ArtifactKind != KindNAVCalc {
		t.Fatalf("nav kind=%q", nav.ArtifactKind)
	}
	if !nav.HasNAVCalcData {
		t.Fatalf("nav must auto-flag: %+v", nav)
	}
	if !nav.HasHighAUM {
		t.Fatalf("nav must flag high AUM: %+v", nav)
	}
	if nav.AccountClass != AccountSociedadGerente {
		t.Fatalf("nav account=%q want sociedad-gerente", nav.AccountClass)
	}

	if hr.ArtifactKind != KindCNVHR {
		t.Fatalf("hr kind=%q", hr.ArtifactKind)
	}
	if !hr.HasCNVHRFiling {
		t.Fatalf("hr must flag: %+v", hr)
	}
	if hr.AccountClass != AccountComplianceOfficer {
		t.Fatalf("hr account=%q want compliance-officer", hr.AccountClass)
	}
}

func TestCollectorRespectsEnv(t *testing.T) {
	tmp := t.TempDir()
	envDir := filepath.Join(tmp, "custom-sintesis")
	must(t, os.MkdirAll(envDir, 0o755))
	must(t, os.WriteFile(filepath.Join(envDir, "sintesis.cfg"),
		[]byte(`fci_code=200
`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "SINTESIS_DIR" {
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
		installRoots: []string{"/nope-sintesis"},
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
		{FilePath: "a", ArtifactKind: KindNAVCalc},
		{FilePath: "a", ArtifactKind: KindConfig},
	}
	SortRows(in)
	if in[0].FilePath != "a" || in[0].ArtifactKind != KindConfig {
		t.Fatalf("first=%+v want (a,sintesis-config)", in[0])
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

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
