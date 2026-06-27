package winargmercap

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindLiquidacionCV), "mercap-liquidacion-cv"},
		{string(KindConciliacionCVSA), "mercap-conciliacion-cvsa"},
		{string(KindSaldoCliente), "mercap-saldo-cliente"},
		{string(KindContabilidadCNV), "mercap-contabilidad-cnv"},
		{string(KindRegimenInformativo), "mercap-regimen-informativo"},
		{string(KindCobrosPagos), "mercap-cobros-pagos"},
		{string(KindComisiones), "mercap-comisiones"},
		{string(KindKYCCliente), "mercap-kyc-cliente"},
		{string(KindCertificado), "mercap-certificado"},
		{string(KindConfig), "mercap-config"},
		{string(KindInstaller), "mercap-installer"},
		{string(KindOther), "other"},
		{string(KindUnknown), "unknown"},
		{string(ModuleGestionClientes), "gestion-clientes"},
		{string(ModuleContabilidad), "contabilidad"},
		{string(ModuleLiquidacion), "liquidacion"},
		{string(ModuleTesoreria), "tesoreria"},
		{string(ModuleRegulatoryCNV), "regulatory-cnv"},
		{string(ModuleRegulatoryUIF), "regulatory-uif"},
		{string(ModuleRegulatoryAFIP), "regulatory-afip"},
		{string(ModuleBackOffice), "back-office"},
		{string(ModuleOther), "other"},
		{string(ModuleUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestIsCandidateName(t *testing.T) {
	yes := []string{
		"liquidacion_cv_20260615.csv",
		"conciliacion_cvsa_20260615.xml",
		"saldo_diario_20260615.csv",
		"saldo_cliente_27111111114.csv",
		"contabilidad_cnv_202506.xml",
		"regimen_informativo_202506.csv",
		"cobros_pagos_20260615.csv",
		"comisiones_20260615.csv",
		"kyc_cliente_27111111114.xml",
		"certificado_op_001.pdf",
		"mercap.ini",
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
		"liquidacion_cv_20260615.csv":    KindLiquidacionCV,
		"conciliacion_cvsa_20260615.xml": KindConciliacionCVSA,
		"saldo_diario_20260615.csv":      KindSaldoCliente,
		"saldo_cliente_27111111114.csv":  KindSaldoCliente,
		"contabilidad_cnv_202506.xml":    KindContabilidadCNV,
		"regimen_informativo_202506.csv": KindRegimenInformativo,
		"cobros_pagos_20260615.csv":      KindCobrosPagos,
		"comisiones_20260615.csv":        KindComisiones,
		"kyc_cliente_27111111114.xml":    KindKYCCliente,
		"certificado_op_001.pdf":         KindCertificado,
		"mercap.ini":                     KindConfig,
		"mercap_v8_installer.msi":        KindInstaller,
		"":                               KindUnknown,
	}
	for in, want := range cases {
		if got := ArtifactKindFromName(in); got != want {
			t.Fatalf("ArtifactKindFromName(%q)=%q want %q", in, got, want)
		}
	}
}

func TestModuleFromKind(t *testing.T) {
	cases := map[ArtifactKind]Module{
		KindLiquidacionCV:      ModuleLiquidacion,
		KindConciliacionCVSA:   ModuleLiquidacion,
		KindComisiones:         ModuleLiquidacion,
		KindCertificado:        ModuleLiquidacion,
		KindSaldoCliente:       ModuleTesoreria,
		KindCobrosPagos:        ModuleTesoreria,
		KindContabilidadCNV:    ModuleContabilidad,
		KindRegimenInformativo: ModuleRegulatoryCNV,
		KindKYCCliente:         ModuleGestionClientes,
		KindConfig:             ModuleBackOffice,
		KindInstaller:          ModuleOther,
		KindUnknown:            ModuleOther,
	}
	for in, want := range cases {
		if got := ModuleFromKind(in); got != want {
			t.Fatalf("ModuleFromKind(%q)=%q want %q", in, got, want)
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
		"broker_matricula 1234": "1234",
		"alyc_matricula 88":     "88",
		"no matricula":          "",
		"":                      "",
	}
	for in, want := range cases {
		if got := MatriculaFromText(in); got != want {
			t.Fatalf("MatriculaFromText(%q)=%q want %q", in, got, want)
		}
	}
}

func TestCuentaSuffix4(t *testing.T) {
	cases := map[string]string{
		"comitente 12345":  "2345",
		"comitente N°7777": "7777",
		"cuenta: 9999":     "9999",
		"no comitente":     "",
	}
	for in, want := range cases {
		if got := CuentaSuffix4(in); got != want {
			t.Fatalf("CuentaSuffix4(%q)=%q want %q", in, got, want)
		}
	}
}

func TestPeriodFromFilename(t *testing.T) {
	if PeriodFromFilename("liquidacion_cv_202506.csv") != "202506" {
		t.Fatal("period mismatch")
	}
	if PeriodFromFilename("random.csv") != "" {
		t.Fatal("non-period must be empty")
	}
}

func TestIsHighSensitivityKind(t *testing.T) {
	yes := []ArtifactKind{
		KindSaldoCliente, KindCobrosPagos, KindKYCCliente,
		KindLiquidacionCV, KindConciliacionCVSA,
		KindComisiones, KindContabilidadCNV,
	}
	no := []ArtifactKind{
		KindRegimenInformativo, KindCertificado, KindConfig,
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

func TestIsKYCOverdue(t *testing.T) {
	now := time.Date(2026, 6, 24, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		date string
		want bool
	}{
		{"2025-06-25", false},
		{"2024-12-01", true},  // > 365d
		{"2026-06-01", false}, // recent
		{"", false},
		{"garbage", false},
	}
	for _, c := range cases {
		if got := IsKYCOverdue(c.date, now); got != c.want {
			t.Fatalf("IsKYCOverdue(%q)=%v want %v", c.date, got, c.want)
		}
	}
}

// -- AnnotateSecurity ---------------------------------------------

func TestAnnotateNegativeBalance(t *testing.T) {
	r := Row{
		ArtifactKind:         KindSaldoCliente,
		SaldoClienteARSCents: -10_000_000,
		ClienteCuitPrefix:    "27",
		ClienteCuitSuffix4:   "1114",
		FileMode:             0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasNegativeClienteBalance {
		t.Fatal("negative saldo must flag")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatalf("readable + cliente + saldo = exposure: %+v", r)
	}
}

func TestAnnotateUnreconciledCVSA(t *testing.T) {
	r := Row{
		ArtifactKind:            KindConciliacionCVSA,
		ReconciliationDiffCents: 50_000,
		FileMode:                0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasUnreconciledCVSA {
		t.Fatal("diff > 0 must flag")
	}
}

func TestAnnotateOverdueSettlement(t *testing.T) {
	r := Row{
		ArtifactKind:      KindLiquidacionCV,
		MaxSettlementDays: 5,
		FileMode:          0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasOverdueSettlement {
		t.Fatal("T+5 must flag overdue")
	}
}

func TestAnnotateCommissionAnomaly(t *testing.T) {
	r := Row{
		ArtifactKind:     KindComisiones,
		CommissionPctMax: 8,
		FileMode:         0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasCommissionAnomaly {
		t.Fatal("8% commission must flag")
	}
}

func TestAnnotateLockedDownClean(t *testing.T) {
	r := Row{
		ArtifactKind:         KindSaldoCliente,
		SaldoClienteARSCents: -10_000_000,
		ClienteCuitPrefix:    "27",
		ClienteCuitSuffix4:   "1114",
		FileMode:             0o600,
	}
	AnnotateSecurity(&r)
	if r.IsCredentialExposureRisk {
		t.Fatal("0o600 must NOT flag exposure")
	}
}

// -- ParseMercapArtifact ------------------------------------------

func TestParseMercapArtifactSaldo(t *testing.T) {
	body := []byte(`<?xml version="1.0"?>
<saldo>
  <matricula>338</matricula>
  <cliente_cuit>27-11111111-4</cliente_cuit>
  <cuenta_comitente>12345</cuenta_comitente>
  <saldo_cliente>-1500000.00</saldo_cliente>
</saldo>`)
	f := ParseMercapArtifact(body)
	if f.BrokerMatricula != "338" {
		t.Fatalf("matricula=%q", f.BrokerMatricula)
	}
	if f.SaldoCents != -150_000_000 {
		t.Fatalf("saldo=%d want -150_000_000", f.SaldoCents)
	}
	if f.CuentaComitenteID != "12345" {
		t.Fatalf("cuenta=%q", f.CuentaComitenteID)
	}
}

func TestParseMercapArtifactSettlement(t *testing.T) {
	body := []byte(`Liquidación CV:
operacion_id=1 T+2 importe=1000000.00 comision_pct=0.50
operacion_id=2 T+5 importe=2000000.00 comision_pct=1.00
`)
	f := ParseMercapArtifact(body)
	if f.MaxSettlementDays != 5 {
		t.Fatalf("max settle=%d", f.MaxSettlementDays)
	}
}

func TestParseMercapArtifactCommission(t *testing.T) {
	body := []byte(`{
  "commission_pct": "8.5%"
}`)
	f := ParseMercapArtifact(body)
	if f.CommissionPctMax < 8 {
		t.Fatalf("commission pct=%d want >=8", f.CommissionPctMax)
	}
}

func TestParseMercapArtifactReconciliation(t *testing.T) {
	body := []byte(`{
  "matricula": "338",
  "diferencia_cvsa": "-50000.00"
}`)
	f := ParseMercapArtifact(body)
	if f.ReconciliationDiffCents != -5_000_000 {
		t.Fatalf("recon diff=%d want -5_000_000", f.ReconciliationDiffCents)
	}
}

func TestParseMercapArtifactKYC(t *testing.T) {
	body := []byte(`{
  "matricula": "338",
  "cliente_cuit": "27-11111111-4",
  "kyc_last_review_date": "2024-12-01"
}`)
	f := ParseMercapArtifact(body)
	if f.KYCLastReviewDate != "2024-12-01" {
		t.Fatalf("kyc=%q", f.KYCLastReviewDate)
	}
}

func TestParseMercapArtifactEmpty(t *testing.T) {
	f := ParseMercapArtifact(nil)
	if f.SaldoCents != 0 || f.BrokerMatricula != "" {
		t.Fatalf("empty must yield zero: %+v", f)
	}
}

// -- collector end-to-end -----------------------------------------

func TestCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")
	dir := filepath.Join(usersBase, "alice", "Documents", "Mercap")
	must(t, os.MkdirAll(dir, 0o755))

	// Saldo cliente with negative balance + cliente CUIT, readable.
	saldoPath := filepath.Join(dir, "saldo_diario_20260615.csv")
	must(t, os.WriteFile(saldoPath, []byte(`matricula,cliente_cuit,saldo_cliente
338,27-11111111-4,-1500000.00
`), 0o644))

	// Liquidación CV with overdue settlement, locked down.
	liqPath := filepath.Join(dir, "liquidacion_cv_20260615.csv")
	must(t, os.WriteFile(liqPath, []byte(`Liquidación CV:
operacion_id=1 T+2 importe=1000000.00
operacion_id=2 T+5 importe=2000000.00
`), 0o600))

	// Comisiones with anomaly.
	comPath := filepath.Join(dir, "comisiones_20260615.csv")
	must(t, os.WriteFile(comPath, []byte(`operacion_id,comision_pct
1,0.5
2,8.5
`), 0o644))

	// CVSA reconciliation with diff.
	conPath := filepath.Join(dir, "conciliacion_cvsa_20260615.xml")
	must(t, os.WriteFile(conPath, []byte(`<?xml version="1.0"?>
<conciliacion>
  <matricula>338</matricula>
  <diferencia_cvsa>-50000.00</diferencia_cvsa>
</conciliacion>`), 0o644))

	// KYC overdue.
	kycPath := filepath.Join(dir, "kyc_cliente_27111111114.xml")
	must(t, os.WriteFile(kycPath, []byte(`<?xml version="1.0"?>
<kyc>
  <matricula>338</matricula>
  <cliente_cuit>27-11111111-4</cliente_cuit>
  <kyc_last_review_date>2024-12-01</kyc_last_review_date>
</kyc>`), 0o644))

	// Random ignored.
	must(t, os.WriteFile(filepath.Join(dir, "random.txt"),
		[]byte(`nope`), 0o644))

	// Public skipped.
	pub := filepath.Join(usersBase, "Public", "Documents", "Mercap")
	must(t, os.MkdirAll(pub, 0o755))
	must(t, os.WriteFile(filepath.Join(pub, "saldo_skip.csv"),
		[]byte(`x`), 0o644))

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
	if len(got) != 5 {
		t.Fatalf("want 5 (saldo+liq+com+con+kyc), got %d: %+v", len(got), got)
	}

	var saldo, liq, com, con, kyc Row
	for _, r := range got {
		switch r.FilePath {
		case saldoPath:
			saldo = r
		case liqPath:
			liq = r
		case comPath:
			com = r
		case conPath:
			con = r
		case kycPath:
			kyc = r
		}
	}

	if saldo.ArtifactKind != KindSaldoCliente {
		t.Fatalf("saldo kind=%q", saldo.ArtifactKind)
	}
	if !saldo.HasNegativeClienteBalance {
		t.Fatalf("saldo must flag negative: %+v", saldo)
	}
	if !saldo.HasClienteCuit {
		t.Fatalf("saldo must flag cliente: %+v", saldo)
	}
	if !saldo.IsCredentialExposureRisk {
		t.Fatalf("readable + cliente + saldo = exposure: %+v", saldo)
	}

	if liq.ArtifactKind != KindLiquidacionCV {
		t.Fatalf("liq kind=%q", liq.ArtifactKind)
	}
	if !liq.HasOverdueSettlement {
		t.Fatalf("liq T+5 must flag overdue: %+v", liq)
	}
	if liq.IsCredentialExposureRisk {
		t.Fatalf("0o600 must NOT flag: %+v", liq)
	}

	if com.ArtifactKind != KindComisiones {
		t.Fatalf("com kind=%q", com.ArtifactKind)
	}
	if !com.HasCommissionAnomaly {
		t.Fatalf("com 8.5%% must flag: %+v", com)
	}

	if con.ArtifactKind != KindConciliacionCVSA {
		t.Fatalf("con kind=%q", con.ArtifactKind)
	}
	if !con.HasUnreconciledCVSA {
		t.Fatalf("con must flag mismatch: %+v", con)
	}

	if kyc.ArtifactKind != KindKYCCliente {
		t.Fatalf("kyc kind=%q", kyc.ArtifactKind)
	}
	if !kyc.HasKYCOverdue {
		t.Fatalf("kyc 2024-12-01 must flag overdue: %+v", kyc)
	}
}

func TestCollectorRespectsEnv(t *testing.T) {
	tmp := t.TempDir()
	envDir := filepath.Join(tmp, "custom-mercap")
	must(t, os.MkdirAll(envDir, 0o755))
	must(t, os.WriteFile(filepath.Join(envDir, "saldo_diario_20260615.csv"),
		[]byte(`x,y,z`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "MERCAP_DIR" {
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
	if len(got) != 1 || got[0].ArtifactKind != KindSaldoCliente {
		t.Fatalf("env: %+v", got)
	}
}

func TestCollectorMissingPathsOK(t *testing.T) {
	c := &fileCollector{
		installRoots: []string{"/nope-mercap"},
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
		{FilePath: "z", ArtifactKind: KindSaldoCliente},
		{FilePath: "a", ArtifactKind: KindLiquidacionCV},
		{FilePath: "a", ArtifactKind: KindSaldoCliente},
	}
	SortRows(in)
	if in[0].FilePath != "a" || in[0].ArtifactKind != KindLiquidacionCV {
		t.Fatalf("first=%+v", in[0])
	}
}

func TestHashContents(t *testing.T) {
	a := HashContents([]byte("mercap"))
	b := HashContents([]byte("mercap"))
	c := HashContents([]byte("MERCAP"))
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
