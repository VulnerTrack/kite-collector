package winargbcrasiscen

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindConfig), "siscen-config"},
		{string(KindCredentials), "siscen-credentials"},
		{string(KindPortalToken), "siscen-portal-token"},
		{string(KindPortalCert), "siscen-portal-cert"},
		{string(KindReport), "siscen-report"},
		{string(KindTemplate), "siscen-template"},
		{string(KindRejectionLog), "siscen-rejection-log"},
		{string(KindSourceDump), "siscen-source-dump"},
		{string(KindArchive), "siscen-archive"},
		{string(KindInstaller), "siscen-installer"},
		{string(KindOther), "other"},
		{string(KindUnknown), "unknown"},
		{string(AccountEntidadFinanciera), "entidad-financiera"},
		{string(AccountALYC), "alyc"},
		{string(AccountSociedadGerente), "sociedad-gerente"},
		{string(AccountSociedadDepositaria), "sociedad-depositaria"},
		{string(AccountAgenteCorredorCambios), "agente-corredor-cambios"},
		{string(AccountAgenteFideicomiso), "agente-fideicomiso"},
		{string(AccountDemo), "demo"},
		{string(AccountOther), "other"},
		{string(AccountUnknown), "unknown"},
		{string(ProductSovBondsTrades), "sov-bonds-trades"},
		{string(ProductCorpONTrades), "corp-on-trades"},
		{string(ProductEquityTrades), "equity-trades"},
		{string(ProductFCICuotapartesTrades), "fci-cuotapartes-trades"},
		{string(ProductRepoCaucion), "repo-caucion"},
		{string(ProductForwardOps), "forward-ops"},
		{string(ProductSwapOps), "swap-ops"},
		{string(ProductMultiProduct), "multi-product"},
		{string(ProductOther), "other"},
		{string(ProductUnknown), "unknown"},
		{string(FormA6356), "A6356"},
		{string(FormA4856), "A4856"},
		{string(FormA7724), "A7724"},
		{string(FormCompraventa), "COMPRAVENTA"},
		{string(FormOther), "other"},
		{string(FormUnknown), ""},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestIsCandidateName(t *testing.T) {
	yes := []string{
		"siscen_config.xml",
		"siscen_credentials.json",
		"A6356_20260615.txt",
		"A4856_20260615.txt",
		"COMPRAVENTA_20260615.txt",
		"compra_venta_202506.csv",
		"siscen_report_202506.txt",
		"titulos_valores_202506.txt",
		"rechazo_20260615.log",
		"rejection_log.txt",
		"portal_token.dat",
		"bcra_portal_cert.pfx",
		"bcra_template_entidad123.tpl",
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
		"siscen_config.xml":            KindConfig,
		"siscen_credentials.json":      KindCredentials,
		"siscen_api_token.json":        KindCredentials,
		"portal_token.dat":             KindPortalToken,
		"bcra_token.json":              KindPortalToken,
		"bcra_portal_cert.pfx":         KindPortalCert,
		"bcra_portal_cert.p12":         KindPortalCert,
		"siscen_portal.pem":            KindPortalCert,
		"A6356_20260615.txt":           KindReport,
		"A4856_20260615.txt":           KindReport,
		"COMPRAVENTA_20260615.txt":     KindReport,
		"compra_venta_202506.csv":      KindReport,
		"titulos_valores_202506.txt":   KindReport,
		"rechazo_20260615.log":         KindRejectionLog,
		"siscen_error_log.log":         KindRejectionLog,
		"bcra_template_entidad123.tpl": KindTemplate,
		"siscen_archive_2025.txt":      KindArchive,
		"siscen_source_dump.csv":       KindSourceDump,
		"siscen_installer.msi":         KindInstaller,
		"":                             KindUnknown,
	}
	for in, want := range cases {
		if got := ArtifactKindFromName(in); got != want {
			t.Fatalf("ArtifactKindFromName(%q)=%q want %q", in, got, want)
		}
	}
}

func TestSISCENFormFromName(t *testing.T) {
	cases := map[string]SISCENFormCode{
		"A6356_20260615.txt":       FormA6356,
		"A4856_20260615.txt":       FormA4856,
		"A7724_20260615.txt":       FormA7724,
		"COMPRAVENTA_20260615.txt": FormCompraventa,
		"compra_venta_202506.csv":  FormCompraventa,
		"random.txt":               FormUnknown,
	}
	for in, want := range cases {
		if got := SISCENFormFromName(in); got != want {
			t.Fatalf("SISCENFormFromName(%q)=%q want %q", in, got, want)
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
	if PeriodFromFilename("A6356_20260615.txt") != "202606" {
		t.Fatal("period mismatch")
	}
	if PeriodFromFilename("random.txt") != "" {
		t.Fatal("non-period must be empty")
	}
}

func TestReportingDateFromFilename(t *testing.T) {
	if got := ReportingDateFromFilename("A6356_20260615.txt"); got != "2026-06-15" {
		t.Fatalf("ReportingDateFromFilename=%q want 2026-06-15", got)
	}
	if ReportingDateFromFilename("random.txt") != "" {
		t.Fatal("non-date must be empty")
	}
}

func TestIsARSovBondStem(t *testing.T) {
	yes := []string{"AL30", "GD30", "AE38", "BONCER", "BOPREAL", "LECAP", "BONAR"}
	no := []string{"", "GGAL", "ES", "AAPL"}
	for _, v := range yes {
		if !IsARSovBondStem(v) {
			t.Fatalf("expected sov: %q", v)
		}
	}
	for _, v := range no {
		if IsARSovBondStem(v) {
			t.Fatalf("expected NOT sov: %q", v)
		}
	}
}

func TestIsBYMAEquityTicker(t *testing.T) {
	yes := []string{"GGAL", "YPFD", "PAMP", "EDN", "BMA", "ALUA"}
	no := []string{"", "AL30", "AAPL", "ES"}
	for _, v := range yes {
		if !IsBYMAEquityTicker(v) {
			t.Fatalf("expected BYMA: %q", v)
		}
	}
	for _, v := range no {
		if IsBYMAEquityTicker(v) {
			t.Fatalf("expected NOT BYMA: %q", v)
		}
	}
}

func TestIsCredentialKind(t *testing.T) {
	yes := []ArtifactKind{
		KindConfig, KindCredentials, KindPortalToken, KindPortalCert,
		KindReport, KindTemplate, KindRejectionLog, KindSourceDump, KindArchive,
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
		ArtifactKind:          KindReport,
		HasPasswordInConfig:   false,
		DistinctClientesCount: 100,
		FileMode:              0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasClienteCuitExport {
		t.Fatal("client export must flag")
	}
	if !r.HasSISCENReport {
		t.Fatal("report kind must auto-flag")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("readable + client export = exposure")
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

func TestAnnotatePortalTokenAuto(t *testing.T) {
	r := Row{ArtifactKind: KindPortalToken}
	AnnotateSecurity(&r)
	if !r.HasBCRAPortalToken {
		t.Fatal("portal-token kind must auto-flag")
	}
}

func TestAnnotateRejectionAuto(t *testing.T) {
	r := Row{ArtifactKind: KindRejectionLog, RejectionRecordCount: 3}
	AnnotateSecurity(&r)
	if !r.HasRejectionLog {
		t.Fatal("rejection kind must auto-flag")
	}
}

func TestAnnotateProductFlags(t *testing.T) {
	r := Row{
		ArtifactKind:        KindReport,
		SovBondRecordCount:  5,
		CorpONRecordCount:   3,
		EquityRecordCount:   10,
		FCIRecordCount:      2,
		RepoRecordCount:     1,
		ForwardRecordCount:  1,
		SwapRecordCount:     1,
		HighValueTradeCount: 2,
	}
	AnnotateSecurity(&r)
	for _, flag := range []bool{
		r.HasSovBonds, r.HasCorpON, r.HasBYMAEquity, r.HasFCICuotapartes,
		r.HasRepoCaucion, r.HasForwardOps, r.HasSwapOps, r.HasHighValueTrade,
	} {
		if !flag {
			t.Fatalf("missing product flag: %+v", r)
		}
	}
}

func TestParseSISCENConfig(t *testing.T) {
	body := []byte(`<SISCEN>
<bcra_username>alice@bcra.entidad123.gob.ar</bcra_username>
<bcra_password>secret123</bcra_password>
<bcra_portal_token>aBcDeFgHiJkLmNoPqRsTuVwX12345</bcra_portal_token>
<entidad_codigo>00123</entidad_codigo>
<cliente_cuit>27-11111111-4</cliente_cuit>
</SISCEN>`)
	f := ParseSISCENConfig(body)
	if !f.HasPassword {
		t.Fatal("password must flag")
	}
	if f.PortalToken == "" {
		t.Fatal("portal token must extract")
	}
	if !f.HasPortalToken {
		t.Fatal("portal token must flag")
	}
	if f.Username == "" {
		t.Fatalf("username=%q", f.Username)
	}
	if f.EntityCode != "00123" {
		t.Fatalf("entity=%q", f.EntityCode)
	}
	if f.ClienteCuitRaw == "" {
		t.Fatal("cliente cuit missing")
	}
}

func TestParseSISCENReport(t *testing.T) {
	body := []byte(`01;A6356;20260615;00123
02;CAUCION;ARARGE03E113;27-11111111-4;100000;1.05;monto_usd=2500000
02;FORWARD;ARARGE03G0V8;30-71234567-8;50000;1.10;monto_usd=550000
02;FCI;ARARGE03H1F9;20-22222222-9;1000;100;monto_usd=100000
02;OBLIGACION_NEGOCIABLE;ARGNI001;33-12345678-9;5000;100;monto_usd=500000
02;SWAP;ARARGE03I0V8;27-33333333-1;200000;1.0;monto_usd=200000
99;TRAILER;5;20260615
GGAL AL30 PAMP YPFD AE38 BONCER
`)
	f := ParseSISCENReport(body)
	if f.TradeRecordCount < 5 {
		t.Fatalf("trade rows=%d", f.TradeRecordCount)
	}
	if f.RepoRecordCount < 1 {
		t.Fatalf("repo=%d", f.RepoRecordCount)
	}
	if f.ForwardRecordCount < 1 {
		t.Fatalf("forward=%d", f.ForwardRecordCount)
	}
	if f.SwapRecordCount < 1 {
		t.Fatalf("swap=%d", f.SwapRecordCount)
	}
	if f.FCIRecordCount < 1 {
		t.Fatalf("fci=%d", f.FCIRecordCount)
	}
	if f.CorpONRecordCount < 1 {
		t.Fatalf("corp on=%d", f.CorpONRecordCount)
	}
	if f.SovBondRecordCount < 2 {
		t.Fatalf("sov=%d want >=2", f.SovBondRecordCount)
	}
	if f.EquityRecordCount < 2 {
		t.Fatalf("equity=%d want >=2", f.EquityRecordCount)
	}
	if f.DistinctClientesCount < 4 {
		t.Fatalf("clientes=%d want >=4", f.DistinctClientesCount)
	}
	if f.HighValueTradeCount < 1 {
		t.Fatalf("high value=%d", f.HighValueTradeCount)
	}
	if f.DistinctISINsCount < 4 {
		t.Fatalf("isins=%d", f.DistinctISINsCount)
	}
}

func TestParseSISCENForeignResident(t *testing.T) {
	body := []byte(`02;CAUCION;ARARGE03E113;55-22222222-9;100000;1.05;monto_usd=2500000
`)
	f := ParseSISCENReport(body)
	if !f.HasForeignResident {
		t.Fatal("55-prefix must flag foreign")
	}
}

func TestParseSISCENRejectionLog(t *testing.T) {
	body := []byte(`2026-06-15 10:00:01 ERR-001 cuit invalido en linea 5
2026-06-15 10:00:02 RECHAZO: codigo de instrumento desconocido en linea 12
2026-06-15 10:00:03 RC-1234 monto fuera de rango en linea 45
`)
	f := ParseSISCENRejectionLog(body)
	if f.RejectionRecordCount < 3 {
		t.Fatalf("rejections=%d want >=3", f.RejectionRecordCount)
	}
}

func TestParseSISCENPortalTokenRaw(t *testing.T) {
	body := []byte(`aBcDeFgHiJkLmNoPqRsTuVwX12345`)
	f := ParseSISCENPortalToken(body)
	if !f.HasPortalToken {
		t.Fatal("raw token must flag")
	}
	if f.PortalToken == "" {
		t.Fatal("token must extract")
	}
}

func TestParseSISCENEmpty(t *testing.T) {
	f := ParseSISCENConfig(nil)
	if f.HasPassword || f.PortalToken != "" {
		t.Fatalf("empty must yield zero: %+v", f)
	}
}

func TestClassifyAccount(t *testing.T) {
	if got := classifyAccount(Row{
		FilePath: "fci_report.txt", HasFCICuotapartes: true,
		FCIRecordCount: 3,
	}); got != AccountSociedadGerente {
		t.Fatalf("fci file -> sociedad-gerente, got %q", got)
	}
	if got := classifyAccount(Row{FilePath: "alyc_report.txt"}); got != AccountALYC {
		t.Fatalf("alyc name -> alyc, got %q", got)
	}
	if got := classifyAccount(Row{FilePath: "banco_report.txt"}); got != AccountEntidadFinanciera {
		t.Fatalf("banco -> entidad-financiera, got %q", got)
	}
	if got := classifyAccount(Row{HasRepoCaucion: true}); got != AccountEntidadFinanciera {
		t.Fatalf("repo -> entidad-financiera, got %q", got)
	}
	if got := classifyAccount(Row{HasSovBonds: true}); got != AccountALYC {
		t.Fatalf("sov -> alyc, got %q", got)
	}
	if got := classifyAccount(Row{}); got != AccountUnknown {
		t.Fatalf("unknown, got %q", got)
	}
}

func TestClassifyProduct(t *testing.T) {
	if got := classifyProduct(Row{HasSovBonds: true, HasCorpON: true}); got != ProductMultiProduct {
		t.Fatalf("multi -> multi-product, got %q", got)
	}
	if got := classifyProduct(Row{HasSovBonds: true}); got != ProductSovBondsTrades {
		t.Fatalf("sov -> sov-bonds-trades, got %q", got)
	}
	if got := classifyProduct(Row{HasCorpON: true}); got != ProductCorpONTrades {
		t.Fatalf("corp on -> corp-on-trades, got %q", got)
	}
	if got := classifyProduct(Row{HasBYMAEquity: true}); got != ProductEquityTrades {
		t.Fatalf("equity -> equity-trades, got %q", got)
	}
	if got := classifyProduct(Row{HasFCICuotapartes: true}); got != ProductFCICuotapartesTrades {
		t.Fatalf("fci -> fci-cuotapartes-trades, got %q", got)
	}
	if got := classifyProduct(Row{HasRepoCaucion: true}); got != ProductRepoCaucion {
		t.Fatalf("repo -> repo-caucion, got %q", got)
	}
	if got := classifyProduct(Row{HasForwardOps: true}); got != ProductForwardOps {
		t.Fatalf("forward -> forward-ops, got %q", got)
	}
	if got := classifyProduct(Row{HasSwapOps: true}); got != ProductSwapOps {
		t.Fatalf("swap -> swap-ops, got %q", got)
	}
	if got := classifyProduct(Row{}); got != ProductUnknown {
		t.Fatalf("unknown, got %q", got)
	}
}

// -- collector end-to-end -----------------------------------------

func TestCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")
	dir := filepath.Join(usersBase, "alice", "AppData", "Roaming", "BCRA", "SISCEN")
	must(t, os.MkdirAll(dir, 0o755))

	cfgPath := filepath.Join(dir, "siscen_config.xml")
	must(t, os.WriteFile(cfgPath, []byte(`<SISCEN>
<bcra_username>alice@bcra.entidad123.gob.ar</bcra_username>
<bcra_password>secret123</bcra_password>
<bcra_portal_token>aBcDeFgHiJkLmNoPqRsTuVwX12345</bcra_portal_token>
<entidad_codigo>00123</entidad_codigo>
<cliente_cuit>27-11111111-4</cliente_cuit>
</SISCEN>`), 0o644))

	rptPath := filepath.Join(dir, "A6356_20260615.txt")
	must(t, os.WriteFile(rptPath, []byte(`01;A6356;20260615;00123
02;CAUCION;ARARGE03E113;27-11111111-4;100000;1.05;monto_usd=2500000
02;OBLIGACION_NEGOCIABLE;ARGNI001;30-71234567-8;5000;100;monto_usd=500000
02;FCI;ARARGE03H1F9;33-12345678-9;1000;100;monto_usd=100000
99;TRAILER;3;20260615
GGAL AL30 PAMP YPFD
`), 0o644))

	rejPath := filepath.Join(dir, "rechazo_20260615.log")
	must(t, os.WriteFile(rejPath, []byte(`2026-06-15 10:00:01 ERR-001 cuit invalido en linea 5
2026-06-15 10:00:02 RECHAZO: codigo de instrumento desconocido en linea 12
`), 0o644))

	// Random ignored.
	must(t, os.WriteFile(filepath.Join(dir, "random.txt"),
		[]byte(`nope`), 0o644))

	// Public skipped.
	pub := filepath.Join(usersBase, "Public", "AppData", "Roaming", "BCRA", "SISCEN")
	must(t, os.MkdirAll(pub, 0o755))
	must(t, os.WriteFile(filepath.Join(pub, "siscen_config.xml"),
		[]byte(`<SISCEN/>`), 0o644))

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
		t.Fatalf("want 3 (cfg+rpt+rej), got %d: %+v", len(got), got)
	}

	var cfg, rpt, rej Row
	for _, r := range got {
		switch r.FilePath {
		case cfgPath:
			cfg = r
		case rptPath:
			rpt = r
		case rejPath:
			rej = r
		}
	}

	if cfg.ArtifactKind != KindConfig {
		t.Fatalf("cfg kind=%q", cfg.ArtifactKind)
	}
	if !cfg.HasPasswordInConfig {
		t.Fatalf("cfg must flag password: %+v", cfg)
	}
	if !cfg.HasBCRAPortalToken {
		t.Fatalf("cfg must flag portal token: %+v", cfg)
	}
	if cfg.EntityCode != "00123" {
		t.Fatalf("cfg entity=%q", cfg.EntityCode)
	}
	if !cfg.IsCredentialExposureRisk {
		t.Fatalf("readable + password + portal token = exposure: %+v", cfg)
	}

	if rpt.ArtifactKind != KindReport {
		t.Fatalf("rpt kind=%q", rpt.ArtifactKind)
	}
	if !rpt.HasSISCENReport {
		t.Fatalf("rpt must flag report: %+v", rpt)
	}
	if !rpt.HasRepoCaucion {
		t.Fatalf("rpt must flag repo: %+v", rpt)
	}
	if !rpt.HasCorpON {
		t.Fatalf("rpt must flag corp on: %+v", rpt)
	}
	if !rpt.HasFCICuotapartes {
		t.Fatalf("rpt must flag fci: %+v", rpt)
	}
	if !rpt.HasSovBonds {
		t.Fatalf("rpt must flag sov: %+v", rpt)
	}
	if !rpt.HasBYMAEquity {
		t.Fatalf("rpt must flag byma: %+v", rpt)
	}
	if rpt.ReportingDate != "2026-06-15" {
		t.Fatalf("rpt date=%q want 2026-06-15", rpt.ReportingDate)
	}
	if rpt.SISCENFormCode != FormA6356 {
		t.Fatalf("rpt form=%q want A6356", rpt.SISCENFormCode)
	}
	if rpt.ProductClass != ProductMultiProduct {
		t.Fatalf("rpt product=%q want multi-product", rpt.ProductClass)
	}

	if rej.ArtifactKind != KindRejectionLog {
		t.Fatalf("rej kind=%q", rej.ArtifactKind)
	}
	if !rej.HasRejectionLog {
		t.Fatalf("rej must flag rejection: %+v", rej)
	}
	if rej.RejectionRecordCount < 2 {
		t.Fatalf("rej count=%d want >=2", rej.RejectionRecordCount)
	}
}

func TestCollectorRespectsEnv(t *testing.T) {
	tmp := t.TempDir()
	envDir := filepath.Join(tmp, "custom-siscen")
	must(t, os.MkdirAll(envDir, 0o755))
	must(t, os.WriteFile(filepath.Join(envDir, "siscen_config.xml"),
		[]byte(`<SISCEN><entidad_codigo>00123</entidad_codigo></SISCEN>`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "BCRA_SISCEN_DIR" {
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
		installRoots: []string{"/nope-siscen"},
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
		{FilePath: "a", ArtifactKind: KindReport},
		{FilePath: "a", ArtifactKind: KindConfig},
	}
	SortRows(in)
	if in[0].FilePath != "a" || in[0].ArtifactKind != KindConfig {
		t.Fatalf("first=%+v want (a,siscen-config)", in[0])
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
