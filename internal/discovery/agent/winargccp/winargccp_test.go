package winargccp

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindMarginCollateral), "ccp-margin-collateral"},
		{string(KindMarginCall), "ccp-margin-call"},
		{string(KindDailySettlement), "ccp-daily-settlement"},
		{string(KindHaircutTable), "ccp-haircut-table"},
		{string(KindClearingMemberBalance), "ccp-clearing-member-balance"},
		{string(KindDefaultFund), "ccp-default-fund"},
		{string(KindHaircutFactor), "ccp-haircut-factor"},
		{string(KindStressTest), "ccp-stress-test"},
		{string(KindInstaller), "ccp-installer"},
		{string(KindOther), "other"},
		{string(KindUnknown), "unknown"},
		{string(CCPArgentinaClearing), "argentina-clearing"},
		{string(CCPBYMACCA), "byma-cca"},
		{string(CCPCajaValoresGarantias), "caja-valores-garantias"},
		{string(CCPMAEClear), "maeclear"},
		{string(CCPOther), "other"},
		{string(CCPUnknown), "unknown"},
		{string(AssetFuturesFinancial), "futures-financial"},
		{string(AssetFuturesAgro), "futures-agro"},
		{string(AssetEquityRV), "equity-rv"},
		{string(AssetBondsRF), "bonds-rf"},
		{string(AssetCaucionRepo), "caucion-repo"},
		{string(AssetOptions), "options"},
		{string(AssetOther), "other"},
		{string(AssetUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestIsCandidateName(t *testing.T) {
	yes := []string{
		"garantias_iniciales_20260615.xml",
		"llamada_margen_20260615.csv",
		"liquidacion_diaria_20260615.xml",
		"aforos_20260615.csv",
		"haircut_dlr_20260615.json",
		"saldo_compensador_20260615.xml",
		"fondo_garantia_compensacion_20260615.xml",
		"factor_riesgo_soja_20260615.json",
		"stress_test_20260615.xml",
		"acyc_dump.xml",
		"byma_cca_balance.xml",
		"maeclear_settlement_20260615.xml",
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
		"garantias_iniciales_20260615.xml": KindMarginCollateral,
		"llamada_margen_20260615.csv":      KindMarginCall,
		"margin_call_20260615.csv":         KindMarginCall,
		"liquidacion_diaria_20260615.xml":  KindDailySettlement,
		"daily_settlement_20260615.xml":    KindDailySettlement,
		"maeclear_settlement_20260615.xml": KindDailySettlement,
		"aforos_20260615.csv":              KindHaircutTable,
		"haircut_table_20260615.csv":       KindHaircutTable,
		"haircut_factor_dlr_20260615.json": KindHaircutFactor,
		"factor_riesgo_soja_20260615.json": KindHaircutFactor,
		"saldo_compensador_20260615.xml":   KindClearingMemberBalance,
		"compensador_balance_20260615.xml": KindClearingMemberBalance,
		"fondo_garantia_compensacion.xml":  KindDefaultFund,
		"default_fund_20260615.xml":        KindDefaultFund,
		"stress_test_20260615.xml":         KindStressTest,
		"acyc_v1_installer.msi":            KindInstaller,
		"":                                 KindUnknown,
	}
	for in, want := range cases {
		if got := ArtifactKindFromName(in); got != want {
			t.Fatalf("ArtifactKindFromName(%q)=%q want %q", in, got, want)
		}
	}
}

func TestCCPEntityFromPath(t *testing.T) {
	cases := map[string]CCPEntity{
		`C:\ArgentinaClearing\garantias.xml`:  CCPArgentinaClearing,
		`C:\ACyC\liquidacion.xml`:             CCPArgentinaClearing,
		`/home/alice/acyc_dump.xml`:           CCPArgentinaClearing,
		`C:\BYMA\CCA\balance.xml`:             CCPBYMACCA,
		`/home/alice/byma_cca_settlement.xml`: CCPBYMACCA,
		`C:\CVSA\Garantias\margin.xml`:        CCPCajaValoresGarantias,
		`C:\MAEClear\settlement.xml`:          CCPMAEClear,
		`/opt/clearing/balance.xml`:           CCPOther,
		`C:\Random\file.txt`:                  CCPUnknown,
		"":                                    CCPUnknown,
	}
	for in, want := range cases {
		if got := CCPEntityFromPath(in); got != want {
			t.Fatalf("CCPEntityFromPath(%q)=%q want %q", in, got, want)
		}
	}
}

func TestAssetClassFromBody(t *testing.T) {
	cases := map[string]AssetClass{
		`{"asset":"DLR","futures_financial":true}`: AssetFuturesFinancial,
		`{"asset":"soja","futures_agro":true}`:     AssetFuturesAgro,
		`{"asset":"GGAL","equity":true}`:           AssetEquityRV,
		`{"asset":"AL30","renta_fija":true}`:       AssetBondsRF,
		`{"asset":"caucion","repo":true}`:          AssetCaucionRepo,
		`{"asset":"options","opciones":true}`:      AssetOptions,
		`{"asset":"random"}`:                       AssetUnknown,
		``:                                         AssetUnknown,
	}
	for in, want := range cases {
		if got := AssetClassFromBody([]byte(in)); got != want {
			t.Fatalf("AssetClassFromBody(%q)=%q want %q", in, got, want)
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
		"matricula 338":       "338",
		"clearing_member 999": "999",
		"compensador 88":      "88",
		"no matricula":        "",
		"":                    "",
	}
	for in, want := range cases {
		if got := MatriculaFromText(in); got != want {
			t.Fatalf("MatriculaFromText(%q)=%q want %q", in, got, want)
		}
	}
}

func TestPeriodFromFilename(t *testing.T) {
	if PeriodFromFilename("garantias_iniciales_202506.xml") != "202506" {
		t.Fatal("period mismatch")
	}
	if PeriodFromFilename("random.xml") != "" {
		t.Fatal("non-period must be empty")
	}
}

func TestSettlementDateFromFilename(t *testing.T) {
	if SettlementDateFromFilename("liquidacion_diaria_20260615.xml") != "2026-06-15" {
		t.Fatal("settlement date mismatch")
	}
	if SettlementDateFromFilename("random.xml") != "" {
		t.Fatal("non-date must be empty")
	}
}

func TestIsSettlementKind(t *testing.T) {
	yes := []ArtifactKind{
		KindMarginCollateral, KindMarginCall,
		KindDailySettlement, KindClearingMemberBalance,
		KindDefaultFund,
	}
	no := []ArtifactKind{
		KindHaircutTable, KindHaircutFactor, KindStressTest,
		KindInstaller, KindOther, KindUnknown,
	}
	for _, k := range yes {
		if !IsSettlementKind(k) {
			t.Fatalf("expected settlement kind: %q", k)
		}
	}
	for _, k := range no {
		if IsSettlementKind(k) {
			t.Fatalf("expected NOT settlement kind: %q", k)
		}
	}
}

// -- AnnotateSecurity ---------------------------------------------

func TestAnnotateMarginCallActive(t *testing.T) {
	r := Row{
		ArtifactKind:       KindMarginCall,
		MarginCallARSCents: 50_000_000, // 500k ARS
		ClienteCuitPrefix:  "27",
		ClienteCuitSuffix4: "1114",
		FileMode:           0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasMarginCallActive {
		t.Fatal("margin call > 0 must flag")
	}
	if !r.HasClienteCuit {
		t.Fatal("cliente cuit must flag")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatalf("readable + cliente + margin = exposure: %+v", r)
	}
}

func TestAnnotateCollateralShortfall(t *testing.T) {
	r := Row{
		ArtifactKind:           KindMarginCollateral,
		MarginRequiredARSCents: 100_000_000,
		MarginPostedARSCents:   50_000_000,
		FileMode:               0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasCollateralShortfall {
		t.Fatal("posted < required must flag shortfall")
	}
}

func TestAnnotateHighHaircut(t *testing.T) {
	r := Row{
		ArtifactKind:  KindHaircutTable,
		MaxHaircutPct: 75,
		FileMode:      0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasHighHaircut {
		t.Fatal("75% haircut must flag")
	}
}

func TestAnnotateNegativeBalance(t *testing.T) {
	r := Row{
		ArtifactKind:            KindClearingMemberBalance,
		CompensadorBalanceCents: -10_000_000,
		FileMode:                0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasNegativeBalance {
		t.Fatal("negative balance must flag")
	}
}

func TestAnnotateLockedDownClean(t *testing.T) {
	r := Row{
		ArtifactKind:       KindMarginCall,
		MarginCallARSCents: 50_000_000,
		ClienteCuitPrefix:  "27",
		FileMode:           0o600,
	}
	AnnotateSecurity(&r)
	if r.IsCredentialExposureRisk {
		t.Fatal("0o600 must NOT flag exposure")
	}
}

// -- ParseCCPArtifact ---------------------------------------------

func TestParseCCPArtifactXML(t *testing.T) {
	body := []byte(`<?xml version="1.0"?>
<ccp_margin>
  <matricula>338</matricula>
  <cliente_cuit>27-11111111-4</cliente_cuit>
  <margin_required>10000000.00</margin_required>
  <margin_posted>8000000.00</margin_posted>
  <margin_call>2000000.00</margin_call>
  <compensador_balance>-500000.00</compensador_balance>
  <default_fund>1500000.00</default_fund>
  <stress_test_var>3000000.00</stress_test_var>
  <settlement_date>2026-06-15</settlement_date>
  <haircut>0.65</haircut>
</ccp_margin>`)
	f := ParseCCPArtifact(body)
	if f.ClearingMemberMatricula != "338" {
		t.Fatalf("matricula=%q", f.ClearingMemberMatricula)
	}
	if f.ClienteCuitRaw == "" {
		t.Fatal("cliente cuit missing")
	}
	if f.MarginRequiredCents != 1_000_000_000 {
		t.Fatalf("margin req=%d", f.MarginRequiredCents)
	}
	if f.MarginPostedCents != 800_000_000 {
		t.Fatalf("margin posted=%d", f.MarginPostedCents)
	}
	if f.MarginCallCents != 200_000_000 {
		t.Fatalf("margin call=%d", f.MarginCallCents)
	}
	if !f.HasMarginCallActive {
		t.Fatal("margin call must flag active")
	}
	if f.CompensadorBalanceCents != -50_000_000 {
		t.Fatalf("compensador=%d want -50_000_000", f.CompensadorBalanceCents)
	}
	if f.DefaultFundContributionCents != 150_000_000 {
		t.Fatalf("default fund=%d", f.DefaultFundContributionCents)
	}
	if f.SettlementDate != "2026-06-15" {
		t.Fatalf("settlement date=%q", f.SettlementDate)
	}
	if f.MaxHaircutPct != 65 {
		t.Fatalf("haircut=%d want 65", f.MaxHaircutPct)
	}
}

func TestParseCCPArtifactStressBreach(t *testing.T) {
	body := []byte(`{
  "stress_test_var": "5000000.00",
  "result": "stress breach detected",
  "extra_contribution": true
}`)
	f := ParseCCPArtifact(body)
	if !f.HasStressBreach {
		t.Fatal("stress breach marker must flag")
	}
}

func TestParseCCPArtifactDefaultFundCall(t *testing.T) {
	body := []byte(`default_fund_call: requested
extra_contribution: yes
amount: 1000000.00
`)
	f := ParseCCPArtifact(body)
	if !f.HasDefaultFundCall {
		t.Fatal("default fund call must flag")
	}
}

func TestParseCCPArtifactEmpty(t *testing.T) {
	f := ParseCCPArtifact(nil)
	if f.MarginRequiredCents != 0 || f.MarginPostedCents != 0 {
		t.Fatalf("empty must be zero: %+v", f)
	}
}

// -- collector end-to-end -----------------------------------------

func TestCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")
	dir := filepath.Join(usersBase, "alice", "Documents", "ArgentinaClearing")
	must(t, os.MkdirAll(dir, 0o755))

	// Margin call with active call + cliente CUIT, readable.
	callPath := filepath.Join(dir, "llamada_margen_20260615.xml")
	must(t, os.WriteFile(callPath, []byte(`<?xml version="1.0"?>
<ccp_margin_call>
  <matricula>338</matricula>
  <cliente_cuit>27-11111111-4</cliente_cuit>
  <margin_call>2000000.00</margin_call>
  <settlement_date>2026-06-15</settlement_date>
  <asset>DLR futures financial</asset>
</ccp_margin_call>`), 0o644))

	// Collateral shortfall.
	collPath := filepath.Join(dir, "garantias_iniciales_20260615.xml")
	must(t, os.WriteFile(collPath, []byte(`<?xml version="1.0"?>
<ccp_collateral>
  <matricula>338</matricula>
  <margin_required>10000000.00</margin_required>
  <margin_posted>5000000.00</margin_posted>
</ccp_collateral>`), 0o600))

	// Haircut table with high haircut.
	hairPath := filepath.Join(dir, "aforos_20260615.csv")
	must(t, os.WriteFile(hairPath, []byte(`asset,haircut
GGAL,30
AL30,75
soja,40
`), 0o644))

	// Negative compensador balance.
	balPath := filepath.Join(dir, "saldo_compensador_20260615.xml")
	must(t, os.WriteFile(balPath, []byte(`<?xml version="1.0"?>
<ccp_balance>
  <matricula>338</matricula>
  <compensador_balance>-500000.00</compensador_balance>
</ccp_balance>`), 0o644))

	// Random ignored.
	must(t, os.WriteFile(filepath.Join(dir, "random.txt"),
		[]byte(`nope`), 0o644))

	// Public skipped.
	pub := filepath.Join(usersBase, "Public", "Documents", "ArgentinaClearing")
	must(t, os.MkdirAll(pub, 0o755))
	must(t, os.WriteFile(filepath.Join(pub, "llamada_margen.xml"),
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
		t.Fatalf("want 4 (call+coll+hair+bal), got %d: %+v", len(got), got)
	}

	var call, coll, hair, bal Row
	for _, r := range got {
		switch r.FilePath {
		case callPath:
			call = r
		case collPath:
			coll = r
		case hairPath:
			hair = r
		case balPath:
			bal = r
		}
	}

	if call.ArtifactKind != KindMarginCall {
		t.Fatalf("call kind=%q", call.ArtifactKind)
	}
	if call.CCPEntity != CCPArgentinaClearing {
		t.Fatalf("call entity=%q", call.CCPEntity)
	}
	if !call.HasMarginCallActive {
		t.Fatalf("call must flag active: %+v", call)
	}
	if call.MarginCallARSCents != 200_000_000 {
		t.Fatalf("call amount=%d", call.MarginCallARSCents)
	}
	if call.ClienteCuitPrefix != "27" {
		t.Fatalf("call cliente=%q", call.ClienteCuitPrefix)
	}
	if !call.IsCredentialExposureRisk {
		t.Fatalf("readable + cliente + margin = exposure: %+v", call)
	}
	if call.SettlementDate != "2026-06-15" {
		t.Fatalf("call date=%q", call.SettlementDate)
	}
	if call.AssetClass != AssetFuturesFinancial {
		t.Fatalf("call asset class=%q", call.AssetClass)
	}

	if coll.ArtifactKind != KindMarginCollateral {
		t.Fatalf("coll kind=%q", coll.ArtifactKind)
	}
	if !coll.HasCollateralShortfall {
		t.Fatalf("coll must flag shortfall: %+v", coll)
	}
	if coll.IsCredentialExposureRisk {
		t.Fatalf("0o600 must NOT flag: %+v", coll)
	}

	if hair.ArtifactKind != KindHaircutTable {
		t.Fatalf("hair kind=%q", hair.ArtifactKind)
	}
	if !hair.HasHighHaircut {
		t.Fatalf("75%% must flag high haircut: %+v", hair)
	}

	if bal.ArtifactKind != KindClearingMemberBalance {
		t.Fatalf("bal kind=%q", bal.ArtifactKind)
	}
	if !bal.HasNegativeBalance {
		t.Fatalf("negative must flag: %+v", bal)
	}
}

func TestCollectorRespectsEnv(t *testing.T) {
	tmp := t.TempDir()
	envDir := filepath.Join(tmp, "custom-ccp")
	must(t, os.MkdirAll(envDir, 0o755))
	must(t, os.WriteFile(filepath.Join(envDir, "llamada_margen_20260615.xml"),
		[]byte(`<ccp><margin_call>500000.00</margin_call></ccp>`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "CCP_DIR" {
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
	if len(got) != 1 || got[0].ArtifactKind != KindMarginCall {
		t.Fatalf("env: %+v", got)
	}
}

func TestCollectorMissingPathsOK(t *testing.T) {
	c := &fileCollector{
		installRoots: []string{"/nope-ccp"},
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
		{FilePath: "z", ArtifactKind: KindMarginCall},
		{FilePath: "a", ArtifactKind: KindMarginCollateral},
		{FilePath: "a", ArtifactKind: KindMarginCall},
	}
	SortRows(in)
	if in[0].FilePath != "a" || in[0].ArtifactKind != KindMarginCall {
		t.Fatalf("first=%+v", in[0])
	}
}

func TestHashContents(t *testing.T) {
	a := HashContents([]byte("ccp"))
	b := HashContents([]byte("ccp"))
	c := HashContents([]byte("CCP"))
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
