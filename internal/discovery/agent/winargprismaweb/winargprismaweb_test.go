package winargprismaweb

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindConfig), "prismaweb-config"},
		{string(KindCredentials), "prismaweb-credentials"},
		{string(KindDailySettlement), "prismaweb-daily-settlement"},
		{string(KindCollateral), "prismaweb-collateral"},
		{string(KindMarginCalls), "prismaweb-margin-calls"},
		{string(KindOptionsExercise), "prismaweb-options-exercise"},
		{string(KindFCICashflow), "prismaweb-fci-cashflow"},
		{string(KindFIXDropCopy), "prismaweb-fix-drop-copy"},
		{string(KindMemberPosition), "prismaweb-member-position"},
		{string(KindInstaller), "prismaweb-installer"},
		{string(KindOther), "other"},
		{string(KindUnknown), "unknown"},
		{string(AccountALYCClearing), "alyc-clearing"},
		{string(AccountALYCNonClearing), "alyc-non-clearing"},
		{string(AccountFCIManager), "fci-manager"},
		{string(AccountBankingCustodian), "banking-custodian"},
		{string(AccountAuditor), "auditor"},
		{string(AccountDemo), "demo"},
		{string(AccountOther), "other"},
		{string(AccountUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestIsCandidateName(t *testing.T) {
	yes := []string{
		"prismaweb_config.xml",
		"prismaweb_credentials.json",
		"daily_settle_202506.xml",
		"liquidacion_202506.xml",
		"garantias_202506.csv",
		"collateral.xml",
		"margin_call_202506.csv",
		"ejercicio_opciones_202506.xml",
		"options_exercise.xml",
		"fci_cashflow_202506.xml",
		"member_position_202506.xml",
		"drop_copy.fix",
		"dropcopy.log",
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
		"prismaweb_config.xml":          KindConfig,
		"prismaweb_credentials.json":    KindCredentials,
		"prismaweb_api_key.json":        KindCredentials,
		"daily_settle_202506.xml":       KindDailySettlement,
		"liquidacion_202506.xml":        KindDailySettlement,
		"garantias_202506.csv":          KindCollateral,
		"collateral.xml":                KindCollateral,
		"margin_call_202506.csv":        KindMarginCalls,
		"llamada_margen.csv":            KindMarginCalls,
		"ejercicio_opciones_202506.xml": KindOptionsExercise,
		"options_exercise.xml":          KindOptionsExercise,
		"fci_cashflow_202506.xml":       KindFCICashflow,
		"member_position_202506.xml":    KindMemberPosition,
		"drop_copy.fix":                 KindFIXDropCopy,
		"dropcopy.log":                  KindFIXDropCopy,
		"prismaweb_setup.msi":           KindInstaller,
		"":                              KindUnknown,
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
	if PeriodFromFilename("daily_settle_202506.xml") != "202506" {
		t.Fatal("period mismatch")
	}
	if PeriodFromFilename("random.xml") != "" {
		t.Fatal("non-period must be empty")
	}
}

func TestIsCEDEARTicker(t *testing.T) {
	yes := []string{"AAPL", "MSFT", "GOOGL", "TSLA", "VALE", "BABA"}
	no := []string{"", "GGAL", "YPFD", "AL30"}
	for _, v := range yes {
		if !IsCEDEARTicker(v) {
			t.Fatalf("expected CEDEAR: %q", v)
		}
	}
	for _, v := range no {
		if IsCEDEARTicker(v) {
			t.Fatalf("expected NOT CEDEAR: %q", v)
		}
	}
}

func TestDistinctCounterpartiesInBody(t *testing.T) {
	body := []byte(`27-11111111-4
30-71234567-8
27-11111111-4
20-99999999-1`)
	if got := DistinctCounterpartiesInBody(body); got != 3 {
		t.Fatalf("distinct=%d want 3", got)
	}
}

func TestMemberIDFromText(t *testing.T) {
	cases := map[string]string{
		`member_id: 42`:              "42",
		`matricula = 123`:            "123",
		`<member_id>987</member_id>`: "987",
		`no member here`:             "",
	}
	for in, want := range cases {
		if got := MemberIDFromText(in); got != want {
			t.Fatalf("MemberIDFromText(%q)=%q want %q", in, got, want)
		}
	}
}

func TestIsCredentialKind(t *testing.T) {
	yes := []ArtifactKind{
		KindConfig, KindCredentials, KindDailySettlement,
		KindCollateral, KindMarginCalls, KindOptionsExercise,
		KindFCICashflow, KindFIXDropCopy, KindMemberPosition,
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
		ArtifactKind:       KindDailySettlement,
		ClienteCuitPrefix:  "27",
		ClienteCuitSuffix4: "1114",
		FileMode:           0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasClienteCuit {
		t.Fatal("cliente cuit must flag")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("readable + cliente = exposure")
	}
}

func TestAnnotateLockedDown(t *testing.T) {
	r := Row{
		ArtifactKind:       KindDailySettlement,
		ClienteCuitPrefix:  "27",
		ClienteCuitSuffix4: "1114",
		FileMode:           0o600,
	}
	AnnotateSecurity(&r)
	if r.IsCredentialExposureRisk {
		t.Fatal("0o600 must NOT flag exposure")
	}
}

func TestAnnotateMarginCall(t *testing.T) {
	r := Row{
		ArtifactKind:    KindMarginCalls,
		MarginCallCount: 2,
	}
	AnnotateSecurity(&r)
	if !r.HasMarginCallEvent {
		t.Fatal("margin call count must flag")
	}
}

func TestAnnotateOptionsExercise(t *testing.T) {
	r := Row{
		ArtifactKind:         KindOptionsExercise,
		OptionsExerciseCount: 5,
	}
	AnnotateSecurity(&r)
	if !r.HasOptionsExercise {
		t.Fatal("exercise count must flag")
	}
}

func TestAnnotateT1Fail(t *testing.T) {
	r := Row{
		ArtifactKind:        KindDailySettlement,
		SettlementFailCount: 3,
	}
	AnnotateSecurity(&r)
	if !r.HasT1Fail {
		t.Fatal("fail count must flag T+1 fail")
	}
}

func TestAnnotateHighCollateral(t *testing.T) {
	r := Row{
		ArtifactKind:       KindCollateral,
		CollateralARSCents: 20_000_000_000,
	}
	AnnotateSecurity(&r)
	if !r.HasHighCollateral {
		t.Fatal("200 M ARS collateral must flag")
	}
}

func TestAnnotateCEDEARSettle(t *testing.T) {
	r := Row{
		ArtifactKind:          KindDailySettlement,
		CEDEARSettlementCount: 3,
	}
	AnnotateSecurity(&r)
	if !r.HasCEDEARSettlement {
		t.Fatal("CEDEAR count must flag")
	}
}

func TestAnnotateFCICashflow(t *testing.T) {
	r := Row{
		ArtifactKind:     KindFCICashflow,
		FCICashflowCount: 10,
	}
	AnnotateSecurity(&r)
	if !r.HasFCICashflow {
		t.Fatal("FCI cashflow count must flag")
	}
}

func TestParsePrismaWebCredentials(t *testing.T) {
	body := []byte(`<PrismaWeb>
<member_id>210</member_id>
<password>secret123</password>
<cliente_cuit>27-11111111-4</cliente_cuit>
</PrismaWeb>`)
	f := ParsePrismaWebCredentials(body)
	if !f.HasPassword {
		t.Fatal("password must flag")
	}
	if f.MemberID != "210" {
		t.Fatalf("member=%q", f.MemberID)
	}
	if f.ClienteCuitRaw == "" {
		t.Fatal("cliente cuit missing")
	}
}

func TestParsePrismaWebDailySettlement(t *testing.T) {
	body := []byte(`2026-06-15 settlement_id=1 symbol=AAPL notional=1000000.00 cliente_cuit=27-11111111-4
2026-06-15 settlement_id=2 symbol=MSFT notional=500000.00
2026-06-15 settlement_id=3 symbol=GGAL notional=300000.00 settlement_fail=true
`)
	f := ParsePrismaWebDailySettlement(body)
	if f.SettlementCount < 3 {
		t.Fatalf("settle=%d", f.SettlementCount)
	}
	if f.SettlementFailCount < 1 {
		t.Fatalf("fails=%d", f.SettlementFailCount)
	}
	if f.CEDEARSettlementCount < 2 {
		t.Fatalf("cedear=%d", f.CEDEARSettlementCount)
	}
	if f.TotalVolumeCents < 180_000_000 {
		t.Fatalf("volume=%d", f.TotalVolumeCents)
	}
	if f.ClienteCuitRaw == "" {
		t.Fatal("cliente cuit missing")
	}
}

func TestParsePrismaWebCollateral(t *testing.T) {
	body := []byte(`{"garantias": 15000000000.00, "member_id": "210"}`)
	f := ParsePrismaWebCollateral(body)
	if f.CollateralCents != 1_500_000_000_000 {
		t.Fatalf("collateral=%d want 1.5 T cents", f.CollateralCents)
	}
}

func TestParsePrismaWebMarginCalls(t *testing.T) {
	body := []byte(`2026-06-15 margin_call cp=30-71234567-8 amount=50000000.00
2026-06-15 llamada_margen cp=30-99999999-1 amount=30000000.00
`)
	f := ParsePrismaWebMarginCalls(body)
	if f.MarginCallCount < 2 {
		t.Fatalf("margin=%d", f.MarginCallCount)
	}
	if f.TotalVolumeCents < 8_000_000_000 {
		t.Fatalf("volume=%d", f.TotalVolumeCents)
	}
}

func TestParsePrismaWebOptionsExercise(t *testing.T) {
	body := []byte(`2026-06-15 ejercicio_opcion symbol=GFGC1500JU exercise=call notional=10000.00
2026-06-15 options_exercise symbol=YPFC2500JU exercise=put notional=5000.00
2026-06-15 ejercicio_opcion symbol=PAMC1000JU exercise=call notional=3000.00
`)
	f := ParsePrismaWebOptionsExercise(body)
	if f.OptionsExerciseCount < 3 {
		t.Fatalf("exercise=%d", f.OptionsExerciseCount)
	}
	if f.TotalVolumeCents < 1_800_000 {
		t.Fatalf("volume=%d", f.TotalVolumeCents)
	}
}

func TestParsePrismaWebFCICashflow(t *testing.T) {
	body := []byte(`2026-06-15 fci_cashflow type=suscripcion_fci fci_id=BALANZ_AHORRO notional=1000000.00 cp=30-71234567-8
2026-06-15 fci_flujo type=rescate_fci fci_id=ALLARIA_RV notional=500000.00 cp=30-99999999-1
`)
	f := ParsePrismaWebFCICashflow(body)
	if f.FCICashflowCount < 2 {
		t.Fatalf("fci=%d", f.FCICashflowCount)
	}
	if f.DistinctCounterparties < 2 {
		t.Fatalf("distinct=%d", f.DistinctCounterparties)
	}
}

func TestParsePrismaWebFIXDropCopy(t *testing.T) {
	body := []byte(`2026-06-15 09:30:01 8=FIX.4.4|9=120|35=AE|49=PRISMAWEB|56=ADCAP|10010=DROP|55=AAPL
2026-06-15 09:30:02 8=FIX.4.4|9=80|35=8|49=PRISMAWEB|56=ADCAP|TradeCaptureReport|55=MSFT settle_fail=true
`)
	f := ParsePrismaWebFIXDropCopy(body)
	if !f.HasFIXDropCopy {
		t.Fatal("drop copy must flag")
	}
	if f.FIXSenderCompID == "" {
		t.Fatal("sender")
	}
	if f.FIXTargetCompID == "" {
		t.Fatal("target")
	}
	if f.SettlementFailCount < 1 {
		t.Fatalf("fails=%d", f.SettlementFailCount)
	}
	if f.CEDEARSettlementCount < 2 {
		t.Fatalf("cedear=%d", f.CEDEARSettlementCount)
	}
}

func TestParsePrismaWebEmpty(t *testing.T) {
	f := ParsePrismaWebCredentials(nil)
	if f.HasPassword || f.MemberID != "" {
		t.Fatalf("empty must yield zero: %+v", f)
	}
}

// -- collector end-to-end -----------------------------------------

func TestCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")
	dir := filepath.Join(usersBase, "alice", "AppData", "Roaming", "PrismaWeb")
	must(t, os.MkdirAll(filepath.Join(dir, "books"), 0o755))

	cfgPath := filepath.Join(dir, "prismaweb_config.xml")
	must(t, os.WriteFile(cfgPath, []byte(`<PrismaWeb>
<member_id>210</member_id>
<password>secret123</password>
<cliente_cuit>27-11111111-4</cliente_cuit>
</PrismaWeb>`), 0o644))

	settlePath := filepath.Join(dir, "books", "daily_settle_202506.xml")
	must(t, os.WriteFile(settlePath, []byte(`2026-06-15 settlement_id=1 symbol=AAPL notional=1000000.00 cliente_cuit=27-11111111-4
2026-06-15 settlement_id=2 symbol=MSFT notional=500000.00 settlement_fail=true
`), 0o644))

	garantPath := filepath.Join(dir, "books", "garantias_202506.csv")
	must(t, os.WriteFile(garantPath, []byte(`{"garantias":15000000000.00,"member_id":"210"}`), 0o644))

	marginPath := filepath.Join(dir, "books", "margin_call_202506.csv")
	must(t, os.WriteFile(marginPath, []byte(`2026-06-15 margin_call cp=30-71234567-8 amount=50000000.00
`), 0o644))

	exerPath := filepath.Join(dir, "books", "ejercicio_opciones_202506.xml")
	must(t, os.WriteFile(exerPath, []byte(`2026-06-15 ejercicio_opcion symbol=GFGC1500JU
2026-06-15 ejercicio_opcion symbol=YPFC2500JU
`), 0o644))

	// Random ignored.
	must(t, os.WriteFile(filepath.Join(dir, "random.txt"),
		[]byte(`nope`), 0o644))

	// Public skipped.
	pub := filepath.Join(usersBase, "Public", "AppData", "Roaming", "PrismaWeb")
	must(t, os.MkdirAll(pub, 0o755))
	must(t, os.WriteFile(filepath.Join(pub, "prismaweb_config.xml"),
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
	if len(got) != 5 {
		t.Fatalf("want 5 (cfg+settle+garant+margin+exer), got %d: %+v", len(got), got)
	}

	var cfg, settle, garant, margin, exer Row
	for _, r := range got {
		switch r.FilePath {
		case cfgPath:
			cfg = r
		case settlePath:
			settle = r
		case garantPath:
			garant = r
		case marginPath:
			margin = r
		case exerPath:
			exer = r
		}
	}

	if cfg.ArtifactKind != KindConfig {
		t.Fatalf("cfg kind=%q", cfg.ArtifactKind)
	}
	if !cfg.HasPasswordInConfig {
		t.Fatalf("cfg must flag password: %+v", cfg)
	}
	if cfg.MemberID != "210" {
		t.Fatalf("cfg member=%q", cfg.MemberID)
	}
	if !cfg.IsCredentialExposureRisk {
		t.Fatalf("readable + password + cuit = exposure: %+v", cfg)
	}

	if settle.ArtifactKind != KindDailySettlement {
		t.Fatalf("settle kind=%q", settle.ArtifactKind)
	}
	if !settle.HasT1Fail {
		t.Fatalf("settle must flag T+1 fail: %+v", settle)
	}
	if !settle.HasCEDEARSettlement {
		t.Fatalf("settle must flag CEDEAR: %+v", settle)
	}

	if garant.ArtifactKind != KindCollateral {
		t.Fatalf("garant kind=%q", garant.ArtifactKind)
	}
	if !garant.HasHighCollateral {
		t.Fatalf("150 G cents must flag high collateral: %d", garant.CollateralARSCents)
	}

	if margin.ArtifactKind != KindMarginCalls {
		t.Fatalf("margin kind=%q", margin.ArtifactKind)
	}
	if !margin.HasMarginCallEvent {
		t.Fatalf("margin must flag: %+v", margin)
	}

	if exer.ArtifactKind != KindOptionsExercise {
		t.Fatalf("exer kind=%q", exer.ArtifactKind)
	}
	if !exer.HasOptionsExercise {
		t.Fatalf("exer must flag: %+v", exer)
	}
}

func TestCollectorRespectsEnv(t *testing.T) {
	tmp := t.TempDir()
	envDir := filepath.Join(tmp, "custom-prismaweb")
	must(t, os.MkdirAll(envDir, 0o755))
	must(t, os.WriteFile(filepath.Join(envDir, "prismaweb_config.xml"),
		[]byte(`<PrismaWeb><member_id>42</member_id></PrismaWeb>`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "PRISMAWEB_DIR" {
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
		installRoots: []string{"/nope-prismaweb"},
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
		{FilePath: "a", ArtifactKind: KindDailySettlement},
		{FilePath: "a", ArtifactKind: KindConfig},
	}
	SortRows(in)
	if in[0].FilePath != "a" || in[0].ArtifactKind != KindConfig {
		t.Fatalf("first=%+v", in[0])
	}
}

func TestHashContents(t *testing.T) {
	a := HashContents([]byte("abc"))
	b := HashContents([]byte("abc"))
	if a != b {
		t.Fatal("hash drift")
	}
	if len(a) != 64 {
		t.Fatalf("hash len=%d", len(a))
	}
}

func TestClassifyAccount(t *testing.T) {
	if classifyAccount(KindFIXDropCopy, PrismaWebFields{HasFIXDropCopy: true}) != AccountALYCClearing {
		t.Fatal("drop-copy -> clearing")
	}
	if classifyAccount(KindFCICashflow, PrismaWebFields{FCICashflowCount: 5}) != AccountFCIManager {
		t.Fatal("fci -> fci-manager")
	}
	if classifyAccount(KindCollateral, PrismaWebFields{CollateralCents: 1000}) != AccountALYCClearing {
		t.Fatal("collateral -> clearing")
	}
	if classifyAccount(KindDailySettlement, PrismaWebFields{SettlementCount: 1}) != AccountALYCNonClearing {
		t.Fatal("settle -> non-clearing")
	}
	if classifyAccount(KindConfig, PrismaWebFields{}) != AccountUnknown {
		t.Fatal("unknown")
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
