package winargmatbarofex

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindSettlementDaily), "settlement-daily"},
		{string(KindPositionReport), "position-report"},
		{string(KindContractSpec), "contract-spec"},
		{string(KindMarginRequirement), "margin-requirement"},
		{string(KindTradeConfirmation), "trade-confirmation"},
		{string(KindOptionsGreeks), "options-greeks"},
		{string(KindOther), "other"},
		{string(KindUnknown), "unknown"},
		{string(CommTrigo), "trigo"},
		{string(CommSoja), "soja"},
		{string(CommMaiz), "maiz"},
		{string(CommGirasol), "girasol"},
		{string(CommSorgo), "sorgo"},
		{string(CommCebada), "cebada"},
		{string(CommDLR), "dlr"},
		{string(CommDOM), "dom"},
		{string(CommROS20), "ros20"},
		{string(CommOro), "oro"},
		{string(CommOther), "other"},
		{string(CommUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestIsCandidateName(t *testing.T) {
	yes := []string{
		"MATBA_settlement_20240615.csv",
		"posiciones_alyc338_202506.xml",
		"contratos_trigo_202506.json",
		"garantia_cuenta12345.xml",
		"futuros_soja_jul2024.con",
		"derivados_dlr_202506.csv",
		"trigo_settlement.csv",
		"rofex_position.xml",
	}
	no := []string{"", "factura.pdf", "cv.docx"}
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
		"MATBA_settlement_20240615.csv": KindSettlementDaily,
		"posiciones_alyc338_202506.xml": KindPositionReport,
		"contratos_trigo_202506.json":   KindContractSpec,
		"futuros_soja.con":              KindContractSpec,
		"garantia_cuenta12345.xml":      KindMarginRequirement,
		"margen_intimacion.xml":         KindMarginRequirement,
		"trade_confirm_001.xml":         KindTradeConfirmation,
		"opciones_greeks_2024.csv":      KindOptionsGreeks,
		"matba_general_2024.csv":        KindOther,
		"random.csv":                    KindUnknown,
		"":                              KindUnknown,
	}
	for in, want := range cases {
		if got := ArtifactKindFromName(in); got != want {
			t.Fatalf("ArtifactKindFromName(%q)=%q want %q", in, got, want)
		}
	}
}

func TestCommodityFromText(t *testing.T) {
	cases := map[string]Commodity{
		"trigo_settlement.csv":  CommTrigo,
		"WK24_settlement.csv":   CommTrigo,
		"soja_202506.csv":       CommSoja,
		"SJN24_data.csv":        CommSoja,
		"maiz_2024.csv":         CommMaiz,
		"MZA24_pos.csv":         CommMaiz,
		"girasol_2024.csv":      CommGirasol,
		"GIR24_2024.csv":        CommGirasol,
		"sorgo_2024.csv":        CommSorgo,
		"cebada_2024.csv":       CommCebada,
		"dlr_202506.csv":        CommDLR,
		"dolar_futuro_2024.csv": CommDLR,
		"dom_202506.csv":        CommDOM,
		"ros20_index.csv":       CommROS20,
		"oro_settlement.csv":    CommOro,
		"random.csv":            CommOther,
		"":                      CommUnknown,
	}
	for in, want := range cases {
		if got := CommodityFromText(in); got != want {
			t.Fatalf("CommodityFromText(%q)=%q want %q", in, got, want)
		}
	}
}

func TestIsForeignCurrencyCommodity(t *testing.T) {
	yes := []Commodity{CommDLR, CommDOM}
	no := []Commodity{CommTrigo, CommSoja, CommMaiz, CommROS20, CommOro, CommUnknown}
	for _, v := range yes {
		if !IsForeignCurrencyCommodity(v) {
			t.Fatalf("expected forex: %q", v)
		}
	}
	for _, v := range no {
		if IsForeignCurrencyCommodity(v) {
			t.Fatalf("expected NOT forex: %q", v)
		}
	}
}

func TestCuitFingerprint(t *testing.T) {
	cases := []struct {
		in, pfx, sfx4 string
	}{
		{"cuenta_30712345678.xml", "30", "5678"},
		{"30-71234567-8", "30", "5678"},
		{"no-cuit", "", ""},
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
		"matricula CNV 338": "338",
		"matrícula: 338":    "338",
		"alyc 338":          "",
		"":                  "",
	}
	for in, want := range cases {
		if got := MatriculaFromText(in); got != want {
			t.Fatalf("MatriculaFromText(%q)=%q want %q", in, got, want)
		}
	}
}

func TestContractMonthFromText(t *testing.T) {
	cases := map[string]string{
		"posiciones_07-2024.xml": "07-2024",
		"settlement_2024-07.csv": "07-2024",
		"no-month.xml":           "",
	}
	for in, want := range cases {
		if got := ContractMonthFromText(in); got != want {
			t.Fatalf("ContractMonthFromText(%q)=%q want %q", in, got, want)
		}
	}
}

func TestIsSpeculativePosition(t *testing.T) {
	if !IsSpeculativePosition(CommTrigo, 100) {
		t.Fatal("100 trigo contracts > 50 threshold = speculative")
	}
	if IsSpeculativePosition(CommTrigo, 30) {
		t.Fatal("30 trigo contracts < 50 threshold = NOT speculative")
	}
	if !IsSpeculativePosition(CommDLR, 1000) {
		t.Fatal("1000 DLR contracts > 500 threshold = speculative")
	}
	if IsSpeculativePosition(CommDLR, 100) {
		t.Fatal("100 DLR contracts < 500 threshold = NOT speculative")
	}
	if IsSpeculativePosition(CommUnknown, 1_000_000) {
		t.Fatal("unknown commodity must NOT classify")
	}
}

// -- AnnotateSecurity ----------------------------------------------

func TestAnnotateSpeculativeExposure(t *testing.T) {
	r := Row{
		ArtifactKind:          KindPositionReport,
		Commodity:             CommSoja,
		OpenPositionContracts: 100,
		AccountCuitPrefix:     "30",
		AccountCuitSuffix4:    "5678",
		FileMode:              0o644,
	}
	AnnotateSecurity(&r)
	if !r.IsSpeculativeSize {
		t.Fatal("100 soja contracts > 40 = speculative")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("account CUIT + readable = exposure")
	}
}

func TestAnnotateForeignCurrencyDLR(t *testing.T) {
	r := Row{Commodity: CommDLR, FileMode: 0o600}
	AnnotateSecurity(&r)
	if !r.HasForeignCurrencyNotional {
		t.Fatal("DLR must flag forex notional")
	}
}

func TestAnnotateHedgePositionClean(t *testing.T) {
	r := Row{
		ArtifactKind:          KindPositionReport,
		Commodity:             CommTrigo,
		OpenPositionContracts: 20,
		FileMode:              0o600,
	}
	AnnotateSecurity(&r)
	if r.IsSpeculativeSize {
		t.Fatal("20 trigo contracts < 50 = hedge, NOT speculative")
	}
	if r.IsCredentialExposureRisk {
		t.Fatal("no CUIT in row = no exposure")
	}
}

// -- ParseMatbaArtifact --------------------------------------------

func TestParseMatbaArtifactXML(t *testing.T) {
	body := []byte(`<?xml version="1.0"?>
<position_report>
  <matricula>338</matricula>
  <cuit_broker>30712345678</cuit_broker>
  <cuit_cuenta>27111111114</cuit_cuenta>
  <open_contracts>100</open_contracts>
  <notional_usd>1500000.00</notional_usd>
  <margin_call>true</margin_call>
  <contract_month>07-2024</contract_month>
</position_report>`)
	f, ok := ParseMatbaArtifact(body)
	if !ok {
		t.Fatal("must parse")
	}
	if f.OpenContracts != 100 {
		t.Fatalf("contracts=%d", f.OpenContracts)
	}
	if f.BrokerMatricula != "338" {
		t.Fatalf("matricula=%q", f.BrokerMatricula)
	}
	if !f.HasMarginCall {
		t.Fatal("margin_call=true must flag")
	}
	if f.ContractMonth != "07-2024" {
		t.Fatalf("contract month=%q", f.ContractMonth)
	}
}

func TestParseMatbaArtifactCSVMarginCall(t *testing.T) {
	body := []byte(`# Posicion report
matricula: 338
contratos: 75
Llamada de margen detectada
`)
	f, ok := ParseMatbaArtifact(body)
	if !ok {
		t.Fatal("must parse")
	}
	if f.BrokerMatricula != "338" {
		t.Fatalf("matricula=%q", f.BrokerMatricula)
	}
	if f.OpenContracts != 75 {
		t.Fatalf("contracts=%d", f.OpenContracts)
	}
	if !f.HasMarginCall {
		t.Fatal("narrative margin call must flag")
	}
}

func TestParseMatbaArtifactEmpty(t *testing.T) {
	if _, ok := ParseMatbaArtifact([]byte("")); ok {
		t.Fatal("empty must NOT parse")
	}
}

// -- collector end-to-end -----------------------------------------

func TestCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")
	dir := filepath.Join(usersBase, "alice", "Documents", "MATBA-Rofex")
	must(t, os.MkdirAll(dir, 0o755))

	// Soja position 100 contracts (speculative), CUIT in file, world-readable.
	posPath := filepath.Join(dir, "posiciones_soja_27111111114_202506.xml")
	must(t, os.WriteFile(posPath, []byte(`<position_report>
<matricula>338</matricula>
<cuit_cuenta>27111111114</cuit_cuenta>
<open_contracts>100</open_contracts>
<contract_month>07-2024</contract_month>
</position_report>`), 0o644))

	// DLR position locked-down.
	dlrPath := filepath.Join(dir, "posiciones_dlr_202506.xml")
	must(t, os.WriteFile(dlrPath, []byte(`<position_report>
<matricula>338</matricula>
<open_contracts>100</open_contracts>
</position_report>`), 0o600))

	// Settlement CSV (no position info).
	setPath := filepath.Join(dir, "MATBA_settlement_20240615.csv")
	must(t, os.WriteFile(setPath, []byte("specie,price\nWK24,250.5\nSJN24,400.0\n"), 0o644))

	// Random — ignored.
	must(t, os.WriteFile(filepath.Join(dir, "random.csv"),
		[]byte("a,b\n"), 0o644))

	// Public — skipped.
	pub := filepath.Join(usersBase, "Public", "Documents", "MATBA-Rofex")
	must(t, os.MkdirAll(pub, 0o755))
	must(t, os.WriteFile(filepath.Join(pub, "matba_skip.csv"),
		[]byte("a,b\n"), 0o644))

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
	if len(got) != 3 {
		t.Fatalf("want 3 (pos+dlr+set), got %d: %+v", len(got), got)
	}

	var pos, dlr, set Row
	for _, r := range got {
		switch r.FilePath {
		case posPath:
			pos = r
		case dlrPath:
			dlr = r
		case setPath:
			set = r
		}
	}
	if pos.Commodity != CommSoja {
		t.Fatalf("pos commodity=%q", pos.Commodity)
	}
	if !pos.IsSpeculativeSize {
		t.Fatalf("100 soja must be speculative: %+v", pos)
	}
	if !pos.IsCredentialExposureRisk {
		t.Fatalf("pos + cuit + readable = exposure: %+v", pos)
	}
	if pos.BrokerMatricula != "338" {
		t.Fatalf("pos matricula=%q", pos.BrokerMatricula)
	}

	if dlr.Commodity != CommDLR {
		t.Fatalf("dlr commodity=%q", dlr.Commodity)
	}
	if !dlr.HasForeignCurrencyNotional {
		t.Fatalf("dlr must flag forex: %+v", dlr)
	}
	if dlr.IsCredentialExposureRisk {
		t.Fatalf("0o600 must NOT flag: %+v", dlr)
	}
	// 100 DLR contracts < 500 threshold = hedge size.
	if dlr.IsSpeculativeSize {
		t.Fatalf("100 DLR = hedge, NOT speculative: %+v", dlr)
	}

	if set.ArtifactKind != KindSettlementDaily {
		t.Fatalf("set kind=%q", set.ArtifactKind)
	}
}

func TestCollectorRespectsEnv(t *testing.T) {
	tmp := t.TempDir()
	envDir := filepath.Join(tmp, "custom-matba")
	must(t, os.MkdirAll(envDir, 0o755))
	must(t, os.WriteFile(filepath.Join(envDir, "MATBA_settlement_20240615.csv"),
		[]byte("a,b\n"), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "MATBA_DIR" {
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
	if len(got) != 1 || got[0].ArtifactKind != KindSettlementDaily {
		t.Fatalf("env: %+v", got)
	}
}

func TestCollectorMissingPathsOK(t *testing.T) {
	c := &fileCollector{
		installRoots: []string{"/nope-matba"},
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
		{FilePath: "z", Commodity: CommSoja, ContractMonth: "07-2024"},
		{FilePath: "a", Commodity: CommTrigo, ContractMonth: "07-2024"},
		{FilePath: "a", Commodity: CommSoja, ContractMonth: "01-2024"},
	}
	SortRows(in)
	if in[0].FilePath != "a" || in[0].Commodity != CommSoja {
		t.Fatalf("first=%+v", in[0])
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
