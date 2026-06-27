package winargkdb

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindConfig), "kdb-config"},
		{string(KindCredentials), "kdb-credentials"},
		{string(KindQScript), "kdb-q-script"},
		{string(KindKScript), "kdb-k-script"},
		{string(KindLicense), "kdb-license"},
		{string(KindHDBColumn), "kdb-hdb-column"},
		{string(KindHDBMeta), "kdb-hdb-meta"},
		{string(KindTplog), "kdb-tplog"},
		{string(KindQRCStartup), "kdb-qrc-startup"},
		{string(KindSubscriberConfig), "kdb-subscriber-config"},
		{string(KindInstaller), "kdb-installer"},
		{string(KindOther), "other"},
		{string(KindUnknown), "unknown"},
		{string(AccountHFT), "hft"},
		{string(AccountPropTrader), "prop-trader"},
		{string(AccountQuantResearch), "quant-research"},
		{string(AccountInstitutional), "institutional"},
		{string(AccountMarketMaker), "market-maker"},
		{string(AccountAPI), "api"},
		{string(AccountDemo), "demo"},
		{string(AccountOther), "other"},
		{string(AccountUnknown), "unknown"},
		{string(ProductMATbaRofex), "matba-rofex"},
		{string(ProductCMEFutures), "cme-futures"},
		{string(ProductUSEquity), "us-equity"},
		{string(ProductCrypto), "crypto"},
		{string(ProductMultiVenue), "multi-venue"},
		{string(ProductOptions), "options"},
		{string(ProductHFTExecution), "hft-execution"},
		{string(ProductOther), "other"},
		{string(ProductUnknown), "unknown"},
		{string(LicenseCommercial), "commercial"},
		{string(LicensePersonalEdition), "personal-edition"},
		{string(LicenseEvaluation), "evaluation"},
		{string(LicenseNone), "none"},
		{string(LicenseUnknown), "unknown"},
		{string(RoleFeedHandler), "feed-handler"},
		{string(RoleTickerplant), "tickerplant"},
		{string(RoleRDB), "rdb"},
		{string(RoleHDB), "hdb"},
		{string(RoleGateway), "gateway"},
		{string(RoleClient), "client"},
		{string(RoleMultiRole), "multi-role"},
		{string(RoleUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestIsCandidateName(t *testing.T) {
	yes := []string{
		"feed_handler.q",
		"tickerplant.q",
		"q.k",
		".qrc",
		"k4.lic",
		"kc.lic",
		"sym",
		"par.txt",
		"tplog_2026.06.15.log",
		"kdb_config.json",
		"hdb_root.cfg",
		"trades.dat",
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
		"kdb_config.json":      KindConfig,
		"kdb_credentials.json": KindCredentials,
		"kdb_api_token.json":   KindCredentials,
		"feed_handler.q":       KindQScript,
		"my_strategy.q":        KindQScript,
		"old_lib.k":            KindKScript,
		"k4.lic":               KindLicense,
		"kc.lic":               KindLicense,
		"trades.dat":           KindHDBColumn,
		"sym":                  KindHDBMeta,
		"par.txt":              KindHDBMeta,
		"q.k":                  KindHDBMeta,
		"tplog_2026.06.15.log": KindTplog,
		"tickerplant.q":        KindQScript,
		"subscriber.cfg":       KindSubscriberConfig,
		"feed_handler.cfg":     KindSubscriberConfig,
		".qrc":                 KindQRCStartup,
		"my_init.qrc":          KindQRCStartup,
		"kdb_installer.msi":    KindInstaller,
		"":                     KindUnknown,
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
	if PeriodFromFilename("tplog_202606.log") != "202606" {
		t.Fatal("period mismatch")
	}
	if PeriodFromFilename("random.log") != "" {
		t.Fatal("non-period must be empty")
	}
}

func TestIsMATbaRofexSymbol(t *testing.T) {
	yes := []string{"DLR", "MTR-USD", "SOJ", "MERV"}
	no := []string{"", "ES", "AAPL"}
	for _, v := range yes {
		if !IsMATbaRofexSymbol(v) {
			t.Fatalf("expected MATba: %q", v)
		}
	}
	for _, v := range no {
		if IsMATbaRofexSymbol(v) {
			t.Fatalf("expected NOT MATba: %q", v)
		}
	}
}

func TestIsCMEFuturesSymbol(t *testing.T) {
	yes := []string{"ES", "NQ", "CL", "GC", "BTC"}
	no := []string{"", "DLR", "AAPL"}
	for _, v := range yes {
		if !IsCMEFuturesSymbol(v) {
			t.Fatalf("expected CME: %q", v)
		}
	}
	for _, v := range no {
		if IsCMEFuturesSymbol(v) {
			t.Fatalf("expected NOT CME: %q", v)
		}
	}
}

func TestIsUSEquityStem(t *testing.T) {
	yes := []string{"AAPL", "MSFT", "SPY"}
	no := []string{"", "DLR", "ES"}
	for _, v := range yes {
		if !IsUSEquityStem(v) {
			t.Fatalf("expected US: %q", v)
		}
	}
	for _, v := range no {
		if IsUSEquityStem(v) {
			t.Fatalf("expected NOT US: %q", v)
		}
	}
}

func TestIsCryptoSymbol(t *testing.T) {
	yes := []string{"BTC", "ETH", "USDT/ARS", "USDT-ARS", "USDC", "USDT"}
	no := []string{"", "AAPL", "DLR", "ES"}
	for _, v := range yes {
		if !IsCryptoSymbol(v) {
			t.Fatalf("expected crypto: %q", v)
		}
	}
	for _, v := range no {
		if IsCryptoSymbol(v) {
			t.Fatalf("expected NOT crypto: %q", v)
		}
	}
}

func TestIsCredentialKind(t *testing.T) {
	yes := []ArtifactKind{
		KindConfig, KindCredentials, KindQScript, KindKScript,
		KindLicense, KindHDBMeta, KindTplog,
		KindQRCStartup, KindSubscriberConfig,
	}
	no := []ArtifactKind{KindHDBColumn, KindInstaller, KindOther, KindUnknown}
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
		ArtifactKind:        KindQScript,
		HasPasswordInConfig: true,
		ClienteCuitPrefix:   "27",
		ClienteCuitSuffix4:  "1114",
		FileMode:            0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasClienteCuit {
		t.Fatal("cliente cuit must flag")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("readable + password + cliente = exposure")
	}
}

func TestAnnotateLockedDown(t *testing.T) {
	r := Row{
		ArtifactKind:        KindQScript,
		HasPasswordInConfig: true,
		FileMode:            0o600,
	}
	AnnotateSecurity(&r)
	if r.IsCredentialExposureRisk {
		t.Fatal("0o600 must NOT flag exposure")
	}
}

func TestAnnotateLicenseAuto(t *testing.T) {
	r := Row{ArtifactKind: KindLicense}
	AnnotateSecurity(&r)
	if !r.HasKXLicense {
		t.Fatal("license kind must auto-flag")
	}
}

func TestAnnotateQScriptAuto(t *testing.T) {
	r := Row{ArtifactKind: KindQScript}
	AnnotateSecurity(&r)
	if !r.HasQScript {
		t.Fatal("q kind must auto-flag")
	}
	if !r.HasHFTPattern {
		t.Fatal("KDB+ Q presence must flag HFT pattern")
	}
}

func TestAnnotateTickDBAuto(t *testing.T) {
	r := Row{ArtifactKind: KindTplog}
	AnnotateSecurity(&r)
	if !r.HasTickDB {
		t.Fatal("tplog kind must auto-flag tick DB")
	}
}

func TestAnnotateLargeHDB(t *testing.T) {
	r := Row{
		ArtifactKind: KindHDBColumn,
		FileSize:     LargeHDBBytes + 1,
	}
	AnnotateSecurity(&r)
	if !r.HasTickDB {
		t.Fatal("HDB column must flag tick DB")
	}
	if !r.HasLargeHDB {
		t.Fatal("> 10 GiB HDB column must flag large")
	}
}

func TestAnnotateSubscriberAuto(t *testing.T) {
	r := Row{ArtifactKind: KindSubscriberConfig}
	AnnotateSecurity(&r)
	if !r.HasSubscriberConfig {
		t.Fatal("subscriber-config kind must auto-flag")
	}
}

func TestAnnotateCrossVenueArb(t *testing.T) {
	r := Row{
		ArtifactKind:       KindQScript,
		HasMATbaRofexTable: true,
		HasCMEFuturesTable: true,
	}
	AnnotateSecurity(&r)
	if !r.HasCrossVenueArb {
		t.Fatal("MATba + CME must flag cross-venue arb")
	}
}

func TestAnnotateQRCAutoload(t *testing.T) {
	r := Row{ArtifactKind: KindQRCStartup, AutoloadChainDepth: 3}
	AnnotateSecurity(&r)
	if !r.HasQRCAutoload {
		t.Fatal("autoload chain > 0 must flag")
	}
}

func TestParseKDBQScript(t *testing.T) {
	body := []byte("// Tickerplant feed handler\n" +
		"\\l tickerplant.q\n" +
		"trades:([]ts:`timestamp$();sym:`symbol$();price:`float$();size:`long$())\n" +
		"depth:([]ts:`timestamp$();sym:`symbol$();bid:`float$();ask:`float$())\n" +
		".u.sub:{`trades`depth!()};\n" +
		".z.ps:{[x] 0N!x;}\n" +
		"upd:{[t;x] t insert x};\n" +
		"sym:`DLR`MTR-USD`ES`NQ`AAPL`BTC/ARS;\n" +
		"kdb_password=\"secret123\"\n" +
		"api_key=\"aBcDeFgHiJkLmNoPqRsTuVwX12345\"\n")
	f := ParseKDBQScript(body)
	if !f.HasSubscriberConfig {
		t.Fatal("subscriber must flag")
	}
	if f.RPCHandlerCount < 1 {
		t.Fatalf("rpc=%d want >=1", f.RPCHandlerCount)
	}
	if !f.HasPassword {
		t.Fatal("password must flag")
	}
	if f.APIKey == "" {
		t.Fatal("api key must extract")
	}
	if !f.HasMATbaRofexTable {
		t.Fatal("MATba must flag")
	}
	if !f.HasCMEFuturesTable {
		t.Fatal("CME must flag")
	}
	if !f.HasUSEquityTable {
		t.Fatal("US equity must flag")
	}
	if !f.HasCryptoData {
		t.Fatal("crypto must flag")
	}
	if f.DistinctTablesCount < 2 {
		t.Fatalf("tables=%d", f.DistinctTablesCount)
	}
}

func TestParseKDBQRCStartup(t *testing.T) {
	body := []byte(`\l q.k
\l feed_handler.q
\l tickerplant.q
\l rdb.q
\l hdb.q
`)
	f := ParseKDBQRCStartup(body)
	if f.AutoloadChainDepth < 5 {
		t.Fatalf("autoload depth=%d want >=5", f.AutoloadChainDepth)
	}
}

func TestParseKDBLicenseCommercial(t *testing.T) {
	body := []byte(`KX Systems kdb+ license
k4.lic
expir_date=2027-12-31
seat_count=20
cpu_count=8
`)
	f := ParseKDBLicense(body)
	if f.LicenseClass != LicenseCommercial {
		t.Fatalf("license=%q want commercial", f.LicenseClass)
	}
}

func TestParseKDBLicensePersonal(t *testing.T) {
	body := []byte(`kdb+ Personal Edition license
non-commercial
32_bit_edition
`)
	f := ParseKDBLicense(body)
	if f.LicenseClass != LicensePersonalEdition {
		t.Fatalf("license=%q want personal", f.LicenseClass)
	}
}

func TestParseKDBLicenseEval(t *testing.T) {
	body := []byte(`kdb+ Evaluation
KX Systems
trial: 30-day
`)
	f := ParseKDBLicense(body)
	if f.LicenseClass != LicenseEvaluation {
		t.Fatalf("license=%q want evaluation", f.LicenseClass)
	}
}

func TestParseKDBTplog(t *testing.T) {
	body := []byte("upd[`trades; (.z.t; `DLR; 850.5; 100)]\n" +
		"upd[`trades; (.z.t; `ES; 5400.25; 1)]\n" +
		"upd[`depth; (.z.t; `MTR-USD; 1200.0; 100)]\n" +
		"upd[`trades; (.z.t; `AAPL; 200.5; 50)]\n")
	f := ParseKDBTplog(body)
	if f.TplogRecordCount < 4 {
		t.Fatalf("tplog records=%d want >=4", f.TplogRecordCount)
	}
	if !f.HasMATbaRofexTable {
		t.Fatal("MATba must flag")
	}
	if !f.HasCMEFuturesTable {
		t.Fatal("CME must flag")
	}
}

func TestParseKDBEmpty(t *testing.T) {
	f := ParseKDBQScript(nil)
	if f.HasPassword || f.APIKey != "" {
		t.Fatalf("empty must yield zero: %+v", f)
	}
}

func TestDetectNodeRole(t *testing.T) {
	tp := []byte(`\l tickerplant.q
.u.tick:{[s] ...}
`)
	if got := detectNodeRole(tp); got != RoleTickerplant {
		t.Fatalf("tickerplant detect=%q", got)
	}
	rdb := []byte(`// real_time database
RDB feed
`)
	if got := detectNodeRole(rdb); got != RoleRDB {
		t.Fatalf("rdb detect=%q", got)
	}
	gw := []byte(`gateway dispatch
.gw.route:{[]; ...}
`)
	if got := detectNodeRole(gw); got != RoleGateway {
		t.Fatalf("gateway detect=%q", got)
	}
	multi := []byte(`tickerplant + RDB combined
.u.tick
HDB roll
`)
	if got := detectNodeRole(multi); got != RoleMultiRole {
		t.Fatalf("multi detect=%q", got)
	}
	none := []byte(`generic q code`)
	if got := detectNodeRole(none); got != RoleUnknown {
		t.Fatalf("none detect=%q", got)
	}
}

func TestClassifyProduct(t *testing.T) {
	if got := classifyProduct(Row{
		HasMATbaRofexTable: true,
		HasCMEFuturesTable: true,
	}); got != ProductMultiVenue {
		t.Fatalf("matba+cme -> multi-venue, got %q", got)
	}
	if got := classifyProduct(Row{HasMATbaRofexTable: true}); got != ProductMATbaRofex {
		t.Fatalf("matba -> matba-rofex, got %q", got)
	}
	if got := classifyProduct(Row{HasCMEFuturesTable: true}); got != ProductCMEFutures {
		t.Fatalf("cme -> cme-futures, got %q", got)
	}
	if got := classifyProduct(Row{HasUSEquityTable: true}); got != ProductUSEquity {
		t.Fatalf("us -> us-equity, got %q", got)
	}
	if got := classifyProduct(Row{HasCryptoData: true}); got != ProductCrypto {
		t.Fatalf("crypto -> crypto, got %q", got)
	}
	if got := classifyProduct(Row{HasKXLicense: true}); got != ProductHFTExecution {
		t.Fatalf("license -> hft-execution, got %q", got)
	}
	if got := classifyProduct(Row{}); got != ProductUnknown {
		t.Fatalf("unknown, got %q", got)
	}
}

func TestClassifyAccount(t *testing.T) {
	if got := classifyAccount(Row{HasCrossVenueArb: true}); got != AccountHFT {
		t.Fatalf("cross-venue -> hft, got %q", got)
	}
	if got := classifyAccount(Row{HasSubscriberConfig: true}); got != AccountHFT {
		t.Fatalf("subscriber -> hft, got %q", got)
	}
	if got := classifyAccount(Row{LicenseClass: LicenseCommercial}); got != AccountInstitutional {
		t.Fatalf("commercial -> institutional, got %q", got)
	}
	// Without AnnotateSecurity the cross-venue flag is not set
	// yet — classifyAccount falls through to MarketMaker for
	// the raw multi-table case. The collector path calls
	// AnnotateSecurity first so production rows promote to HFT.
	if got := classifyAccount(Row{
		HasMATbaRofexTable: true,
		HasCMEFuturesTable: true,
	}); got != AccountMarketMaker {
		t.Fatalf("multi-table (raw) -> market-maker, got %q", got)
	}
	if got := classifyAccount(Row{
		HasMATbaRofexTable: true,
		HasCMEFuturesTable: true,
		HasCrossVenueArb:   true,
	}); got != AccountHFT {
		t.Fatalf("multi-table + cross-venue -> hft, got %q", got)
	}
	if got := classifyAccount(Row{ArtifactKind: KindQScript}); got != AccountQuantResearch {
		t.Fatalf("q script -> researcher, got %q", got)
	}
	if got := classifyAccount(Row{HasTickDB: true}); got != AccountHFT {
		t.Fatalf("tick db -> hft, got %q", got)
	}
	if got := classifyAccount(Row{}); got != AccountUnknown {
		t.Fatalf("unknown, got %q", got)
	}
}

// -- collector end-to-end -----------------------------------------

func TestCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")
	dir := filepath.Join(usersBase, "alice", "q")
	must(t, os.MkdirAll(dir, 0o755))

	qPath := filepath.Join(dir, "feed_handler.q")
	must(t, os.WriteFile(qPath, []byte("// Tickerplant feed handler\n"+
		"\\l tickerplant.q\n"+
		"trades:([]ts:`timestamp$();sym:`symbol$();price:`float$())\n"+
		".u.sub:{`trades!()};\n"+
		".z.ps:{[x] 0N!x;}\n"+
		"sym:`DLR`ES`AAPL;\n"+
		"kdb_password=\"secret123\"\n"+
		"cliente_cuit=27-11111111-4\n"), 0o644))

	licPath := filepath.Join(dir, "k4.lic")
	must(t, os.WriteFile(licPath, []byte(`KX Systems kdb+ license
k4.lic
expir_date=2027-12-31
seat_count=20
`), 0o644))

	qrcPath := filepath.Join(dir, ".qrc")
	must(t, os.WriteFile(qrcPath, []byte(`\l q.k
\l feed_handler.q
\l rdb.q
`), 0o644))

	// Random ignored.
	must(t, os.WriteFile(filepath.Join(dir, "random.txt"),
		[]byte(`nope`), 0o644))

	// Public skipped.
	pub := filepath.Join(usersBase, "Public", "q")
	must(t, os.MkdirAll(pub, 0o755))
	must(t, os.WriteFile(filepath.Join(pub, "feed_handler.q"),
		[]byte(`// public`), 0o644))

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
		t.Fatalf("want 3 (q+lic+qrc), got %d: %+v", len(got), got)
	}

	var q, lic, qrc Row
	for _, r := range got {
		switch r.FilePath {
		case qPath:
			q = r
		case licPath:
			lic = r
		case qrcPath:
			qrc = r
		}
	}

	if q.ArtifactKind != KindQScript {
		t.Fatalf("q kind=%q", q.ArtifactKind)
	}
	if !q.HasPasswordInConfig {
		t.Fatalf("q must flag password: %+v", q)
	}
	if !q.HasQScript {
		t.Fatalf("q must auto-flag q-script: %+v", q)
	}
	if !q.HasHFTPattern {
		t.Fatalf("q must flag HFT pattern: %+v", q)
	}
	if !q.HasClienteCuit {
		t.Fatalf("q must flag cliente cuit: %+v", q)
	}
	if !q.IsCredentialExposureRisk {
		t.Fatalf("readable + password + cliente = exposure: %+v", q)
	}

	if lic.ArtifactKind != KindLicense {
		t.Fatalf("lic kind=%q", lic.ArtifactKind)
	}
	if !lic.HasKXLicense {
		t.Fatalf("lic must auto-flag KX license: %+v", lic)
	}
	if lic.LicenseClass != LicenseCommercial {
		t.Fatalf("lic class=%q want commercial", lic.LicenseClass)
	}
	if lic.AccountClass != AccountInstitutional {
		t.Fatalf("lic account=%q want institutional", lic.AccountClass)
	}

	if qrc.ArtifactKind != KindQRCStartup {
		t.Fatalf("qrc kind=%q", qrc.ArtifactKind)
	}
	if qrc.AutoloadChainDepth < 3 {
		t.Fatalf("qrc autoload=%d want >=3", qrc.AutoloadChainDepth)
	}
	if !qrc.HasQRCAutoload {
		t.Fatalf("qrc must flag autoload: %+v", qrc)
	}
}

func TestCollectorRespectsEnv(t *testing.T) {
	tmp := t.TempDir()
	envDir := filepath.Join(tmp, "custom-kdb")
	must(t, os.MkdirAll(envDir, 0o755))
	must(t, os.WriteFile(filepath.Join(envDir, "feed_handler.q"),
		[]byte(`// custom feed handler
`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "KDB_DIR" {
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
	if len(got) != 1 || got[0].ArtifactKind != KindQScript {
		t.Fatalf("env: %+v", got)
	}
}

func TestCollectorMissingPathsOK(t *testing.T) {
	c := &fileCollector{
		installRoots: []string{"/nope-kdb"},
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
		{FilePath: "a", ArtifactKind: KindTplog},
		{FilePath: "a", ArtifactKind: KindConfig},
	}
	SortRows(in)
	if in[0].FilePath != "a" || in[0].ArtifactKind != KindConfig {
		t.Fatalf("first=%+v want (a,kdb-config)", in[0])
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
