package winargecotrader

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindConfig), "ecotrader-config"},
		{string(KindSessionLog), "ecotrader-session-log"},
		{string(KindPositionsCache), "ecotrader-positions-cache"},
		{string(KindWatchlist), "ecotrader-watchlist"},
		{string(KindChartTemplate), "ecotrader-chart-template"},
		{string(KindQuotesCache), "ecotrader-quotes-cache"},
		{string(KindInstaller), "ecotrader-installer"},
		{string(KindOther), "other"},
		{string(KindUnknown), "unknown"},
		{string(AccountPrimaryAPI), "primary-api"},
		{string(AccountDirectFIX), "direct-fix"},
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
		"settings.xml",
		"rofex_settings.xml",
		"ecotrader_settings.ini",
		"eco_trader_config.cfg",
		"session_20260615.log",
		"positions_cache.json",
		"watchlist_default.xml",
		"quotes_20260615.qte",
		"chart_DLR.cht",
		"ROFEXTraderPro_setup.msi",
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

func TestIsCandidateExt(t *testing.T) {
	yes := []string{
		"x.xml", "x.ini", "x.cfg", "x.conf", "x.log",
		"x.json", "x.csv", "x.cht", "x.qte", "x.msi", "x.exe", "x.txt",
	}
	for _, v := range yes {
		if !IsCandidateExt(v) {
			t.Fatalf("expected ext candidate: %q", v)
		}
	}
	if IsCandidateExt("x.pdf") {
		t.Fatal("pdf must not be candidate")
	}
}

func TestArtifactKindFromName(t *testing.T) {
	cases := map[string]ArtifactKind{
		"settings.xml":             KindConfig,
		"rofex_settings.xml":       KindConfig,
		"ecotrader_config.ini":     KindConfig,
		"eco_trader_settings.cfg":  KindConfig,
		"session_20260615.log":     KindSessionLog,
		"session_today.txt":        KindSessionLog,
		"positions_cache.json":     KindPositionsCache,
		"positions-cache.json":     KindPositionsCache,
		"watchlist_default.xml":    KindWatchlist,
		"quotes_20260615.json":     KindQuotesCache,
		"quotes_20260615.qte":      KindQuotesCache,
		"chart_DLR.cht":            KindChartTemplate,
		"ROFEXTraderPro_setup.msi": KindInstaller,
		"":                         KindUnknown,
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
	if PeriodFromFilename("session_202506.log") != "202506" {
		t.Fatal("period mismatch")
	}
	if PeriodFromFilename("random.json") != "" {
		t.Fatal("non-period must be empty")
	}
}

func TestIsDollarFutures(t *testing.T) {
	yes := []string{"DLR", "DLR/JUN26", "DOM", "ROS-DLR", "MTR-USD"}
	no := []string{"", "GGAL", "YPFD", "AL30"}
	for _, v := range yes {
		if !IsDollarFutures(v) {
			t.Fatalf("expected dollar: %q", v)
		}
	}
	for _, v := range no {
		if IsDollarFutures(v) {
			t.Fatalf("expected NOT dollar: %q", v)
		}
	}
}

func TestIsAgroFutures(t *testing.T) {
	yes := []string{
		"SOJ", "SOJ/JUN26", "MAI", "TRI", "GIR", "SOR",
		"ROS-SOJ", "ROS20",
	}
	no := []string{"", "DLR", "GGAL"}
	for _, v := range yes {
		if !IsAgroFutures(v) {
			t.Fatalf("expected agro: %q", v)
		}
	}
	for _, v := range no {
		if IsAgroFutures(v) {
			t.Fatalf("expected NOT agro: %q", v)
		}
	}
}

func TestIsInflationFutures(t *testing.T) {
	yes := []string{"CER", "UVA", "CER-FUT", "UVA-FUT"}
	no := []string{"", "DLR", "SOJ"}
	for _, v := range yes {
		if !IsInflationFutures(v) {
			t.Fatalf("expected inflation: %q", v)
		}
	}
	for _, v := range no {
		if IsInflationFutures(v) {
			t.Fatalf("expected NOT inflation: %q", v)
		}
	}
}

func TestIsMTRUSDBridge(t *testing.T) {
	yes := []string{"MTR-USD", "MTRUSD", "mtr-usd/jun26"}
	no := []string{"", "DLR", "SOJ"}
	for _, v := range yes {
		if !IsMTRUSDBridge(v) {
			t.Fatalf("expected MTR-USD: %q", v)
		}
	}
	for _, v := range no {
		if IsMTRUSDBridge(v) {
			t.Fatalf("expected NOT MTR-USD: %q", v)
		}
	}
}

func TestIsAfterHoursStamp(t *testing.T) {
	yes := []string{
		"07:30", "08:59", "16:00", "16:30", "22:15:00",
		"2026-06-15 08:00", "2026-06-15 17:30:00",
	}
	no := []string{
		"", "09:00", "09:30", "10:00", "15:59",
		"2026-06-15 09:30", "2026-06-15 12:00:00",
	}
	for _, v := range yes {
		if !IsAfterHoursStamp(v) {
			t.Fatalf("expected after-hours: %q", v)
		}
	}
	for _, v := range no {
		if IsAfterHoursStamp(v) {
			t.Fatalf("expected NOT after-hours: %q", v)
		}
	}
}

func TestIsSensitiveKind(t *testing.T) {
	yes := []ArtifactKind{KindConfig, KindSessionLog, KindPositionsCache}
	no := []ArtifactKind{
		KindWatchlist, KindChartTemplate, KindQuotesCache,
		KindInstaller, KindOther, KindUnknown,
	}
	for _, k := range yes {
		if !IsSensitiveKind(k) {
			t.Fatalf("expected sensitive: %q", k)
		}
	}
	for _, k := range no {
		if IsSensitiveKind(k) {
			t.Fatalf("expected NOT sensitive: %q", k)
		}
	}
}

// -- AnnotateSecurity ---------------------------------------------

func TestAnnotateExposure(t *testing.T) {
	r := Row{
		ArtifactKind:        KindConfig,
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
	if !r.IsWorldReadable {
		t.Fatal("0o644 must flag world-readable")
	}
}

func TestAnnotateLockedDown(t *testing.T) {
	r := Row{
		ArtifactKind:        KindConfig,
		HasPasswordInConfig: true,
		ClienteCuitPrefix:   "27",
		ClienteCuitSuffix4:  "1114",
		FileMode:            0o600,
	}
	AnnotateSecurity(&r)
	if r.IsCredentialExposureRisk {
		t.Fatal("0o600 must NOT flag exposure")
	}
}

func TestAnnotateAgroDollar(t *testing.T) {
	r := Row{
		ArtifactKind:      KindPositionsCache,
		DollarFuturesLots: 50,
		AgroFuturesLots:   200,
	}
	AnnotateSecurity(&r)
	if !r.HasDollarFuturesDLR {
		t.Fatal("dollar lots must flag")
	}
	if !r.HasAgroFutures {
		t.Fatal("agro lots must flag")
	}
}

func TestAnnotateAfterHours(t *testing.T) {
	r := Row{
		ArtifactKind:     KindSessionLog,
		SessionFirstSeen: "2026-06-15 17:30:00",
		SessionLastSeen:  "2026-06-15 18:45:00",
	}
	AnnotateSecurity(&r)
	if !r.HasAfterHoursSession {
		t.Fatal("after-hours timestamps must flag")
	}
}

// -- ParseEcoTraderConfig -----------------------------------------

func TestParseEcoTraderConfigXML(t *testing.T) {
	body := []byte(`<settings>
<login>123456</login>
<password>secret123</password>
<server>fix-traderpro.rofex.com.ar:9876</server>
<matricula>987</matricula>
<cliente_cuit>27-11111111-4</cliente_cuit>
<broker>FIX.4.4 BeginString=FIX.4.4</broker>
</settings>`)
	f := ParseEcoTraderConfig(body)
	if !f.HasPassword {
		t.Fatal("password must flag")
	}
	if f.Login != "123456" {
		t.Fatalf("login=%q", f.Login)
	}
	if f.Server == "" {
		t.Fatal("server must extract")
	}
	if f.BrokerMatricula != "987" {
		t.Fatalf("matricula=%q", f.BrokerMatricula)
	}
	if f.ClienteCuitRaw == "" {
		t.Fatal("cliente cuit missing")
	}
	if !f.IsDirectFIX {
		t.Fatal("FIX.4.4 must flag direct FIX")
	}
}

func TestParseEcoTraderConfigINIDemoAccount(t *testing.T) {
	body := []byte(`[account]
login=999
password=demo
server=demo.ecotrader.rofex.com.ar
matricula=42
[mode]
env=demo
`)
	f := ParseEcoTraderConfig(body)
	if !f.HasPassword {
		t.Fatal("password must flag")
	}
	if !f.IsDemoAccount {
		t.Fatal("demo env must flag")
	}
	if f.BrokerMatricula != "42" {
		t.Fatalf("matricula=%q", f.BrokerMatricula)
	}
}

// -- ParseEcoTraderSessionLog -------------------------------------

func TestParseEcoTraderSessionLog(t *testing.T) {
	body := []byte(`2026-06-15 09:30:01 SESSION_OPEN
2026-06-15 09:31:15 execution_report symbol=DLR/JUN26 lots=10
2026-06-15 15:59:45 SESSION_CLOSE
`)
	f := ParseEcoTraderSessionLog(body)
	if f.SessionFirstSeen == "" || f.SessionLastSeen == "" {
		t.Fatalf("session=%+v", f)
	}
	if f.HasAfterHours {
		t.Fatalf("09:30-15:59 must NOT flag after-hours: %+v", f)
	}
}

func TestParseEcoTraderSessionLogAfterHours(t *testing.T) {
	body := []byte(`2026-06-15 07:00:00 SESSION_OPEN
2026-06-15 18:30:00 execution_report symbol=DLR
`)
	f := ParseEcoTraderSessionLog(body)
	if !f.HasAfterHours {
		t.Fatalf("07:00 + 18:30 must flag after-hours: %+v", f)
	}
}

// -- ParseEcoTraderPositions --------------------------------------

func TestParseEcoTraderPositions(t *testing.T) {
	body := []byte(`{
"positions": [
{ "symbol": "DLR/JUN26", "lots": 50 },
{ "symbol": "DOM/JUL26", "lots": 30 },
{ "symbol": "SOJ/MAY26", "lots": 100 },
{ "symbol": "MAI/JUL26", "lots": 200 },
{ "symbol": "CER/DIC26", "lots": 15 },
{ "symbol": "MTR-USD/JUN26", "lots": 5 }
]
}`)
	f := ParseEcoTraderPositions(body)
	if f.DistinctFuturesCount < 6 {
		t.Fatalf("distinct=%d want >=6: %+v", f.DistinctFuturesCount, f)
	}
	if f.MaxPositionLots != 200 {
		t.Fatalf("max=%d", f.MaxPositionLots)
	}
	if f.DollarFuturesLots != 85 {
		t.Fatalf("dollar lots=%d want 85 (DLR50+DOM30+MTR-USD5)", f.DollarFuturesLots)
	}
	if f.AgroFuturesLots != 300 {
		t.Fatalf("agro lots=%d want 300", f.AgroFuturesLots)
	}
	if !f.HasInflation {
		t.Fatal("CER must flag inflation")
	}
	if !f.HasMTRUSDBridge {
		t.Fatal("MTR-USD must flag bridge")
	}
}

// -- ParseEcoTraderWatchlist --------------------------------------

func TestParseEcoTraderWatchlistXML(t *testing.T) {
	body := []byte(`<watchlist>
<symbol>DLR/JUN26</symbol>
<symbol>SOJ/MAY26</symbol>
<symbol>CER/DIC26</symbol>
<symbol>MTR-USD/JUN26</symbol>
<symbol>GGAL</symbol>
</watchlist>`)
	f := ParseEcoTraderWatchlist(body)
	if f.DistinctFuturesCount < 5 {
		t.Fatalf("distinct=%d", f.DistinctFuturesCount)
	}
	if f.DollarFuturesLots == 0 {
		t.Fatal("dollar marker missing")
	}
	if f.AgroFuturesLots == 0 {
		t.Fatal("agro marker missing")
	}
	if !f.HasInflation {
		t.Fatal("CER must flag inflation")
	}
	if !f.HasMTRUSDBridge {
		t.Fatal("MTR-USD must flag bridge")
	}
}

func TestParseEcoTraderEmpty(t *testing.T) {
	f := ParseEcoTraderConfig(nil)
	if f.Login != "" || f.HasPassword {
		t.Fatalf("empty must yield zero: %+v", f)
	}
}

// -- collector end-to-end -----------------------------------------

func TestCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")
	dir := filepath.Join(usersBase, "alice", "Documents", "ROFEX TraderPro")
	must(t, os.MkdirAll(filepath.Join(dir, "logs"), 0o755))
	must(t, os.MkdirAll(filepath.Join(dir, "watchlists"), 0o755))

	// settings.xml with cleartext password, readable.
	cfgPath := filepath.Join(dir, "settings.xml")
	must(t, os.WriteFile(cfgPath, []byte(`<settings>
<login>123456</login>
<password>secret123</password>
<server>fix-traderpro.rofex.com.ar:9876</server>
<matricula>987</matricula>
<cliente_cuit>27-11111111-4</cliente_cuit>
<broker>FIX.4.4 BeginString=FIX.4.4</broker>
</settings>`), 0o644))

	// Session log spanning after-hours.
	logPath := filepath.Join(dir, "logs", "session_202506.log")
	must(t, os.WriteFile(logPath, []byte(`2026-06-15 07:00:00 SESSION_OPEN
2026-06-15 18:30:00 execution_report symbol=DLR
`), 0o600))

	// Positions cache with dollar+agro+inflation+MTR-USD.
	posPath := filepath.Join(dir, "positions_cache.json")
	must(t, os.WriteFile(posPath, []byte(`{
"positions": [
{ "symbol": "DLR/JUN26", "lots": 50 },
{ "symbol": "SOJ/MAY26", "lots": 100 },
{ "symbol": "CER/DIC26", "lots": 15 },
{ "symbol": "MTR-USD/JUN26", "lots": 5 }
]
}`), 0o644))

	// Watchlist with dollar.
	wlPath := filepath.Join(dir, "watchlists", "watchlist_default.xml")
	must(t, os.WriteFile(wlPath, []byte(`<watchlist>
<symbol>DLR/JUN26</symbol>
<symbol>GGAL</symbol>
</watchlist>`), 0o644))

	// Random ignored.
	must(t, os.WriteFile(filepath.Join(dir, "random.txt"),
		[]byte(`nope`), 0o644))

	// Public skipped.
	pub := filepath.Join(usersBase, "Public", "Documents", "ROFEX TraderPro")
	must(t, os.MkdirAll(pub, 0o755))
	must(t, os.WriteFile(filepath.Join(pub, "settings.xml"),
		[]byte(`<settings><password>x</password></settings>`), 0o644))

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
		t.Fatalf("want 4 (cfg+log+pos+wl), got %d: %+v", len(got), got)
	}

	var cfg, sess, pos, wl Row
	for _, r := range got {
		switch r.FilePath {
		case cfgPath:
			cfg = r
		case logPath:
			sess = r
		case posPath:
			pos = r
		case wlPath:
			wl = r
		}
	}

	if cfg.ArtifactKind != KindConfig {
		t.Fatalf("cfg kind=%q", cfg.ArtifactKind)
	}
	if !cfg.HasPasswordInConfig {
		t.Fatalf("cfg must flag password: %+v", cfg)
	}
	if cfg.AccountClass != AccountDirectFIX {
		t.Fatalf("cfg account=%q want direct-fix", cfg.AccountClass)
	}
	if cfg.BrokerMatricula != "987" {
		t.Fatalf("cfg matricula=%q", cfg.BrokerMatricula)
	}
	if cfg.AccountLoginSuffix4 != "3456" {
		t.Fatalf("cfg login_suffix4=%q want 3456", cfg.AccountLoginSuffix4)
	}
	if !cfg.HasClienteCuit {
		t.Fatalf("cfg must flag cliente cuit: %+v", cfg)
	}
	if !cfg.IsCredentialExposureRisk {
		t.Fatalf("readable + password + cliente = exposure: %+v", cfg)
	}

	if sess.ArtifactKind != KindSessionLog {
		t.Fatalf("sess kind=%q", sess.ArtifactKind)
	}
	if !sess.HasAfterHoursSession {
		t.Fatalf("sess must flag after-hours: %+v", sess)
	}

	if pos.ArtifactKind != KindPositionsCache {
		t.Fatalf("pos kind=%q", pos.ArtifactKind)
	}
	if !pos.HasDollarFuturesDLR {
		t.Fatalf("pos must flag dollar futures: %+v", pos)
	}
	if !pos.HasAgroFutures {
		t.Fatalf("pos must flag agro futures: %+v", pos)
	}
	if !pos.HasInflationFutures {
		t.Fatalf("pos must flag inflation futures: %+v", pos)
	}
	if !pos.HasMTRUSDBridge {
		t.Fatalf("pos must flag MTR-USD bridge: %+v", pos)
	}

	if wl.ArtifactKind != KindWatchlist {
		t.Fatalf("wl kind=%q", wl.ArtifactKind)
	}
	if !wl.HasDollarFuturesDLR {
		t.Fatalf("wl must flag dollar futures: %+v", wl)
	}
}

func TestCollectorRespectsEnv(t *testing.T) {
	tmp := t.TempDir()
	envDir := filepath.Join(tmp, "custom-ecotrader")
	must(t, os.MkdirAll(envDir, 0o755))
	must(t, os.WriteFile(filepath.Join(envDir, "settings.xml"),
		[]byte(`<settings><password>x</password><login>42</login></settings>`),
		0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "ECOTRADER_DIR" {
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
		installRoots: []string{"/nope-ecotrader"},
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
		{FilePath: "a", ArtifactKind: KindPositionsCache},
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
	if classifyAccount(EcoTraderFields{IsDemoAccount: true}) != AccountDemo {
		t.Fatal("demo")
	}
	if classifyAccount(EcoTraderFields{IsDirectFIX: true}) != AccountDirectFIX {
		t.Fatal("fix")
	}
	if classifyAccount(EcoTraderFields{Server: "x"}) != AccountPrimaryAPI {
		t.Fatal("primary")
	}
	if classifyAccount(EcoTraderFields{}) != AccountUnknown {
		t.Fatal("unknown")
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
