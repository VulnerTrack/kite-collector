package winargmaeonlinefx

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindConfig), "mae-onlinefx-config"},
		{string(KindCredentials), "mae-onlinefx-credentials"},
		{string(KindQuotesCache), "mae-onlinefx-quotes-cache"},
		{string(KindTradeBlotter), "mae-onlinefx-trade-blotter"},
		{string(KindForwardBook), "mae-onlinefx-forward-book"},
		{string(KindNDFBook), "mae-onlinefx-ndf-book"},
		{string(KindUSDTBook), "mae-onlinefx-usdt-book"},
		{string(KindSessionLog), "mae-onlinefx-session-log"},
		{string(KindFIXDropCopy), "mae-onlinefx-fix-drop-copy"},
		{string(KindInstaller), "mae-onlinefx-installer"},
		{string(KindOther), "other"},
		{string(KindUnknown), "unknown"},
		{string(ParticipantBank), "bank"},
		{string(ParticipantALYC), "alyc"},
		{string(ParticipantCriptoExchange), "cripto-exchange"},
		{string(ParticipantImporterExporter), "importer-exporter"},
		{string(ParticipantFCIManager), "fci-manager"},
		{string(ParticipantBCRA), "bcra"},
		{string(ParticipantAuditor), "auditor"},
		{string(ParticipantDemo), "demo"},
		{string(ParticipantOther), "other"},
		{string(ParticipantUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestIsCandidateName(t *testing.T) {
	yes := []string{
		"mae_onlinefx_config.xml",
		"mae-onlinefx-credentials.json",
		"onlinefx_session.log",
		"quotes_fx_202506.json",
		"fx_quotes.json",
		"trade_blotter_202506.csv",
		"fx_blotter.csv",
		"fwd_book_202506.csv",
		"ndf_book.csv",
		"usdt_book.csv",
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
		"mae_onlinefx_config.xml":       KindConfig,
		"onlinefx_settings.json":        KindConfig,
		"mae_onlinefx_credentials.json": KindCredentials,
		"mae_onlinefx_api_key.json":     KindCredentials,
		"quotes_fx_202506.json":         KindQuotesCache,
		"fx_quotes_202506.json":         KindQuotesCache,
		"trade_blotter_202506.csv":      KindTradeBlotter,
		"fx_blotter.csv":                KindTradeBlotter,
		"fwd_book_202506.csv":           KindForwardBook,
		"forward_book.csv":              KindForwardBook,
		"ndf_book_202506.csv":           KindNDFBook,
		"usdt_book_202506.csv":          KindUSDTBook,
		"drop_copy.fix":                 KindFIXDropCopy,
		"dropcopy_202506.log":           KindFIXDropCopy,
		"onlinefx_session.log":          KindSessionLog,
		"mae_onlinefx_setup.msi":        KindInstaller,
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
		{"counterparty 27-11111111-4", "27", "1114"},
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
	if PeriodFromFilename("trade_blotter_202506.csv") != "202506" {
		t.Fatal("period mismatch")
	}
	if PeriodFromFilename("random.csv") != "" {
		t.Fatal("non-period must be empty")
	}
}

func TestFXMarkers(t *testing.T) {
	yes := map[string]func([]byte) bool{
		`{"pair":"USD/ARS-SPOT"}`: HasUSDARSSpotMarker,
		`{"pair":"DLR-SPOT"}`:     HasUSDARSSpotMarker,
		`{"pair":"USD/ARS-FWD"}`:  HasUSDARSForwardMarker,
		`{"pair":"DLR-NDF"}`:      HasUSDARSNDFMarker,
		`{"pair":"USDT/ARS"}`:     HasUSDTARSMarker,
		`{"pair":"BRL/ARS"}`:      HasBRLARSMarker,
		`{"pair":"EUR/ARS"}`:      HasEURARSMarker,
	}
	for in, fn := range yes {
		if !fn([]byte(in)) {
			t.Fatalf("expected marker hit for %q", in)
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

func TestParticipantIDFromText(t *testing.T) {
	cases := map[string]string{
		`participant_id: 42`:               "42",
		`matricula = 123`:                  "123",
		`<bank_id>987</bank_id>`:           "987",
		`<participante>456</participante>`: "456",
		`no participant here`:              "",
	}
	for in, want := range cases {
		if got := ParticipantIDFromText(in); got != want {
			t.Fatalf("ParticipantIDFromText(%q)=%q want %q", in, got, want)
		}
	}
}

func TestIsCredentialKind(t *testing.T) {
	yes := []ArtifactKind{
		KindConfig, KindCredentials, KindTradeBlotter,
		KindForwardBook, KindNDFBook, KindUSDTBook,
		KindFIXDropCopy, KindSessionLog,
	}
	no := []ArtifactKind{
		KindQuotesCache, KindInstaller, KindOther, KindUnknown,
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
		ArtifactKind:       KindTradeBlotter,
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
		ArtifactKind:       KindTradeBlotter,
		ClienteCuitPrefix:  "27",
		ClienteCuitSuffix4: "1114",
		FileMode:           0o600,
	}
	AnnotateSecurity(&r)
	if r.IsCredentialExposureRisk {
		t.Fatal("0o600 must NOT flag exposure")
	}
}

func TestAnnotateProductFlags(t *testing.T) {
	r := Row{
		ArtifactKind:      KindTradeBlotter,
		SpotTradeCount:    3,
		ForwardTradeCount: 2,
		NDFTradeCount:     1,
		USDTTradeCount:    5,
		BRLTradeCount:     1,
		EURTradeCount:     1,
	}
	AnnotateSecurity(&r)
	if !r.HasUSDARSSpot || !r.HasUSDARSForward || !r.HasUSDARSNDF ||
		!r.HasUSDTARSTrading || !r.HasBRLARSTrading || !r.HasEURARSTrading {
		t.Fatalf("all product flags must fire: %+v", r)
	}
}

func TestAnnotateHighVolumeAndAboveCap(t *testing.T) {
	r := Row{
		ArtifactKind:        KindForwardBook,
		TotalVolumeUSDCents: 150_000_000,
		AboveCapCount:       3,
	}
	AnnotateSecurity(&r)
	if !r.HasHighVolumeFX {
		t.Fatal("USD 1.5 M must flag high volume")
	}
	if !r.HasBCRAAboveCap {
		t.Fatal("above-cap count must flag")
	}
}

func TestParseMAEFXCredentials(t *testing.T) {
	body := []byte(`<MAEOnlineFX>
<participant_id>210</participant_id>
<password>secret123</password>
<cliente_cuit>27-11111111-4</cliente_cuit>
</MAEOnlineFX>`)
	f := ParseMAEFXCredentials(body)
	if !f.HasPassword {
		t.Fatal("password must flag")
	}
	if f.ParticipantID != "210" {
		t.Fatalf("participant=%q", f.ParticipantID)
	}
	if f.ClienteCuitRaw == "" {
		t.Fatal("cliente cuit missing")
	}
}

func TestParseMAEFXQuotesCache(t *testing.T) {
	body := []byte(`2026-06-15 trade_id=1 pair=USD/ARS-SPOT importe_usd=5000000.00 cliente_cuit=27-11111111-4
2026-06-15 trade_id=2 pair=USD/ARS-FWD importe_usd=10000000.00
2026-06-15 trade_id=3 pair=DLR-NDF importe_usd=8000000.00
2026-06-15 trade_id=4 pair=USDT/ARS importe_usd=3000000.00
2026-06-15 trade_id=5 pair=BRL/ARS importe_usd=2000000.00
2026-06-15 trade_id=6 pair=EUR/ARS importe_usd=1500000.00
2026-06-15 trade_id=7 pair=USD/ARS-SPOT importe_usd=300000000.00
`)
	f := ParseMAEFXQuotesCache(body)
	if f.TradeCount < 7 {
		t.Fatalf("trades=%d", f.TradeCount)
	}
	if f.SpotCount < 2 {
		t.Fatalf("spot=%d", f.SpotCount)
	}
	if f.ForwardCount < 1 {
		t.Fatalf("fwd=%d", f.ForwardCount)
	}
	if f.NDFCount < 1 {
		t.Fatalf("ndf=%d", f.NDFCount)
	}
	if f.USDTCount < 1 {
		t.Fatalf("usdt=%d", f.USDTCount)
	}
	if f.BRLCount < 1 {
		t.Fatalf("brl=%d", f.BRLCount)
	}
	if f.EURCount < 1 {
		t.Fatalf("eur=%d", f.EURCount)
	}
	if f.AboveCapCount < 1 {
		t.Fatalf("above_cap=%d want >=1 (300 M > 200 K cap)", f.AboveCapCount)
	}
}

func TestParseMAEFXForwardBook(t *testing.T) {
	body := []byte(`trade_id,pair,notional_usd,counterparty
1,USD/ARS-FWD,5000000.00,30-71234567-8
2,USD/ARS-FWD,3000000.00,30-99999999-1
`)
	f := ParseMAEFXForwardBook(body)
	if f.ForwardCount < 2 {
		t.Fatalf("forwards=%d", f.ForwardCount)
	}
	if f.TotalVolumeUSDCents < 800_000_000 {
		t.Fatalf("volume=%d", f.TotalVolumeUSDCents)
	}
	if f.DistinctCounterparties < 2 {
		t.Fatalf("distinct=%d", f.DistinctCounterparties)
	}
}

func TestParseMAEFXNDFBook(t *testing.T) {
	body := []byte(`trade_id,pair,notional_usd
1,USD/ARS-NDF,4000000.00
2,DLR-NDF,2000000.00
`)
	f := ParseMAEFXNDFBook(body)
	if f.NDFCount < 2 {
		t.Fatalf("ndf=%d", f.NDFCount)
	}
}

func TestParseMAEFXUSDTBook(t *testing.T) {
	body := []byte(`trade_id,pair,notional_usd
1,USDT/ARS,1000000.00
2,USDT-ARS,500000.00
`)
	f := ParseMAEFXUSDTBook(body)
	if f.USDTCount < 2 {
		t.Fatalf("usdt=%d", f.USDTCount)
	}
}

func TestParseMAEFXFIXDropCopy(t *testing.T) {
	body := []byte(`2026-06-15 09:30:01 8=FIX.4.4|9=120|35=AE|49=MAEONLINEFX|56=BANK|TradeCaptureReport|trade_id=1 pair=USD/ARS-SPOT notional_usd=5000000.00
2026-06-15 09:30:02 8=FIX.4.4|9=80|35=AE|49=MAEONLINEFX|56=BANK|trade_id=2 pair=USD/ARS-FWD notional_usd=2000000.00
`)
	f := ParseMAEFXFIXDropCopy(body)
	if !f.HasFIXDropCopy {
		t.Fatal("drop copy must flag")
	}
	if f.FIXSenderCompID == "" {
		t.Fatal("sender")
	}
	if f.FIXTargetCompID == "" {
		t.Fatal("target")
	}
	if f.SpotCount < 1 || f.ForwardCount < 1 {
		t.Fatalf("products: spot=%d fwd=%d", f.SpotCount, f.ForwardCount)
	}
}

func TestParseMAEFXEmpty(t *testing.T) {
	f := ParseMAEFXCredentials(nil)
	if f.HasPassword || f.ParticipantID != "" {
		t.Fatalf("empty must yield zero: %+v", f)
	}
}

// -- collector end-to-end -----------------------------------------

func TestCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")
	dir := filepath.Join(usersBase, "alice", "AppData", "Roaming", "MAE", "OnlineFX")
	must(t, os.MkdirAll(filepath.Join(dir, "books"), 0o755))

	cfgPath := filepath.Join(dir, "mae_onlinefx_config.xml")
	must(t, os.WriteFile(cfgPath, []byte(`<MAEOnlineFX>
<participant_id>210</participant_id>
<password>secret123</password>
<cliente_cuit>27-11111111-4</cliente_cuit>
</MAEOnlineFX>`), 0o644))

	blotPath := filepath.Join(dir, "books", "trade_blotter_202506.csv")
	must(t, os.WriteFile(blotPath, []byte(`2026-06-15 trade_id=1 pair=USD/ARS-SPOT importe_usd=5000000.00
2026-06-15 trade_id=2 pair=USD/ARS-FWD importe_usd=3000000.00
2026-06-15 trade_id=3 pair=DLR-NDF importe_usd=2000000.00
2026-06-15 trade_id=4 pair=USDT/ARS importe_usd=200000000.00
`), 0o644))

	fwdPath := filepath.Join(dir, "books", "fwd_book_202506.csv")
	must(t, os.WriteFile(fwdPath, []byte(`trade_id,pair,notional_usd,counterparty
1,USD/ARS-FWD,1000000.00,30-71234567-8
`), 0o644))

	// Random ignored.
	must(t, os.WriteFile(filepath.Join(dir, "random.txt"),
		[]byte(`nope`), 0o644))

	// Public skipped.
	pub := filepath.Join(usersBase, "Public", "AppData", "Roaming", "MAE", "OnlineFX")
	must(t, os.MkdirAll(pub, 0o755))
	must(t, os.WriteFile(filepath.Join(pub, "mae_onlinefx_config.xml"),
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
	if len(got) != 3 {
		t.Fatalf("want 3 (cfg+blot+fwd), got %d: %+v", len(got), got)
	}

	var cfg, blot, fwd Row
	for _, r := range got {
		switch r.FilePath {
		case cfgPath:
			cfg = r
		case blotPath:
			blot = r
		case fwdPath:
			fwd = r
		}
	}

	if cfg.ArtifactKind != KindConfig {
		t.Fatalf("cfg kind=%q", cfg.ArtifactKind)
	}
	if !cfg.HasPasswordInConfig {
		t.Fatalf("cfg must flag password: %+v", cfg)
	}
	if cfg.ParticipantID != "210" {
		t.Fatalf("cfg participant=%q", cfg.ParticipantID)
	}
	if !cfg.HasClienteCuit {
		t.Fatalf("cfg must flag cliente cuit: %+v", cfg)
	}
	if !cfg.IsCredentialExposureRisk {
		t.Fatalf("readable + password + cuit = exposure: %+v", cfg)
	}

	if blot.ArtifactKind != KindTradeBlotter {
		t.Fatalf("blot kind=%q", blot.ArtifactKind)
	}
	if !blot.HasUSDARSSpot {
		t.Fatalf("blot must flag USD/ARS spot: %+v", blot)
	}
	if !blot.HasUSDARSForward {
		t.Fatalf("blot must flag forward: %+v", blot)
	}
	if !blot.HasUSDARSNDF {
		t.Fatalf("blot must flag NDF: %+v", blot)
	}
	if !blot.HasUSDTARSTrading {
		t.Fatalf("blot must flag USDT: %+v", blot)
	}
	if !blot.HasBCRAAboveCap {
		t.Fatalf("blot must flag above-cap (200 M > 200 K): %+v", blot)
	}

	if fwd.ArtifactKind != KindForwardBook {
		t.Fatalf("fwd kind=%q", fwd.ArtifactKind)
	}
	if !fwd.HasUSDARSForward {
		t.Fatalf("fwd must flag forward: %+v", fwd)
	}
}

func TestCollectorRespectsEnv(t *testing.T) {
	tmp := t.TempDir()
	envDir := filepath.Join(tmp, "custom-mae-onlinefx")
	must(t, os.MkdirAll(envDir, 0o755))
	must(t, os.WriteFile(filepath.Join(envDir, "mae_onlinefx_config.xml"),
		[]byte(`<MAEOnlineFX><participant_id>42</participant_id></MAEOnlineFX>`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "MAE_ONLINEFX_DIR" {
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
		installRoots: []string{"/nope-mae-onlinefx"},
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
		{FilePath: "a", ArtifactKind: KindTradeBlotter},
		{FilePath: "a", ArtifactKind: KindConfig},
	}
	SortRows(in)
	if in[0].FilePath != "a" || in[0].ArtifactKind != KindConfig {
		t.Fatalf("first=%+v want (a,mae-onlinefx-config)", in[0])
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

func TestClassifyParticipant(t *testing.T) {
	if classifyParticipant(MAEFXFields{HasFIXDropCopy: true}, Row{}) != ParticipantBank {
		t.Fatal("drop-copy -> bank")
	}
	if classifyParticipant(MAEFXFields{USDTCount: 1}, Row{}) != ParticipantCriptoExchange {
		t.Fatal("usdt -> cripto-exchange")
	}
	if classifyParticipant(MAEFXFields{ForwardCount: 1}, Row{}) != ParticipantBank {
		t.Fatal("forward -> bank")
	}
	if classifyParticipant(MAEFXFields{SpotCount: 1}, Row{}) != ParticipantALYC {
		t.Fatal("spot -> alyc")
	}
	if classifyParticipant(MAEFXFields{}, Row{}) != ParticipantUnknown {
		t.Fatal("unknown")
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
