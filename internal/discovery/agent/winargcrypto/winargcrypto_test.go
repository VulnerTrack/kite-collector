package winargcrypto

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindAPIKey), "crypto-api-key"},
		{string(KindAccountExport), "crypto-account-export"},
		{string(KindOTCP2PLog), "crypto-otc-p2p-log"},
		{string(KindWalletSeed), "crypto-wallet-seed"},
		{string(KindTaxReport), "crypto-tax-report"},
		{string(KindStablecoinLog), "crypto-stablecoin-trade-log"},
		{string(KindStrategyScript), "crypto-strategy-script"},
		{string(KindCCXTCache), "crypto-ccxt-cache"},
		{string(KindInstaller), "crypto-installer"},
		{string(KindOther), "other"},
		{string(KindUnknown), "unknown"},
		{string(ExchangeBitso), "bitso"},
		{string(ExchangeLemon), "lemon"},
		{string(ExchangeBelo), "belo"},
		{string(ExchangeRipio), "ripio"},
		{string(ExchangeBuenbit), "buenbit"},
		{string(ExchangeDecrypto), "decrypto"},
		{string(ExchangeSatoshitango), "satoshitango"},
		{string(ExchangeFiwind), "fiwind"},
		{string(ExchangeCryptomarket), "cryptomarket"},
		{string(ExchangeVibrant), "vibrant"},
		{string(ExchangeLetsbit), "letsbit"},
		{string(ExchangeBinance), "binance"},
		{string(ExchangeKraken), "kraken"},
		{string(ExchangeOKX), "okx"},
		{string(ExchangeBybit), "bybit"},
		{string(ExchangeCoinbase), "coinbase"},
		{string(ExchangeKuCoin), "kucoin"},
		{string(ExchangeOther), "other"},
		{string(ExchangeUnknown), "unknown"},
		{string(PSAVArgRegistered), "arg-registered-psav"},
		{string(PSAVOffshoreSelfReport), "offshore-self-report"},
		{string(PSAVWalletNonCustodial), "wallet-non-custodial"},
		{string(PSAVOther), "other"},
		{string(PSAVUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestIsCandidateName(t *testing.T) {
	yes := []string{
		"credentials",
		"api_key",
		"wallet_seed",
		"mnemonic",
		"seed_phrase",
		"bitso_credentials.json",
		"lemon_export_20260615.csv",
		"binance_api.json",
		"otc_p2p_20260615.log",
		"usdt_pairs_20260615.csv",
		"bienes_personales_2026.csv",
		"wallet.json",
		"ccxt_config.json",
		"strategy_ccxt.py",
		"my_binance_algo.ipynb",
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
		"credentials":                KindAPIKey,
		"api_key":                    KindAPIKey,
		"wallet_seed":                KindWalletSeed,
		"mnemonic":                   KindWalletSeed,
		"seed_phrase":                KindWalletSeed,
		"bitso_credentials.json":     KindAPIKey,
		"binance_api_key.json":       KindAPIKey,
		"otc_p2p_20260615.log":       KindOTCP2PLog,
		"usdt_pairs_20260615.csv":    KindStablecoinLog,
		"stablecoin_trades.csv":      KindStablecoinLog,
		"bienes_personales_2026.csv": KindTaxReport,
		"afip_cripto_2026.csv":       KindTaxReport,
		"wallet_mnemonic.txt":        KindWalletSeed,
		"ccxt_config.json":           KindCCXTCache,
		"lemon_export_20260615.csv":  KindAccountExport,
		"strategy_ccxt.py":           KindStrategyScript,
		"my_binance_algo.ipynb":      KindStrategyScript,
		"binance_v1_installer.msi":   KindInstaller,
		"":                           KindUnknown,
	}
	for in, want := range cases {
		if got := ArtifactKindFromName(in); got != want {
			t.Fatalf("ArtifactKindFromName(%q)=%q want %q", in, got, want)
		}
	}
}

func TestExchangeFromPath(t *testing.T) {
	cases := map[string]Exchange{
		`C:\Users\alice\Documents\Bitso\credentials.json`: ExchangeBitso,
		`/home/alice/.lemon/config.toml`:                  ExchangeLemon,
		`/home/alice/Documents/Belo/api.json`:             ExchangeBelo,
		`/home/alice/Documents/Ripio/api.json`:            ExchangeRipio,
		`/home/alice/.buenbit/api.json`:                   ExchangeBuenbit,
		`/home/alice/Decrypto/api.json`:                   ExchangeDecrypto,
		`/home/alice/.config/binance/api.json`:            ExchangeBinance,
		`/home/alice/.kraken/api.json`:                    ExchangeKraken,
		`/home/alice/Documents/Bybit/api.json`:            ExchangeBybit,
		`/home/alice/Documents/OKX/api.json`:              ExchangeOKX,
		`/home/alice/Documents/Coinbase/api.json`:         ExchangeCoinbase,
		`/home/alice/Documents/KuCoin/api.json`:           ExchangeKuCoin,
		`/home/alice/Documents/Random/file.csv`:           ExchangeUnknown,
		"":                                                ExchangeUnknown,
	}
	for in, want := range cases {
		if got := ExchangeFromPath(in); got != want {
			t.Fatalf("ExchangeFromPath(%q)=%q want %q", in, got, want)
		}
	}
}

func TestPSAVClassFromExchange(t *testing.T) {
	cases := map[Exchange]PSAVClass{
		ExchangeBitso:   PSAVArgRegistered,
		ExchangeLemon:   PSAVArgRegistered,
		ExchangeBelo:    PSAVArgRegistered,
		ExchangeBinance: PSAVOffshoreSelfReport,
		ExchangeKraken:  PSAVOffshoreSelfReport,
		ExchangeOther:   PSAVUnknown,
		ExchangeUnknown: PSAVUnknown,
	}
	for in, want := range cases {
		if got := PSAVClassFromExchange(in); got != want {
			t.Fatalf("PSAVClassFromExchange(%q)=%q want %q", in, got, want)
		}
	}
}

func TestIsArgRegisteredPSAV(t *testing.T) {
	yes := []Exchange{ExchangeBitso, ExchangeLemon, ExchangeBelo, ExchangeRipio, ExchangeBuenbit, ExchangeDecrypto}
	no := []Exchange{ExchangeBinance, ExchangeKraken, ExchangeOther, ExchangeUnknown}
	for _, v := range yes {
		if !IsArgRegisteredPSAV(v) {
			t.Fatalf("expected ARG-PSAV: %q", v)
		}
	}
	for _, v := range no {
		if IsArgRegisteredPSAV(v) {
			t.Fatalf("expected NOT ARG-PSAV: %q", v)
		}
	}
}

func TestIsStablecoinPair(t *testing.T) {
	yes := []string{"BTCUSDT", "ETHUSDC", "USDT", "USDC", "DAI", "BUSD", "usdt"}
	no := []string{"BTCARS", "ETH", "", "BTC/ARS"}
	for _, v := range yes {
		if !IsStablecoinPair(v) {
			t.Fatalf("expected stablecoin: %q", v)
		}
	}
	for _, v := range no {
		if IsStablecoinPair(v) {
			t.Fatalf("expected NOT stablecoin: %q", v)
		}
	}
}

func TestCuitFingerprint(t *testing.T) {
	cases := []struct {
		in, pfx, sfx4 string
	}{
		{"cliente 27-11111111-4", "27", "1114"},
		{"operador 20-12345678-9", "20", "6789"},
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

// -- AnnotateSecurity ---------------------------------------------

func TestAnnotateAPIKeyExposure(t *testing.T) {
	r := Row{
		ArtifactKind: KindAPIKey,
		Exchange:     ExchangeBinance,
		HasAPIKey:    true,
		HasAPISecret: true,
		FileMode:     0o644,
	}
	AnnotateSecurity(&r)
	if !r.IsCredentialExposureRisk {
		t.Fatalf("readable + api-key + secret = exposure: %+v", r)
	}
}

func TestAnnotateWalletSeedExposure(t *testing.T) {
	r := Row{
		ArtifactKind:        KindWalletSeed,
		HasWalletSeedMarker: true,
		FileMode:            0o644,
	}
	AnnotateSecurity(&r)
	if !r.IsCredentialExposureRisk {
		t.Fatalf("readable + seed marker = exposure: %+v", r)
	}
}

func TestAnnotateStablecoinHigh(t *testing.T) {
	r := Row{
		ArtifactKind:             KindStablecoinLog,
		StablecoinVolumeARSCents: 2_000_000_000, // 20 M ARS
		FileMode:                 0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasHighVolumeStablecoin {
		t.Fatal("20M ARS USDT must flag high stablecoin")
	}
	if !r.HasStablecoinVolume {
		t.Fatal("any USDT volume must flag")
	}
}

func TestAnnotateOTCActivity(t *testing.T) {
	r := Row{
		ArtifactKind: KindOTCP2PLog,
		OTCP2PCount:  5,
		FileMode:     0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasOTCP2PActivity {
		t.Fatal("P2P count > 0 must flag")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatalf("readable + p2p = exposure: %+v", r)
	}
}

func TestAnnotateLockedDownClean(t *testing.T) {
	r := Row{
		ArtifactKind:        KindWalletSeed,
		HasWalletSeedMarker: true,
		FileMode:            0o600,
	}
	AnnotateSecurity(&r)
	if r.IsCredentialExposureRisk {
		t.Fatal("0o600 must NOT flag exposure")
	}
}

// -- ParseCryptoCredentials ---------------------------------------

func TestParseCryptoCredentialsJSON(t *testing.T) {
	body := []byte(`{
  "exchange": "binance",
  "api_key": "aBcDeFgHiJkLmNoPqRsTuVwX",
  "api_secret": "ZyXwVuTsRqPoNmLkJiHgFeDc",
  "cliente_cuit": "27-11111111-4"
}`)
	f := ParseCryptoCredentials(body)
	if !f.HasAPIKey {
		t.Fatal("api_key must flag")
	}
	if f.APIKey == "" {
		t.Fatal("api key value must extract")
	}
	if !f.HasAPISecret {
		t.Fatal("api_secret must flag")
	}
	if f.ClienteCuitRaw == "" {
		t.Fatal("cliente cuit missing")
	}
}

func TestParseCryptoCredentialsEmpty(t *testing.T) {
	f := ParseCryptoCredentials(nil)
	if f.HasAPIKey || f.HasAPISecret {
		t.Fatal("empty must not flag")
	}
}

// -- ParseCryptoOTCLog --------------------------------------------

func TestParseCryptoOTCLog(t *testing.T) {
	body := []byte(`2026-06-15 10:00:00 OTC P2P trade seller_id=alice notional=500000.00
2026-06-15 10:05:00 P2P sell buyer_id=bob notional=300000.00
2026-06-15 10:10:00 P2P sell buyer_id=carol notional=1200000.00
cliente_cuit: 27-11111111-4
`)
	f := ParseCryptoOTCLog(body)
	if f.OTCP2PCount < 3 {
		t.Fatalf("p2p count=%d want >=3", f.OTCP2PCount)
	}
	if f.MaxTradeCents != 120_000_000 {
		t.Fatalf("max trade=%d", f.MaxTradeCents)
	}
	if f.ClienteCuitRaw == "" {
		t.Fatal("cliente cuit missing")
	}
}

// -- ParseCryptoStablecoinLog -------------------------------------

func TestParseCryptoStablecoinLog(t *testing.T) {
	body := []byte(`2026-06-15 10:00:00 BUY USDT/ARS USDT_amount=1500000.00 rate=1100
2026-06-15 10:05:00 SELL USDT/ARS USDT_amount=800000.00 rate=1102
2026-06-15 10:10:00 BUY USDC/ARS USDC_amount=500000.00 rate=1095
`)
	f := ParseCryptoStablecoinLog(body)
	if f.StablecoinCents != 280_000_000 {
		t.Fatalf("stablecoin total=%d want 280_000_000", f.StablecoinCents)
	}
	if f.MaxTradeCents != 150_000_000 {
		t.Fatalf("max trade=%d", f.MaxTradeCents)
	}
	if f.DistinctPairCount < 2 {
		t.Fatalf("distinct pairs=%d want >=2", f.DistinctPairCount)
	}
}

// -- ParseCryptoAccountExport -------------------------------------

func TestParseCryptoAccountExport(t *testing.T) {
	body := []byte(`# Bitso account export header
fecha,tipo,par,Importe,fee
2026-06-15,buy,BTC/ARS,Importe=1000000.00,500
2026-06-15,sell,ETH/ARS,Importe=500000.00,250
2026-06-15,buy,USDT/ARS,Importe=800000.00,400
`)
	f := ParseCryptoAccountExport(body)
	if f.TradeCount < 1 {
		t.Fatalf("trade count=%d", f.TradeCount)
	}
	if f.MaxTradeCents != 100_000_000 {
		t.Fatalf("max=%d", f.MaxTradeCents)
	}
}

// -- ParseCryptoWalletSeed ----------------------------------------

func TestParseCryptoWalletSeedDetectsCluster(t *testing.T) {
	// 12 BIP39 words clustered.
	body := []byte(`abandon ability able about above absent absorb abstract absurd abuse access accident`)
	f := ParseCryptoWalletSeed(body)
	if !f.HasWalletSeedMarker {
		t.Fatalf("BIP39 cluster must flag: %+v", f)
	}
}

func TestParseCryptoWalletSeedNoCluster(t *testing.T) {
	body := []byte(`just a single random word like access without any other matching`)
	f := ParseCryptoWalletSeed(body)
	if f.HasWalletSeedMarker {
		t.Fatal("single word must NOT flag cluster")
	}
}

func TestParseCryptoWalletSeedEmpty(t *testing.T) {
	f := ParseCryptoWalletSeed(nil)
	if f.HasWalletSeedMarker {
		t.Fatal("empty must NOT flag")
	}
}

// -- ParseCryptoStrategy ------------------------------------------

func TestParseCryptoStrategy(t *testing.T) {
	body := []byte(`import ccxt
exchange = ccxt.binance()
`)
	f := ParseCryptoStrategy(body)
	if !f.HasStrategyImport {
		t.Fatal("ccxt import must flag")
	}
}

// -- collector end-to-end -----------------------------------------

func TestCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")
	dir := filepath.Join(usersBase, "alice", "Documents", "Bitso")
	must(t, os.MkdirAll(dir, 0o755))

	// API key, world-readable.
	apiPath := filepath.Join(dir, "bitso_credentials.json")
	must(t, os.WriteFile(apiPath, []byte(`{
  "exchange": "bitso",
  "api_key": "aBcDeFgHiJkLmNoPqRsTuVwX",
  "api_secret": "ZyXwVuTsRqPoNmLkJiHgFeDc",
  "cliente_cuit": "27-11111111-4"
}`), 0o644))

	// Wallet seed file, world-readable (worst case).
	seedPath := filepath.Join(dir, "wallet_seed")
	must(t, os.WriteFile(seedPath,
		[]byte(`abandon ability able about above absent absorb abstract absurd abuse access accident`),
		0o644))

	// USDT stablecoin log with high volume + no AFIP marker.
	stablePath := filepath.Join(dir, "usdt_pairs_202506.csv")
	must(t, os.WriteFile(stablePath, []byte(`2026-06-15 10:00:00 BUY USDT/ARS USDT_amount=8000000.00 rate=1100
2026-06-15 10:05:00 SELL USDT/ARS USDT_amount=5000000.00 rate=1102
2026-06-15 10:10:00 BUY USDC/ARS USDC_amount=3000000.00 rate=1095
`), 0o600))

	// OTC P2P log.
	otcPath := filepath.Join(dir, "otc_p2p_202506.log")
	must(t, os.WriteFile(otcPath, []byte(`2026-06-15 10:00:00 OTC P2P trade seller_id=alice notional=500000.00
2026-06-15 10:05:00 P2P sell buyer_id=bob notional=300000.00
`), 0o644))

	// Random ignored.
	must(t, os.WriteFile(filepath.Join(dir, "random.txt"),
		[]byte(`nope`), 0o644))

	// Public skipped.
	pub := filepath.Join(usersBase, "Public", "Documents", "Bitso")
	must(t, os.MkdirAll(pub, 0o755))
	must(t, os.WriteFile(filepath.Join(pub, "bitso_credentials.json"),
		[]byte(`{"x":1}`), 0o644))

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
		t.Fatalf("want 4 (api+seed+stable+otc), got %d: %+v", len(got), got)
	}

	var api, seed, stable, otc Row
	for _, r := range got {
		switch r.FilePath {
		case apiPath:
			api = r
		case seedPath:
			seed = r
		case stablePath:
			stable = r
		case otcPath:
			otc = r
		}
	}

	if api.ArtifactKind != KindAPIKey {
		t.Fatalf("api kind=%q", api.ArtifactKind)
	}
	if api.Exchange != ExchangeBitso {
		t.Fatalf("api exchange=%q", api.Exchange)
	}
	if api.PSAVClass != PSAVArgRegistered {
		t.Fatalf("api psav class=%q", api.PSAVClass)
	}
	if !api.HasAPIKey {
		t.Fatalf("api must flag key: %+v", api)
	}
	if api.APIKeyHash == "" {
		t.Fatal("api key hash must populate")
	}
	if !api.IsCredentialExposureRisk {
		t.Fatalf("readable + api-key = exposure: %+v", api)
	}

	if seed.ArtifactKind != KindWalletSeed {
		t.Fatalf("seed kind=%q", seed.ArtifactKind)
	}
	if !seed.HasWalletSeedMarker {
		t.Fatalf("seed must flag marker: %+v", seed)
	}
	if !seed.IsCredentialExposureRisk {
		t.Fatalf("readable + seed = exposure: %+v", seed)
	}

	if stable.ArtifactKind != KindStablecoinLog {
		t.Fatalf("stable kind=%q", stable.ArtifactKind)
	}
	if !stable.HasHighVolumeStablecoin {
		t.Fatalf("16M ARS USDT must flag high vol: vol=%d %+v", stable.StablecoinVolumeARSCents, stable)
	}
	if !stable.HasAfipUnreported {
		t.Fatalf("16M ARS + no AFIP marker must flag unreported: %+v", stable)
	}
	if stable.IsCredentialExposureRisk {
		t.Fatalf("0o600 must NOT flag: %+v", stable)
	}
	if stable.PeriodYYYYMM != "202506" {
		t.Fatalf("stable period=%q", stable.PeriodYYYYMM)
	}

	if otc.ArtifactKind != KindOTCP2PLog {
		t.Fatalf("otc kind=%q", otc.ArtifactKind)
	}
	if !otc.HasOTCP2PActivity {
		t.Fatalf("otc must flag p2p: %+v", otc)
	}
	if otc.OTCP2PCount < 2 {
		t.Fatalf("otc count=%d want >=2", otc.OTCP2PCount)
	}
}

func TestCollectorRespectsEnv(t *testing.T) {
	tmp := t.TempDir()
	envDir := filepath.Join(tmp, "custom-crypto")
	must(t, os.MkdirAll(envDir, 0o755))
	must(t, os.WriteFile(filepath.Join(envDir, "bitso_credentials.json"),
		[]byte(`{"api_key":"aBcDeFgHiJkLmNoPqRsTuVwX"}`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "CRYPTO_DIR" {
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
	if len(got) != 1 || got[0].ArtifactKind != KindAPIKey {
		t.Fatalf("env: %+v", got)
	}
}

func TestCollectorMissingPathsOK(t *testing.T) {
	c := &fileCollector{
		installRoots: []string{"/nope-crypto"},
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
		{FilePath: "z", ArtifactKind: KindAPIKey},
		{FilePath: "a", ArtifactKind: KindWalletSeed},
		{FilePath: "a", ArtifactKind: KindAPIKey},
	}
	SortRows(in)
	if in[0].FilePath != "a" || in[0].ArtifactKind != KindAPIKey {
		t.Fatalf("first=%+v", in[0])
	}
}

func TestHashSecret(t *testing.T) {
	a := HashSecret("abcdef")
	b := HashSecret("abcdef")
	c := HashSecret("ABCDEF")
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
