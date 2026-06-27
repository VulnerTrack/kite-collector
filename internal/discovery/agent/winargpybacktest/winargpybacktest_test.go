package winargpybacktest

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindVectorbtPortfolio), "pybt-vectorbt-portfolio"},
		{string(KindBacktraderOutput), "pybt-backtrader-output"},
		{string(KindZiplineResult), "pybt-zipline-result"},
		{string(KindFreqtradeResult), "pybt-freqtrade-result"},
		{string(KindQuantstatsTearsheet), "pybt-quantstats-tearsheet"},
		{string(KindBTStrategy), "pybt-bt-strategy"},
		{string(KindOHLCVHistory), "pybt-ohlcv-history"},
		{string(KindEquityCurve), "pybt-equity-curve"},
		{string(KindTradeLog), "pybt-trade-log"},
		{string(KindParamsGrid), "pybt-params-grid"},
		{string(KindStrategyScript), "pybt-strategy-script"},
		{string(KindInstaller), "pybt-installer"},
		{string(KindOther), "other"},
		{string(KindUnknown), "unknown"},
		{string(FrameworkVectorbt), "vectorbt"},
		{string(FrameworkBacktrader), "backtrader"},
		{string(FrameworkZipline), "zipline"},
		{string(FrameworkFreqtrade), "freqtrade"},
		{string(FrameworkQuantstats), "quantstats"},
		{string(FrameworkBT), "bt"},
		{string(FrameworkCustom), "custom"},
		{string(FrameworkOther), "other"},
		{string(FrameworkUnknown), "unknown"},
		{string(ClassEquity), "equity"},
		{string(ClassBonds), "bonds"},
		{string(ClassFutures), "futures"},
		{string(ClassFX), "fx"},
		{string(ClassCrypto), "crypto"},
		{string(ClassMixed), "mixed"},
		{string(ClassOther), "other"},
		{string(ClassUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestIsCandidateName(t *testing.T) {
	yes := []string{
		"backtest_vectorbt_GGAL.pkl",
		"vectorbt_portfolio.pkl",
		"backtrader_equity.csv",
		"zipline_perf.pickle",
		"freqtrade_result.json",
		"quantstats_tearsheet.html",
		"tear_sheet_GGAL.html",
		"bt_strategy_001.pkl",
		"ohlcv_GGAL.parquet",
		"equity_curve_GGAL.csv",
		"tradelog_GGAL.txt",
		"params_grid_GGAL.csv",
		"strategy_backtest.py",
		"my_quant_algo.ipynb",
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
		"vectorbt_portfolio.pkl":    KindVectorbtPortfolio,
		"backtrader_equity.csv":     KindBacktraderOutput,
		"backtrader_trades.txt":     KindBacktraderOutput,
		"zipline_perf.pickle":       KindZiplineResult,
		"freqtrade_result.json":     KindFreqtradeResult,
		"quantstats_tearsheet.html": KindQuantstatsTearsheet,
		"tear_sheet_GGAL.html":      KindQuantstatsTearsheet,
		"bt_strategy_001.pkl":       KindBTStrategy,
		"ohlcv_GGAL.parquet":        KindOHLCVHistory,
		"equity_curve_GGAL.csv":     KindEquityCurve,
		"tradelog_GGAL.txt":         KindTradeLog,
		"params_grid_GGAL.csv":      KindParamsGrid,
		"strategy_backtest.py":      KindStrategyScript,
		"my_quant_algo.ipynb":       KindStrategyScript,
		"vectorbt_v1_installer.msi": KindInstaller,
		"":                          KindUnknown,
	}
	for in, want := range cases {
		if got := ArtifactKindFromName(in); got != want {
			t.Fatalf("ArtifactKindFromName(%q)=%q want %q", in, got, want)
		}
	}
}

func TestFrameworkFromPath(t *testing.T) {
	cases := map[string]Framework{
		`C:\Backtests\vectorbt\portfolio.pkl`:         FrameworkVectorbt,
		`/home/alice/.cache/vectorbt/p.pkl`:           FrameworkVectorbt,
		`/home/alice/Documents/Backtests/backtrader/`: FrameworkBacktrader,
		`/home/alice/.zipline/quotes/`:                FrameworkZipline,
		`/home/alice/.config/freqtrade/result.json`:   FrameworkFreqtrade,
		`/home/alice/Documents/tearsheet.html`:        FrameworkQuantstats,
		`/home/alice/Backtests/bt_strategy.pkl`:       FrameworkBT,
		`/home/alice/Backtests/custom.pkl`:            FrameworkCustom,
		`/home/alice/Random/file.txt`:                 FrameworkUnknown,
		"":                                            FrameworkUnknown,
	}
	for in, want := range cases {
		if got := FrameworkFromPath(in); got != want {
			t.Fatalf("FrameworkFromPath(%q)=%q want %q", in, got, want)
		}
	}
}

func TestIsArgentineTicker(t *testing.T) {
	yes := []string{"GGAL", "YPFD", "AL30", "AL30D", "GD30", "LELIQ", "ggal"}
	no := []string{"AAPL", "TSLA", "BTC", "ETH", "", "FOO"}
	for _, v := range yes {
		if !IsArgentineTicker(v) {
			t.Fatalf("expected ARG ticker: %q", v)
		}
	}
	for _, v := range no {
		if IsArgentineTicker(v) {
			t.Fatalf("expected NOT ARG ticker: %q", v)
		}
	}
}

func TestStrategyClassFromTickers(t *testing.T) {
	eq := map[string]struct{}{"GGAL": {}}
	bd := map[string]struct{}{"AL30": {}}
	fut := map[string]struct{}{"DLR/MAR26": {}}
	mix := map[string]struct{}{"GGAL": {}, "AL30": {}}
	cases := []struct {
		in   map[string]struct{}
		want StrategyClass
	}{
		{eq, ClassEquity},
		{bd, ClassBonds},
		{fut, ClassFutures},
		{mix, ClassMixed},
		{map[string]struct{}{}, ClassUnknown},
	}
	for _, c := range cases {
		if got := StrategyClassFromTickers(c.in); got != c.want {
			t.Fatalf("StrategyClassFromTickers(%v)=%q want %q", c.in, got, c.want)
		}
	}
}

func TestPeriodFromFilename(t *testing.T) {
	if PeriodFromFilename("backtest_202506.json") != "202506" {
		t.Fatal("period mismatch")
	}
	if PeriodFromFilename("random.json") != "" {
		t.Fatal("non-period must be empty")
	}
}

func TestIsCompiledKind(t *testing.T) {
	yes := []ArtifactKind{
		KindVectorbtPortfolio, KindZiplineResult,
		KindBTStrategy, KindOHLCVHistory,
	}
	no := []ArtifactKind{
		KindBacktraderOutput, KindFreqtradeResult,
		KindQuantstatsTearsheet, KindEquityCurve, KindTradeLog,
		KindParamsGrid, KindStrategyScript, KindInstaller,
		KindOther, KindUnknown,
	}
	for _, k := range yes {
		if !IsCompiledKind(k) {
			t.Fatalf("expected compiled: %q", k)
		}
	}
	for _, k := range no {
		if IsCompiledKind(k) {
			t.Fatalf("expected NOT compiled: %q", k)
		}
	}
}

// -- AnnotateSecurity ---------------------------------------------

func TestAnnotateOverfitSharpe(t *testing.T) {
	r := Row{
		ArtifactKind: KindFreqtradeResult,
		SharpeX100:   600,
		FileMode:     0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasOverfitSharpe {
		t.Fatal("sharpe 6 must flag overfit")
	}
}

func TestAnnotateExtremeDrawdown(t *testing.T) {
	r := Row{
		ArtifactKind:   KindFreqtradeResult,
		MaxDrawdownPct: 75,
		FileMode:       0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasExtremeDrawdown {
		t.Fatal("75% drawdown must flag")
	}
}

func TestAnnotateUnrealisticReturns(t *testing.T) {
	r := Row{
		ArtifactKind:    KindFreqtradeResult,
		AnnualReturnPct: 250,
		FileMode:        0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasUnrealisticReturns {
		t.Fatal("250%/y must flag unrealistic")
	}
}

func TestAnnotateArgentineTickers(t *testing.T) {
	r := Row{
		ArtifactKind:         KindFreqtradeResult,
		ArgentineTickerCount: 3,
		FileMode:             0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasArgentineTickers {
		t.Fatal("ARG ticker count > 0 must flag")
	}
}

func TestAnnotateCompiledStrategy(t *testing.T) {
	r := Row{
		ArtifactKind: KindBTStrategy,
		FileMode:     0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasCompiledStrategy {
		t.Fatal(".pkl strategy must flag compiled")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("readable + compiled = exposure")
	}
}

func TestAnnotateAPIKeyExposure(t *testing.T) {
	r := Row{
		ArtifactKind:    KindStrategyScript,
		HasAPIKeyInCode: true,
		FileMode:        0o644,
	}
	AnnotateSecurity(&r)
	if !r.IsCredentialExposureRisk {
		t.Fatal("readable + api-key = exposure")
	}
}

func TestAnnotateLockedDownClean(t *testing.T) {
	r := Row{
		ArtifactKind:    KindStrategyScript,
		HasAPIKeyInCode: true,
		FileMode:        0o600,
	}
	AnnotateSecurity(&r)
	if r.IsCredentialExposureRisk {
		t.Fatal("0o600 must NOT flag exposure")
	}
}

// -- ParsePyBacktestArtifact --------------------------------------

func TestParsePyBacktestArtifactFreqtrade(t *testing.T) {
	body := []byte(`{
  "strategy_name": "GGAL_momentum",
  "sharpe_ratio": 6.5,
  "annual_return": 1.20,
  "max_drawdown": 0.65,
  "n_trades": 250,
  "pairs": ["GGAL/ARS", "YPFD/ARS", "AL30/ARS"]
}`)
	f := ParsePyBacktestArtifact(body)
	if f.SharpeX100 != 650 {
		t.Fatalf("sharpe=%d want 650", f.SharpeX100)
	}
	if f.AnnualReturnPct != 120 {
		t.Fatalf("annual=%d want 120", f.AnnualReturnPct)
	}
	if f.MaxDrawdownPct != 65 {
		t.Fatalf("dd=%d want 65", f.MaxDrawdownPct)
	}
	if f.TradeCount != 250 {
		t.Fatalf("trades=%d", f.TradeCount)
	}
	if f.StrategyName != "GGAL_momentum" {
		t.Fatalf("name=%q", f.StrategyName)
	}
	if len(f.ArgentineTickers) < 3 {
		t.Fatalf("ARG tickers=%d want >=3 (%+v)", len(f.ArgentineTickers), f.ArgentineTickers)
	}
}

func TestParsePyBacktestArtifactLookahead(t *testing.T) {
	body := []byte(`# strategy.py
import pandas as pd
data['next_open'] = data['open'].shift(-1)
signal = data['close'] < data['next_open']
`)
	f := ParsePyBacktestArtifact(body)
	if !f.HasLookaheadBias {
		t.Fatal("shift(-1) must flag lookahead")
	}
}

func TestParsePyBacktestArtifactAPIKey(t *testing.T) {
	body := []byte(`# strategy.py
API_KEY = "abcdef1234567890ABCDEFGHIJKLMNOP"
`)
	f := ParsePyBacktestArtifact(body)
	if f.APIKey == "" {
		t.Fatal("api key must extract")
	}
}

func TestParsePyBacktestArtifactIpynbSecret(t *testing.T) {
	body := []byte(`{
  "cells": [
    {"cell_type":"code","source":"\"api_key\": \"abcdef1234567890ABCDEFGH\""}
  ]
}`)
	f := ParsePyBacktestArtifact(body)
	if !f.HasIpynbWithSecrets {
		t.Fatal("ipynb secret must flag")
	}
}

func TestParsePyBacktestArtifactEmpty(t *testing.T) {
	f := ParsePyBacktestArtifact(nil)
	if f.SharpeX100 != 0 || f.TradeCount != 0 {
		t.Fatalf("empty must yield zero: %+v", f)
	}
}

// -- collector end-to-end -----------------------------------------

func TestCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")
	dir := filepath.Join(usersBase, "alice", "Documents", "Backtests")
	must(t, os.MkdirAll(dir, 0o755))

	// Freqtrade result with overfit + ARG tickers.
	fqPath := filepath.Join(dir, "freqtrade_GGAL_202506.json")
	must(t, os.WriteFile(fqPath, []byte(`{
  "strategy_name": "GGAL_momentum",
  "sharpe_ratio": 6.5,
  "annual_return": 1.20,
  "max_drawdown": 0.65,
  "n_trades": 250,
  "pairs": ["GGAL/ARS", "YPFD/ARS", "AL30/ARS"]
}`), 0o644))

	// Strategy script with lookahead bias + API key.
	stratPath := filepath.Join(dir, "strategy_backtest_GGAL.py")
	must(t, os.WriteFile(stratPath, []byte(`# strategy.py
import pandas as pd
API_KEY = "abcdef1234567890ABCDEFGHIJKLMNOP"
data['next_open'] = data['open'].shift(-1)
`), 0o644))

	// Compiled vectorbt portfolio (no body parse).
	pklPath := filepath.Join(dir, "vectorbt_portfolio.pkl")
	must(t, os.WriteFile(pklPath, []byte(`PICKLE-binary-blob`), 0o644))

	// Quantstats tear sheet HTML.
	tsPath := filepath.Join(dir, "tear_sheet_GGAL.html")
	must(t, os.WriteFile(tsPath, []byte(`<html><body>
Strategy: GGAL_momentum
Sharpe Ratio: 6.5
Max Drawdown: 65%
Annual Return: 120%
</body></html>`), 0o644))

	// Random ignored.
	must(t, os.WriteFile(filepath.Join(dir, "random.txt"),
		[]byte(`nope`), 0o644))

	// Public skipped.
	pub := filepath.Join(usersBase, "Public", "Documents", "Backtests")
	must(t, os.MkdirAll(pub, 0o755))
	must(t, os.WriteFile(filepath.Join(pub, "freqtrade_skip.json"),
		[]byte(`{}`), 0o644))

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
		t.Fatalf("want 4 (fq+strat+pkl+ts), got %d: %+v", len(got), got)
	}

	var fq, strat, pkl, ts Row
	for _, r := range got {
		switch r.FilePath {
		case fqPath:
			fq = r
		case stratPath:
			strat = r
		case pklPath:
			pkl = r
		case tsPath:
			ts = r
		}
	}

	if fq.ArtifactKind != KindFreqtradeResult {
		t.Fatalf("fq kind=%q", fq.ArtifactKind)
	}
	if fq.Framework != FrameworkFreqtrade {
		t.Fatalf("fq framework=%q", fq.Framework)
	}
	if !fq.HasOverfitSharpe {
		t.Fatalf("fq sharpe 6.5 must flag: %+v", fq)
	}
	if !fq.HasExtremeDrawdown {
		t.Fatalf("fq 65%% drawdown must flag: %+v", fq)
	}
	if !fq.HasUnrealisticReturns {
		t.Fatalf("fq 120%%/y must flag: %+v", fq)
	}
	if !fq.HasArgentineTickers {
		t.Fatalf("fq must flag ARG tickers: %+v", fq)
	}
	if fq.StrategyName != "GGAL_momentum" {
		t.Fatalf("fq name=%q", fq.StrategyName)
	}
	if fq.StrategyClass != ClassMixed {
		t.Fatalf("fq class=%q want mixed (GGAL equity + AL30 bond)", fq.StrategyClass)
	}

	if strat.ArtifactKind != KindStrategyScript {
		t.Fatalf("strat kind=%q", strat.ArtifactKind)
	}
	if !strat.HasLookaheadBias {
		t.Fatalf("strat must flag lookahead: %+v", strat)
	}
	if !strat.HasAPIKeyInCode {
		t.Fatalf("strat must flag api key: %+v", strat)
	}
	if strat.APIKeyHash == "" {
		t.Fatal("strat api key hash must populate")
	}
	if !strat.IsCredentialExposureRisk {
		t.Fatalf("readable + api-key = exposure: %+v", strat)
	}

	if pkl.ArtifactKind != KindVectorbtPortfolio {
		t.Fatalf("pkl kind=%q", pkl.ArtifactKind)
	}
	if !pkl.HasCompiledStrategy {
		t.Fatalf("pkl must flag compiled: %+v", pkl)
	}

	if ts.ArtifactKind != KindQuantstatsTearsheet {
		t.Fatalf("ts kind=%q", ts.ArtifactKind)
	}
	if ts.Framework != FrameworkQuantstats {
		t.Fatalf("ts framework=%q", ts.Framework)
	}
}

func TestCollectorRespectsEnv(t *testing.T) {
	tmp := t.TempDir()
	envDir := filepath.Join(tmp, "custom-pybt")
	must(t, os.MkdirAll(envDir, 0o755))
	must(t, os.WriteFile(filepath.Join(envDir, "freqtrade_result.json"),
		[]byte(`{"strategy_name":"X","sharpe_ratio":1.0}`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "PYBACKTEST_DIR" {
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
	if len(got) != 1 || got[0].ArtifactKind != KindFreqtradeResult {
		t.Fatalf("env: %+v", got)
	}
}

func TestCollectorMissingPathsOK(t *testing.T) {
	c := &fileCollector{
		installRoots: []string{"/nope-pybt"},
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
		{FilePath: "z", ArtifactKind: KindFreqtradeResult},
		{FilePath: "a", ArtifactKind: KindFreqtradeResult},
		{FilePath: "a", ArtifactKind: KindBTStrategy},
	}
	SortRows(in)
	// "pybt-bt-strategy" sorts before "pybt-freqtrade-result".
	if in[0].FilePath != "a" || in[0].ArtifactKind != KindBTStrategy {
		t.Fatalf("first=%+v", in[0])
	}
}

func TestHashSecret(t *testing.T) {
	a := HashSecret("abc")
	b := HashSecret("abc")
	c := HashSecret("ABC")
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
