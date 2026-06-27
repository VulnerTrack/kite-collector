package winargbymadata

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindConfig), "bymadata-config"},
		{string(KindCredentials), "bymadata-credentials"},
		{string(KindFIXFASTLog), "bymadata-fix-fast-log"},
		{string(KindWSLog), "bymadata-ws-log"},
		{string(KindRESTCache), "bymadata-rest-cache"},
		{string(KindHistoricalCSV), "bymadata-historical-csv"},
		{string(KindSDKScript), "bymadata-sdk-script"},
		{string(KindTerminalConfig), "bymadata-terminal-config"},
		{string(KindInstaller), "bymadata-installer"},
		{string(KindOther), "other"},
		{string(KindUnknown), "unknown"},
		{string(AccountVendor), "vendor"},
		{string(AccountMarketMaker), "market-maker"},
		{string(AccountFCIManager), "fci-manager"},
		{string(AccountQuant), "quant"},
		{string(AccountRetailAggregator), "retail-aggregator"},
		{string(AccountDemo), "demo"},
		{string(AccountOther), "other"},
		{string(AccountUnknown), "unknown"},
		{string(TierBasic), "basic"},
		{string(TierProfesional), "profesional"},
		{string(TierInternacional), "internacional"},
		{string(TierOther), "other"},
		{string(TierUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestIsCandidateName(t *testing.T) {
	yes := []string{
		"bymadata_config.json",
		"bymadata_credentials.json",
		"bymadata_fix_fast.log",
		"bymadata-fixfast-session.log",
		"bymadata_ws.log",
		"bymadata_rest_snapshot.json",
		"bymadata_historical_GGAL.csv",
		"bymadata_sdk_demo.py",
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
		"bymadata_config.json":           KindConfig,
		"bymadata_credentials.json":      KindCredentials,
		"bymadata_api_key.json":          KindCredentials,
		"bymadata_vendor_key.json":       KindCredentials,
		"bymadata_terminal.xml":          KindTerminalConfig,
		"bymadata_fix_fast.log":          KindFIXFASTLog,
		"bymadata-fixfast-session.log":   KindFIXFASTLog,
		"bymadata_ws.log":                KindWSLog,
		"bymadata_websocket_session.log": KindWSLog,
		"bymadata_rest_snapshot.json":    KindRESTCache,
		"bymadata_snapshot_202506.json":  KindRESTCache,
		"bymadata_historical_GGAL.csv":   KindHistoricalCSV,
		"bymadata_eod_202506.csv":        KindHistoricalCSV,
		"bymadata_sdk_demo.py":           KindSDKScript,
		"bymadata_strategy.ipynb":        KindSDKScript,
		"bymadata_setup.msi":             KindInstaller,
		"":                               KindUnknown,
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
		{"licensee 27-11111111-4", "27", "1114"},
		{"vendor 30-71234567-8", "30", "5678"},
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
	if PeriodFromFilename("bymadata_fix_fast_202506.log") != "202506" {
		t.Fatal("period mismatch")
	}
	if PeriodFromFilename("random.json") != "" {
		t.Fatal("non-period must be empty")
	}
}

func TestSubscriptionTierFromBody(t *testing.T) {
	cases := map[string]SubscriptionTier{
		`{"tier":"internacional"}`: TierInternacional,
		`{"tier":"international"}`: TierInternacional,
		`feed=latam_mirror`:        TierInternacional,
		`{"tier":"profesional"}`:   TierProfesional,
		`{"feed":"depth_of_book"}`: TierProfesional,
		`{"level":"level2"}`:       TierProfesional,
		`{"tier": "basic"}`:        TierBasic,
		`{"feed":"top_of_book"}`:   TierBasic,
		`{}`:                       TierUnknown,
	}
	for in, want := range cases {
		if got := SubscriptionTierFromBody([]byte(in)); got != want {
			t.Fatalf("tier(%q)=%q want %q", in, got, want)
		}
	}
}

func TestHasDepthOfBookMarker(t *testing.T) {
	yes := [][]byte{
		[]byte(`{"feed":"depth_of_book"}`),
		[]byte(`level2 stream`),
		[]byte(`MarketDepth=full_book`),
	}
	no := [][]byte{
		[]byte(`{"feed":"top_of_book"}`),
		[]byte(``),
	}
	for _, v := range yes {
		if !HasDepthOfBookMarker(v) {
			t.Fatalf("expected depth: %q", v)
		}
	}
	for _, v := range no {
		if HasDepthOfBookMarker(v) {
			t.Fatalf("expected NOT depth: %q", v)
		}
	}
}

func TestHasInternationalMarker(t *testing.T) {
	yes := [][]byte{
		[]byte(`{"tier":"internacional"}`),
		[]byte(`feed=b3_mirror`),
	}
	no := [][]byte{
		[]byte(`{"tier":"basic"}`),
		[]byte(``),
	}
	for _, v := range yes {
		if !HasInternationalMarker(v) {
			t.Fatalf("expected international: %q", v)
		}
	}
	for _, v := range no {
		if HasInternationalMarker(v) {
			t.Fatalf("expected NOT international: %q", v)
		}
	}
}

func TestDistinctCuitsInBody(t *testing.T) {
	body := []byte(`27-11111111-4
30-71234567-8
27-11111111-4
20-99999999-1`)
	if got := DistinctCuitsInBody(body); got != 3 {
		t.Fatalf("distinct cuits=%d want 3", got)
	}
}

func TestIsCredentialKind(t *testing.T) {
	yes := []ArtifactKind{
		KindConfig, KindCredentials, KindTerminalConfig,
		KindFIXFASTLog, KindWSLog, KindRESTCache,
	}
	no := []ArtifactKind{
		KindHistoricalCSV, KindSDKScript,
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
		ArtifactKind:        KindCredentials,
		HasAPIKey:           true,
		LicenseeCuitPrefix:  "27",
		LicenseeCuitSuffix4: "1114",
		FileMode:            0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasClienteCuit {
		t.Fatal("licensee cuit must flag cliente cuit")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("readable + api key + cuit = exposure")
	}
}

func TestAnnotateLockedDown(t *testing.T) {
	r := Row{
		ArtifactKind: KindCredentials,
		HasAPIKey:    true,
		FileMode:     0o600,
	}
	AnnotateSecurity(&r)
	if r.IsCredentialExposureRisk {
		t.Fatal("0o600 must NOT flag exposure")
	}
}

func TestAnnotateHFT(t *testing.T) {
	r := Row{
		ArtifactKind:  KindWSLog,
		PeakMsgPerSec: 1500,
	}
	AnnotateSecurity(&r)
	if !r.HasHighMessageRate {
		t.Fatal("1500 msg/s must flag HFT")
	}
}

func TestAnnotateHistorical(t *testing.T) {
	r := Row{
		ArtifactKind:        KindHistoricalCSV,
		HistoricalRowsCount: 5000,
	}
	AnnotateSecurity(&r)
	if !r.HasHistoricalDownload {
		t.Fatal("5000 rows must flag historical")
	}
}

func TestAnnotateLicenseSharing(t *testing.T) {
	r := Row{
		ArtifactKind:      KindRESTCache,
		DistinctCuitCount: 3,
	}
	AnnotateSecurity(&r)
	if !r.HasLicenseSharingRisk {
		t.Fatal("3 distinct CUITs must flag license sharing")
	}
}

func TestParseBymadataCredentials(t *testing.T) {
	body := []byte(`{
  "endpoint": "https://feed.bymadata.com.ar",
  "vendor_key": "aBcDeFgHiJkLmNoPqRsTuVwX12345",
  "username": "vendor@adcap.com.ar",
  "password": "secret123",
  "tier": "profesional",
  "licensee_cuit": "30-71234567-8"
}`)
	f := ParseBymadataCredentials(body)
	if f.APIKey == "" {
		t.Fatal("api key must extract")
	}
	if f.Username == "" {
		t.Fatalf("username=%q", f.Username)
	}
	if !f.HasPassword {
		t.Fatal("password must flag")
	}
	if f.Tier != TierProfesional {
		t.Fatalf("tier=%q want profesional", f.Tier)
	}
}

func TestParseBymadataFIXFASTLog(t *testing.T) {
	body := []byte(`2026-06-15 09:30:01 FIXT.1.1 8=FIXT.1.1|9=120|35=W|49=BYMADATA|56=ADCAP|55=GGAL
2026-06-15 09:30:01 8=FIXT.1.1|9=80|35=X|49=BYMADATA|56=ADCAP|55=YPFD
2026-06-15 09:30:02 8=FIXT.1.1|9=120|35=W|49=BYMADATA|56=ADCAP|55=GGAL
`)
	f := ParseBymadataFIXFASTLog(body)
	if !f.HasFIXFASTSession {
		t.Fatal("FIX-FAST must flag")
	}
	if f.FIXSenderCompID == "" {
		t.Fatalf("sender=%q", f.FIXSenderCompID)
	}
	if f.FIXTargetCompID == "" {
		t.Fatalf("target=%q", f.FIXTargetCompID)
	}
	if f.MessageCount < 3 {
		t.Fatalf("msgs=%d", f.MessageCount)
	}
}

func TestParseBymadataWSLog(t *testing.T) {
	body := []byte(`2026-06-15 09:30:01 wss://feed.bymadata.com.ar/v1 connected
2026-06-15 09:30:01 hub_subscribe symbol=GGAL feed=depth_of_book
2026-06-15 09:30:01 md_update symbol=GGAL level1_update
2026-06-15 09:30:01 md_update symbol=GGAL level1_update
2026-06-15 09:30:02 md_update symbol=YPFD level2_update
`)
	f := ParseBymadataWSLog(body)
	if !f.HasWebsocketSession {
		t.Fatal("WS must flag")
	}
	if !f.HasDepthOfBook {
		t.Fatal("depth of book must flag")
	}
	if f.MessageCount < 3 {
		t.Fatalf("msgs=%d", f.MessageCount)
	}
}

func TestParseBymadataHistoricalCSV(t *testing.T) {
	body := []byte(`symbol,date,open,high,low,close,volume
GGAL,2026-06-15,1000.0,1010.0,995.0,1005.0,500000
YPFD,2026-06-15,2500.0,2520.0,2480.0,2510.0,300000
PAMP,2026-06-15,500.0,510.0,495.0,505.0,200000
`)
	f := ParseBymadataHistoricalCSV(body)
	if f.HistoricalRows != 3 {
		t.Fatalf("rows=%d want 3", f.HistoricalRows)
	}
	if f.DistinctSymbols != 3 {
		t.Fatalf("distinct=%d want 3", f.DistinctSymbols)
	}
}

func TestParseBymadataSDKScript(t *testing.T) {
	body := []byte(`from bymadata import BymadataClient
client = BymadataClient(vendor_key="aBcDeFgHiJkLmNoPqRsTuVwX12345", password="secret")
`)
	f := ParseBymadataSDKScript(body)
	if f.APIKey == "" {
		t.Fatal("hardcoded vendor key must extract")
	}
	if !f.HasPassword {
		t.Fatal("hardcoded password must flag")
	}
	if !HasSDKImport(body) {
		t.Fatal("sdk import must signal")
	}
}

func TestParseBymadataEmpty(t *testing.T) {
	f := ParseBymadataCredentials(nil)
	if f.APIKey != "" || f.HasPassword {
		t.Fatalf("empty must yield zero: %+v", f)
	}
}

// -- collector end-to-end -----------------------------------------

func TestCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")
	dir := filepath.Join(usersBase, "alice", "AppData", "Roaming", "Bymadata")
	must(t, os.MkdirAll(filepath.Join(dir, "sessions"), 0o755))

	credsPath := filepath.Join(dir, "bymadata_credentials.json")
	must(t, os.WriteFile(credsPath, []byte(`{
"endpoint": "https://feed.bymadata.com.ar",
"vendor_key": "aBcDeFgHiJkLmNoPqRsTuVwX12345",
"username": "vendor@adcap.com.ar",
"password": "secret123",
"tier": "profesional",
"licensee_cuit": "30-71234567-8"
}`), 0o644))

	fixPath := filepath.Join(dir, "sessions", "bymadata_fix_fast_202506.log")
	var fixBody []byte
	fixBody = append(fixBody, []byte(`2026-06-15 09:30:01 8=FIXT.1.1|9=120|35=W|49=BYMADATA|56=ADCAP|55=GGAL`+"\n")...)
	for i := 0; i < 1500; i++ {
		fixBody = append(fixBody, []byte(`2026-06-15 09:30:02 8=FIXT.1.1|35=W|49=BYMADATA|56=ADCAP|55=GGAL`+"\n")...)
	}
	must(t, os.WriteFile(fixPath, fixBody, 0o644))

	histPath := filepath.Join(dir, "bymadata_historical_GGAL.csv")
	histBody := []byte("symbol,date,close\n")
	for i := 0; i < 1500; i++ {
		histBody = append(histBody, []byte("GGAL,2026-06-15,1005.0\n")...)
	}
	must(t, os.WriteFile(histPath, histBody, 0o644))

	// Random ignored.
	must(t, os.WriteFile(filepath.Join(dir, "random.txt"),
		[]byte(`nope`), 0o644))

	// Public skipped.
	pub := filepath.Join(usersBase, "Public", "AppData", "Roaming", "Bymadata")
	must(t, os.MkdirAll(pub, 0o755))
	must(t, os.WriteFile(filepath.Join(pub, "bymadata_credentials.json"),
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
	if len(got) != 3 {
		t.Fatalf("want 3 (creds+fix+hist), got %d: %+v", len(got), got)
	}

	var creds, fix, hist Row
	for _, r := range got {
		switch r.FilePath {
		case credsPath:
			creds = r
		case fixPath:
			fix = r
		case histPath:
			hist = r
		}
	}

	if creds.ArtifactKind != KindCredentials {
		t.Fatalf("creds kind=%q", creds.ArtifactKind)
	}
	if !creds.HasAPIKey {
		t.Fatalf("creds must flag api key: %+v", creds)
	}
	if !creds.HasPasswordInConfig {
		t.Fatalf("creds must flag password: %+v", creds)
	}
	if creds.SubscriptionTier != TierProfesional {
		t.Fatalf("creds tier=%q want profesional", creds.SubscriptionTier)
	}
	if !creds.IsCredentialExposureRisk {
		t.Fatalf("readable + api key = exposure: %+v", creds)
	}

	if fix.ArtifactKind != KindFIXFASTLog {
		t.Fatalf("fix kind=%q", fix.ArtifactKind)
	}
	if !fix.HasFIXFASTSession {
		t.Fatalf("fix must flag FIX-FAST: %+v", fix)
	}
	if !fix.HasHighMessageRate {
		t.Fatalf("1500 msgs in 1 sec must flag HFT: peak=%d", fix.PeakMsgPerSec)
	}

	if hist.ArtifactKind != KindHistoricalCSV {
		t.Fatalf("hist kind=%q", hist.ArtifactKind)
	}
	if !hist.HasHistoricalDownload {
		t.Fatalf("hist must flag download: rows=%d", hist.HistoricalRowsCount)
	}
}

func TestCollectorRespectsEnv(t *testing.T) {
	tmp := t.TempDir()
	envDir := filepath.Join(tmp, "custom-bymadata")
	must(t, os.MkdirAll(envDir, 0o755))
	must(t, os.WriteFile(filepath.Join(envDir, "bymadata_credentials.json"),
		[]byte(`{"vendor_key":"abcdefghijklmnopqrst","tier":"basic"}`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "BYMADATA_DIR" {
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
	if len(got) != 1 || got[0].ArtifactKind != KindCredentials {
		t.Fatalf("env: %+v", got)
	}
	if got[0].SubscriptionTier != TierBasic {
		t.Fatalf("tier=%q", got[0].SubscriptionTier)
	}
}

func TestCollectorMissingPathsOK(t *testing.T) {
	c := &fileCollector{
		installRoots: []string{"/nope-bymadata"},
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
		{FilePath: "z", ArtifactKind: KindCredentials},
		{FilePath: "a", ArtifactKind: KindFIXFASTLog},
		{FilePath: "a", ArtifactKind: KindCredentials},
	}
	SortRows(in)
	if in[0].FilePath != "a" || in[0].ArtifactKind != KindCredentials {
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
	if a != c {
		t.Fatal("hash must be case-insensitive")
	}
	if len(a) != 64 {
		t.Fatalf("hash len=%d", len(a))
	}
}

func TestClassifyAccount(t *testing.T) {
	if classifyAccount(KindFIXFASTLog, BymadataFields{HasFIXFASTSession: true}) != AccountVendor {
		t.Fatal("vendor")
	}
	if classifyAccount(KindWSLog, BymadataFields{HasWebsocketSession: true, HasDepthOfBook: true}) != AccountMarketMaker {
		t.Fatal("market-maker")
	}
	if classifyAccount(KindWSLog, BymadataFields{HasInternational: true}) != AccountFCIManager {
		t.Fatal("fci-manager")
	}
	if classifyAccount(KindSDKScript, BymadataFields{}) != AccountQuant {
		t.Fatal("quant")
	}
	if classifyAccount(KindWSLog, BymadataFields{HasWebsocketSession: true}) != AccountRetailAggregator {
		t.Fatal("retail-aggregator")
	}
	if classifyAccount(KindConfig, BymadataFields{}) != AccountUnknown {
		t.Fatal("unknown")
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
