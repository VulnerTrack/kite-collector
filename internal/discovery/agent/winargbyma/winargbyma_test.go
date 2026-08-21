package winargbyma

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fixedClock at 2026-06-16 UTC — matches the reference collectors.
func fixedClock() time.Time { return time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC) }

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// -- enum strings pinned to host_arg_byma CHECK constraints -------

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindEdgeConfig), "byma-edge-config"},
		{string(KindAriesConfig), "byma-aries-config"},
		{string(KindSXConfig), "byma-sx-config"},
		{string(KindConnectAPI), "byma-connect-api"},
		{string(KindRVBlotter), "byma-rv-blotter"},
		{string(KindCEDEARPos), "byma-cedear-pos"},
		{string(KindBCV), "byma-bcv"},
		{string(KindLiquidacionT2), "byma-liquidacion-t2"},
		{string(KindCaucionRV), "byma-caucion-rv"},
		{string(KindMarketDataCache), "byma-market-data-cache"},
		{string(KindInstaller), "byma-installer"},
		{string(KindOther), "other"},
		{string(KindUnknown), "unknown"},
		{string(TerminalEdge), "edge"},
		{string(TerminalAries), "aries"},
		{string(TerminalSXBursatil), "sx-bursatil"},
		{string(TerminalConnectAPI), "connect-api"},
		{string(TerminalBackOffice), "back-office"},
		{string(TerminalOther), "other"},
		{string(TerminalUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestConstants(t *testing.T) {
	if CaucionMaxTenorDaysCap != 60 {
		t.Fatalf("CaucionMaxTenorDaysCap=%d", CaucionMaxTenorDaysCap)
	}
	if HighConcentrationPct != 50 {
		t.Fatalf("HighConcentrationPct=%d", HighConcentrationPct)
	}
	if VenueOpenHourART != 11 || VenueCloseHourART != 17 {
		t.Fatalf("venue window=%d..%d", VenueOpenHourART, VenueCloseHourART)
	}
}

func TestHashers(t *testing.T) {
	h := HashContents([]byte("hello"))
	if len(h) != 64 {
		t.Fatalf("sha256 hex len=%d", len(h))
	}
	// Known SHA-256 of "hello".
	const want = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	if h != want {
		t.Fatalf("HashContents(hello)=%q want %q", h, want)
	}
	s := HashSecret("SECRETKEY")
	if len(s) != 64 || s == "SECRETKEY" {
		t.Fatalf("HashSecret bad: %q", s)
	}
}

func TestDefaultPathSets(t *testing.T) {
	if len(DefaultInstallRoots()) == 0 {
		t.Fatal("install roots empty")
	}
	if len(DefaultUsersBases()) != 3 {
		t.Fatalf("users bases=%d", len(DefaultUsersBases()))
	}
	if len(UserBYMADirs()) == 0 {
		t.Fatal("user byma dirs empty")
	}
}

func TestIsCandidateExt(t *testing.T) {
	yes := []string{
		"x.ini", "x.cfg", "x.conf", "x.json", "x.yaml",
		"x.yml", "x.xml", "x.csv", "x.tsv", "x.dat", "x.log",
		"x.msi", "x.exe", "X.JSON",
	}
	no := []string{"x.txt", "x.pdf", "x", "x.docx"}
	for _, v := range yes {
		if !IsCandidateExt(v) {
			t.Fatalf("expected candidate ext: %q", v)
		}
	}
	for _, v := range no {
		if IsCandidateExt(v) {
			t.Fatalf("expected NOT candidate ext: %q", v)
		}
	}
}

func TestIsCandidateName(t *testing.T) {
	yes := []string{
		"byma.ini", "edge.cfg", "aries.json", "sx_bursatil.conf",
		"connect_api.json", "rv_blotter.csv", "cedear_pos.csv",
		"bcv_2025.xml", "boleto_compra.csv", "liquidacion_t2.csv",
		"caucion_rv.csv", "report_byma.dat",
	}
	no := []string{"", "factura.xml", "random.csv", "notes.log"}
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
		"":                     KindUnknown,
		"   ":                  KindUnknown,
		"setup_byma.msi":       KindInstaller,
		"edge_installer.exe":   KindInstaller,
		"randomtool.exe":       KindOther,
		"connect_api.json":     KindConnectAPI,
		"edge.ini":             KindEdgeConfig,
		"aries.cfg":            KindAriesConfig,
		"sx_bursatil.conf":     KindSXConfig,
		"rv_blotter.csv":       KindRVBlotter,
		"blotter_byma.csv":     KindRVBlotter,
		"cedear_positions.csv": KindCEDEARPos,
		"bcv_202503.xml":       KindBCV,
		"boleto-compra.csv":    KindBCV,
		"liquidacion_t2.csv":   KindLiquidacionT2,
		"t2_liquidacion.csv":   KindLiquidacionT2,
		"caucion_rv.csv":       KindCaucionRV,
		"report_byma.dat":      KindMarketDataCache,
		"notes.txt":            KindOther,
	}
	for in, want := range cases {
		if got := ArtifactKindFromName(in); got != want {
			t.Fatalf("ArtifactKindFromName(%q)=%q want %q", in, got, want)
		}
	}
}

func TestTerminalFromPath(t *testing.T) {
	cases := map[string]Terminal{
		"":                         TerminalUnknown,
		`C:\BYMA\Edge\x.ini`:       TerminalEdge,
		`C:\BYMA\Aries\x.ini`:      TerminalAries,
		`C:\BYMA\SX\x.ini`:         TerminalSXBursatil,
		`C:\BYMA\Connect\api.json`: TerminalConnectAPI,
		"/opt/byma/backoffice/x":   TerminalBackOffice,
		"/opt/byma/liquidacion/x":  TerminalBackOffice,
		"/srv/byma/report.dat":     TerminalOther,
		"/random/place/file.csv":   TerminalUnknown,
		"/x/byma_edge/y.ini":       TerminalEdge,
		"/x/sx_bursatil/y.ini":     TerminalSXBursatil,
		"/x/byma_connect/y.json":   TerminalConnectAPI,
	}
	for in, want := range cases {
		if got := TerminalFromPath(in); got != want {
			t.Fatalf("TerminalFromPath(%q)=%q want %q", in, got, want)
		}
	}
}

func TestCuitPrefixHelpers(t *testing.T) {
	if len(CuitEntityPrefixes()) != 7 {
		t.Fatalf("prefixes=%d", len(CuitEntityPrefixes()))
	}
	for _, p := range []string{"20", "23", "24", "27", "30", "33", "34"} {
		if !IsValidCuitEntityPrefix(p) {
			t.Fatalf("expected valid prefix %q", p)
		}
	}
	if IsValidCuitEntityPrefix("99") {
		t.Fatal("99 must be invalid")
	}
	for _, p := range []string{"20", "23", "24", "27"} {
		if !IsOperatorCuitPrefix(p) {
			t.Fatalf("expected operator prefix %q", p)
		}
	}
	for _, p := range []string{"30", "33", "34", "99"} {
		if IsOperatorCuitPrefix(p) {
			t.Fatalf("expected NOT operator prefix %q", p)
		}
	}
}

func TestCuitFingerprint(t *testing.T) {
	p, s := CuitFingerprint("cliente 20-12345678-9 fin")
	if p != "20" || s != "6789" {
		t.Fatalf("fingerprint=(%q,%q) want (20,6789)", p, s)
	}
	// Invalid prefix rejected.
	if p, s := CuitFingerprint("99-12345678-9"); p != "" || s != "" {
		t.Fatalf("invalid prefix should yield empty, got (%q,%q)", p, s)
	}
	// No CUIT.
	if p, s := CuitFingerprint("no cuit here"); p != "" || s != "" {
		t.Fatalf("no-match should yield empty, got (%q,%q)", p, s)
	}
}

func TestMatriculaFromText(t *testing.T) {
	if got := MatriculaFromText("broker_matricula=456"); got != "456" {
		t.Fatalf("matricula=%q want 456", got)
	}
	if got := MatriculaFromText("no matricula token"); got != "" {
		t.Fatalf("expected empty, got %q", got)
	}
}

func TestPeriodFromFilename(t *testing.T) {
	if got := PeriodFromFilename("rv_blotter_202503.csv"); got != "202503" {
		t.Fatalf("period=%q want 202503", got)
	}
	if got := PeriodFromFilename("blotter.csv"); got != "" {
		t.Fatalf("expected empty, got %q", got)
	}
	// Month 13 is invalid.
	if got := PeriodFromFilename("x_202513.csv"); got != "" {
		t.Fatalf("invalid month must not match, got %q", got)
	}
}

func TestTickerSets(t *testing.T) {
	if !IsCEDEARTicker("aapl") {
		t.Fatal("AAPL is CEDEAR (case-insensitive)")
	}
	if IsCEDEARTicker("GGAL") {
		t.Fatal("GGAL is local, not CEDEAR")
	}
	if !IsSovereignTicker("al30") {
		t.Fatal("AL30 is sovereign")
	}
	if IsSovereignTicker("AAPL") {
		t.Fatal("AAPL is not sovereign")
	}
	if len(LocalEquityTickers()) == 0 {
		t.Fatal("local equities empty")
	}
}

func TestIsMEPCCLPair(t *testing.T) {
	yes := [][2]string{{"AL30", "AL30D"}, {"GD30", "GD30C"}, {"AL30D", "AL30"}}
	for _, p := range yes {
		if !IsMEPCCLPair(p[0], p[1]) {
			t.Fatalf("expected pair: %v", p)
		}
	}
	no := [][2]string{
		{"AL30", "AL35"},   // different stems
		{"AL30D", "AL30C"}, // both USD-denominated
		{"AL30", "AL30"},   // identical
		{"GGAL", "GGALD"},  // not sovereign
		{"", "AL30"},       // empty
		{"AL30", "GD30D"},  // different stems
	}
	for _, p := range no {
		if IsMEPCCLPair(p[0], p[1]) {
			t.Fatalf("expected NOT pair: %v", p)
		}
	}
}

func TestIsAfterHoursStamp(t *testing.T) {
	cases := map[string]bool{
		"09:30":    true,  // before open
		"17:00":    true,  // at/after close
		"12:00":    false, // in-window
		"16:59":    false, // last in-window minute
		"11:00":    false, // at open
		"":         false,
		"no time":  false,
		"25:00":    false, // out-of-range hour
		"08:15:30": true,
	}
	for in, want := range cases {
		if got := IsAfterHoursStamp(in); got != want {
			t.Fatalf("IsAfterHoursStamp(%q)=%v want %v", in, got, want)
		}
	}
}

func TestIsBlotterArtifactKind(t *testing.T) {
	yes := []ArtifactKind{
		KindRVBlotter, KindCEDEARPos, KindBCV,
		KindLiquidacionT2, KindCaucionRV,
	}
	no := []ArtifactKind{
		KindEdgeConfig, KindAriesConfig, KindSXConfig,
		KindConnectAPI, KindMarketDataCache, KindInstaller, KindOther,
		KindUnknown,
	}
	for _, k := range yes {
		if !IsBlotterArtifactKind(k) {
			t.Fatalf("expected blotter kind: %q", k)
		}
	}
	for _, k := range no {
		if IsBlotterArtifactKind(k) {
			t.Fatalf("expected NOT blotter kind: %q", k)
		}
	}
}

// -- AnnotateSecurity ---------------------------------------------

func TestAnnotateSecurityExposure(t *testing.T) {
	r := Row{
		FileMode:            0o644,
		ClienteCuitPrefix:   "27",
		CEDEARTickerCount:   3,
		CaucionMaxTenorDays: 90,
		MaxPositionPct:      60,
		TradeCount:          5,
		SessionFirstSeen:    "09:30",
	}
	AnnotateSecurity(&r)
	if !r.IsWorldReadable || !r.IsGroupReadable {
		t.Fatalf("0o644 should be world+group readable: %+v", r)
	}
	if !r.HasClienteCuit || !r.HasCEDEARPosition || !r.HasCaucionLongTenor {
		t.Fatalf("cliente/cedear/caucion flags: %+v", r)
	}
	if !r.HasHighConcentration || !r.HasConcertacion || !r.IsAfterHours {
		t.Fatalf("concentration/concertacion/afterhours flags: %+v", r)
	}
	if !r.IsCredentialExposureRisk {
		t.Fatalf("readable + cliente cuit + trade body = exposure: %+v", r)
	}
}

func TestAnnotateSecurityLockedDown(t *testing.T) {
	r := Row{
		FileMode:          0o600,
		ClienteCuitPrefix: "27",
		TradeCount:        5,
	}
	AnnotateSecurity(&r)
	if r.IsWorldReadable || r.IsGroupReadable {
		t.Fatalf("0o600 must not be readable: %+v", r)
	}
	if r.IsCredentialExposureRisk {
		t.Fatal("0o600 must NOT flag exposure")
	}
}

func TestAnnotateSecurityAfterHoursLastSeen(t *testing.T) {
	r := Row{
		FileMode:          0o604, // world-readable only
		ClienteCuitPrefix: "20",
		HasAPIKeyInConfig: true,
		SessionFirstSeen:  "12:00", // in-window
		SessionLastSeen:   "19:30", // after hours
	}
	AnnotateSecurity(&r)
	if !r.IsAfterHours {
		t.Fatal("last-seen after-hours must flag")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatalf("world-readable + cuit + api key = exposure: %+v", r)
	}
}

func TestAnnotateSecurityHighTenorBoundary(t *testing.T) {
	// Exactly at the cap does NOT flag; above does.
	r := Row{CaucionMaxTenorDays: CaucionMaxTenorDaysCap, MaxPositionPct: HighConcentrationPct - 1}
	AnnotateSecurity(&r)
	if r.HasCaucionLongTenor {
		t.Fatal("at cap must NOT flag long tenor")
	}
	if r.HasHighConcentration {
		t.Fatal("below threshold must NOT flag concentration")
	}
	r2 := Row{CaucionMaxTenorDays: CaucionMaxTenorDaysCap + 1, MaxPositionPct: HighConcentrationPct}
	AnnotateSecurity(&r2)
	if !r2.HasCaucionLongTenor || !r2.HasHighConcentration {
		t.Fatalf("boundary+1 must flag both: %+v", r2)
	}
}

// -- parser: config -----------------------------------------------

func TestParseBYMAConfigFull(t *testing.T) {
	body := []byte("api_key = abcdef0123456789xyz\n" +
		"Matricula=1234\n" +
		"operador_cuit: 20-12345678-9\n" +
		"cliente_cuit: 27-98765432-1\n")
	f := ParseBYMAConfig(body)
	if !f.HasAPIKey {
		t.Fatal("expected api key detected")
	}
	if f.APIKeyHash == "" || len(f.APIKeyHash) != 64 {
		t.Fatalf("api key hash=%q", f.APIKeyHash)
	}
	if f.BrokerMatricula != "1234" {
		t.Fatalf("matricula=%q", f.BrokerMatricula)
	}
	if f.OperatorCuitRaw != "20-12345678-9" {
		t.Fatalf("operator cuit=%q", f.OperatorCuitRaw)
	}
	if f.ClienteCuitRaw != "27-98765432-1" {
		t.Fatalf("cliente cuit=%q", f.ClienteCuitRaw)
	}
}

func TestParseBYMAConfigFallbackCuit(t *testing.T) {
	// No labeled cuit → first-found heuristic populates operator raw.
	f := ParseBYMAConfig([]byte("some cuit 30-11223344-5 in body"))
	if f.OperatorCuitRaw != "30112233445" {
		t.Fatalf("fallback operator cuit=%q", f.OperatorCuitRaw)
	}
}

func TestParseBYMAConfigEmpty(t *testing.T) {
	f := ParseBYMAConfig(nil)
	if f.HasAPIKey || f.BrokerMatricula != "" {
		t.Fatalf("empty config non-zero: %+v", f)
	}
}

// -- parser: blotter XML ------------------------------------------

func TestParseBYMABlotterXML(t *testing.T) {
	body := []byte(`<blotter>
  <operacion>
    <ticker>AL30</ticker>
    <importe>1.000,00</importe>
  </operacion>
  <operacion>
    <ticker>AL30D</ticker>
    <importe>500,00</importe>
  </operacion>
</blotter>`)
	f := ParseBYMABlotter(body)
	if f.TradeCount != 2 {
		t.Fatalf("trade count=%d want 2", f.TradeCount)
	}
	if f.SovereignCount != 2 {
		t.Fatalf("sovereign count=%d want 2", f.SovereignCount)
	}
	if f.DistinctCount != 2 {
		t.Fatalf("distinct=%d want 2", f.DistinctCount)
	}
	if f.MaxNotionalCents != 100000 {
		t.Fatalf("max notional=%d want 100000", f.MaxNotionalCents)
	}
	if f.TotalCents != 150000 {
		t.Fatalf("total=%d want 150000", f.TotalCents)
	}
	if f.MaxPositionPct != 66 {
		t.Fatalf("max pct=%d want 66", f.MaxPositionPct)
	}
	if !f.HasMEPCCLArbitrage {
		t.Fatal("AL30 + AL30D must flag MEP/CCL arbitrage")
	}
}

func TestParseBYMABlotterXMLMeta(t *testing.T) {
	body := []byte(`<blotter>
  <matricula_broker>777</matricula_broker>
  <cuit_cliente>27-11112222-3</cuit_cliente>
  <cuit_operador>20-33334444-5</cuit_operador>
  <periodo>202504</periodo>
  <operacion>
    <especie>AAPL</especie>
    <monto>2000,00</monto>
    <fecha_hora>2026-04-01 12:00:00</fecha_hora>
  </operacion>
</blotter>`)
	f := ParseBYMABlotter(body)
	if f.BrokerMatricula != "777" {
		t.Fatalf("broker matricula=%q", f.BrokerMatricula)
	}
	if f.ClienteCuitRaw != "27-11112222-3" {
		t.Fatalf("cliente=%q", f.ClienteCuitRaw)
	}
	if f.OperatorCuitRaw != "20-33334444-5" {
		t.Fatalf("operator=%q", f.OperatorCuitRaw)
	}
	if f.Period != "202504" {
		t.Fatalf("period=%q", f.Period)
	}
	if f.CEDEARCount != 1 {
		t.Fatalf("cedear=%d want 1 (AAPL)", f.CEDEARCount)
	}
	if f.SessionFirstSeen != "2026-04-01 12:00:00" ||
		f.SessionLastSeen != "2026-04-01 12:00:00" {
		t.Fatalf("session seen first=%q last=%q", f.SessionFirstSeen, f.SessionLastSeen)
	}
}

func TestParseBYMABlotterXMLBroken(t *testing.T) {
	// Malformed XML starting with '<' but not valid — walk skipped,
	// remaining regex-based extraction still runs without panic.
	f := ParseBYMABlotter([]byte("<blotter><unclosed>"))
	if f.TradeCount != 0 {
		t.Fatalf("broken xml trade count=%d", f.TradeCount)
	}
}

// -- parser: blotter text -----------------------------------------

func TestParseBYMABlotterCSV(t *testing.T) {
	body := []byte("# header comment\n" +
		"2025-03-10 11:30:00 AL30 Importe=1000,00\n" +
		"2025-03-10 18:45:00 AAPL Importe=2000,00\n")
	f := ParseBYMABlotter(body)
	if f.TradeCount != 2 {
		t.Fatalf("trade count=%d want 2", f.TradeCount)
	}
	if f.CEDEARCount != 1 {
		t.Fatalf("cedear=%d want 1", f.CEDEARCount)
	}
	if f.SovereignCount != 1 {
		t.Fatalf("sovereign=%d want 1", f.SovereignCount)
	}
	if f.TotalCents != 300000 {
		t.Fatalf("total=%d want 300000", f.TotalCents)
	}
	if f.MaxNotionalCents != 200000 {
		t.Fatalf("max=%d want 200000", f.MaxNotionalCents)
	}
	if f.SessionFirstSeen != "2025-03-10 11:30:00" {
		t.Fatalf("first seen=%q", f.SessionFirstSeen)
	}
	if f.SessionLastSeen != "2025-03-10 18:45:00" {
		t.Fatalf("last seen=%q", f.SessionLastSeen)
	}
}

func TestParseBYMABlotterCaucionTenorAndMatricula(t *testing.T) {
	body := []byte("BrokerMatricula=88\n" +
		"caucion row plazo=90\n" +
		"another tenor=30\n")
	f := ParseBYMABlotter(body)
	if f.CaucionMaxTenorDays != 90 {
		t.Fatalf("caucion tenor=%d want 90 (max)", f.CaucionMaxTenorDays)
	}
	if f.BrokerMatricula != "88" {
		t.Fatalf("matricula=%q want 88", f.BrokerMatricula)
	}
}

func TestParseBYMABlotterEmptyAndBOM(t *testing.T) {
	if f := ParseBYMABlotter(nil); f.TradeCount != 0 {
		t.Fatal("nil body must be zero")
	}
	// Whitespace-only after BOM strip.
	bom := append([]byte{0xEF, 0xBB, 0xBF}, []byte("   \n\t")...)
	if f := ParseBYMABlotter(bom); f.TradeCount != 0 {
		t.Fatalf("ws-only body must be zero: %+v", f)
	}
}

func TestParseBYMABlotterStress(t *testing.T) {
	var sb strings.Builder
	for i := 0; i < 5000; i++ {
		fmt.Fprintf(&sb, "2025-03-10 12:%02d:00 AL30 Importe=100,00\n", i%60)
	}
	f := ParseBYMABlotter([]byte(sb.String()))
	if f.TradeCount != 5000 {
		t.Fatalf("stress trade count=%d want 5000", f.TradeCount)
	}
	// Only distinct ticker is AL30.
	if f.DistinctCount != 1 {
		t.Fatalf("distinct=%d want 1", f.DistinctCount)
	}
	if f.SovereignCount != 1 {
		t.Fatalf("sovereign=%d want 1", f.SovereignCount)
	}
}

// -- SortRows -----------------------------------------------------

func TestSortRowsDeterministic(t *testing.T) {
	in := []Row{
		{FilePath: "z", ArtifactKind: KindRVBlotter, PeriodYYYYMM: "202501"},
		{FilePath: "a", ArtifactKind: KindEdgeConfig, PeriodYYYYMM: "202502"},
		{FilePath: "a", ArtifactKind: KindEdgeConfig, PeriodYYYYMM: "202501"},
		{FilePath: "a", ArtifactKind: KindConnectAPI, PeriodYYYYMM: "202599"},
	}
	SortRows(in)
	// KindConnectAPI ("byma-connect-api") sorts before KindEdgeConfig
	// ("byma-edge-config"), and FilePath "a" sorts before "z".
	if in[0].FilePath != "a" || in[0].ArtifactKind != KindConnectAPI {
		t.Fatalf("first=%+v", in[0])
	}
	// Among the two edge-config "a" rows, the earlier period wins.
	if in[1].ArtifactKind != KindEdgeConfig || in[1].PeriodYYYYMM != "202501" {
		t.Fatalf("second=%+v", in[1])
	}
	if in[len(in)-1].FilePath != "z" {
		t.Fatalf("last=%+v", in[len(in)-1])
	}
}

// -- collector end-to-end -----------------------------------------

func newTestCollector(installRoots, usersBases []string, getenv func(string) string) *fileCollector {
	if getenv == nil {
		getenv = func(string) string { return "" }
	}
	return &fileCollector{
		installRoots: installRoots,
		usersBases:   usersBases,
		getenv:       getenv,
		readFile:     os.ReadFile,
		readDir:      os.ReadDir,
		statFile:     os.Stat,
		now:          fixedClock,
	}
}

func TestNewCollectorName(t *testing.T) {
	if NewCollector().Name() != "winargbyma" {
		t.Fatal("collector name")
	}
}

func TestCollectorWalksInstallTree(t *testing.T) {
	tmp := t.TempDir()
	root := filepath.Join(tmp, "BYMA")

	// Connect API config with an api key.
	connDir := filepath.Join(root, "Connect")
	must(t, os.MkdirAll(connDir, 0o755))
	connPath := filepath.Join(connDir, "connect_api.json")
	must(t, os.WriteFile(connPath,
		[]byte(`{"api_key":"abcdef0123456789xyz","cliente_cuit":"27-11112222-3"}`), 0o644))

	// RV blotter CSV.
	blotPath := filepath.Join(root, "rv_blotter_202503.csv")
	must(t, os.WriteFile(blotPath,
		[]byte("2025-03-10 09:30:00 AL30 Importe=1000,00\n"+
			"2025-03-10 09:31:00 AL30D Importe=500,00\n"), 0o644))

	// Market-data cache .dat — exercises the mergeFields early-return.
	datPath := filepath.Join(root, "report_byma.dat")
	must(t, os.WriteFile(datPath, []byte("binary-ish\x00cache"), 0o644))

	// Installer .exe — exercises skipBody hash-only path.
	exePath := filepath.Join(root, "setup_byma.exe")
	must(t, os.WriteFile(exePath, []byte("MZ fake installer"), 0o644))

	// Non-candidate file ignored.
	must(t, os.WriteFile(filepath.Join(root, "random.csv"), []byte("noise"), 0o644))

	c := newTestCollector([]string{root}, nil, nil)
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 4 {
		t.Fatalf("want 4 rows, got %d: %+v", len(got), paths(got))
	}

	byPath := map[string]Row{}
	for _, r := range got {
		byPath[r.FilePath] = r
	}

	conn := byPath[connPath]
	if conn.ArtifactKind != KindConnectAPI {
		t.Fatalf("conn kind=%q", conn.ArtifactKind)
	}
	if conn.Terminal != TerminalConnectAPI {
		t.Fatalf("conn terminal=%q", conn.Terminal)
	}
	if !conn.HasAPIKeyInConfig || conn.APIKeyHash == "" {
		t.Fatalf("conn must flag api key: %+v", conn)
	}
	if conn.ClienteCuitPrefix != "27" || conn.ClienteCuitSuffix4 != "2223" {
		t.Fatalf("conn cliente cuit=(%q,%q)", conn.ClienteCuitPrefix, conn.ClienteCuitSuffix4)
	}
	if !conn.IsRecent {
		t.Fatal("conn should be recent (mtime ~= fixed clock)")
	}
	if len(conn.FileHash) != 64 {
		t.Fatalf("conn file hash len=%d", len(conn.FileHash))
	}
	if !conn.IsCredentialExposureRisk {
		t.Fatalf("readable + cliente cuit + api key = exposure: %+v", conn)
	}

	blot := byPath[blotPath]
	if blot.ArtifactKind != KindRVBlotter {
		t.Fatalf("blotter kind=%q", blot.ArtifactKind)
	}
	if blot.Terminal != TerminalOther {
		t.Fatalf("blotter terminal=%q want other", blot.Terminal)
	}
	if blot.PeriodYYYYMM != "202503" {
		t.Fatalf("blotter period=%q", blot.PeriodYYYYMM)
	}
	if blot.TradeCount != 2 || blot.SovereignTickerCount != 2 {
		t.Fatalf("blotter counts trades=%d sov=%d", blot.TradeCount, blot.SovereignTickerCount)
	}
	if !blot.HasMEPCCLArbitrage {
		t.Fatal("blotter AL30+AL30D must flag MEP/CCL")
	}
	if !blot.HasConcertacion {
		t.Fatal("blotter with trades must flag concertacion")
	}

	dat := byPath[datPath]
	if dat.ArtifactKind != KindMarketDataCache {
		t.Fatalf("dat kind=%q", dat.ArtifactKind)
	}
	if dat.FileHash == "" {
		t.Fatal("dat should still be hashed")
	}

	exe := byPath[exePath]
	if exe.ArtifactKind != KindInstaller {
		t.Fatalf("exe kind=%q", exe.ArtifactKind)
	}
	if exe.FileHash == "" {
		t.Fatal("exe hash-only path should populate hash")
	}
}

func TestCollectorRespectsEnv(t *testing.T) {
	tmp := t.TempDir()
	envDir := filepath.Join(tmp, "custom-byma")
	must(t, os.MkdirAll(envDir, 0o755))
	must(t, os.WriteFile(filepath.Join(envDir, "edge.ini"),
		[]byte("Matricula=1234\n"), 0o644))

	c := newTestCollector(nil, nil, func(k string) string {
		if k == "BYMA_DIR" {
			return envDir
		}
		return ""
	})
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 1 || got[0].ArtifactKind != KindEdgeConfig {
		t.Fatalf("env override: %+v", got)
	}
	if got[0].BrokerMatricula != "1234" {
		t.Fatalf("edge matricula=%q", got[0].BrokerMatricula)
	}
}

func TestCollectorWalksUserProfiles(t *testing.T) {
	tmp := t.TempDir()
	base := filepath.Join(tmp, "home")

	// Real user with a BYMA doc dir.
	aliceDir := filepath.Join(base, "alice", "Documents", "BYMA")
	must(t, os.MkdirAll(aliceDir, 0o755))
	alicePath := filepath.Join(aliceDir, "caucion_rv.csv")
	must(t, os.WriteFile(alicePath, []byte("row plazo=120\n"), 0o644))

	// Pseudo-profile that must be skipped.
	pubDir := filepath.Join(base, "Public", "Documents", "BYMA")
	must(t, os.MkdirAll(pubDir, 0o755))
	must(t, os.WriteFile(filepath.Join(pubDir, "edge.ini"), []byte("x"), 0o644))

	// Dot-profile that must be skipped.
	dotDir := filepath.Join(base, ".cache", "Documents", "BYMA")
	must(t, os.MkdirAll(dotDir, 0o755))
	must(t, os.WriteFile(filepath.Join(dotDir, "aries.ini"), []byte("x"), 0o644))

	c := newTestCollector(nil, []string{base}, nil)
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 (alice only), got %d: %+v", len(got), paths(got))
	}
	if got[0].FilePath != alicePath {
		t.Fatalf("unexpected path %q", got[0].FilePath)
	}
	if got[0].UserProfile != "alice" {
		t.Fatalf("user profile=%q", got[0].UserProfile)
	}
	if got[0].CaucionMaxTenorDays != 120 || !got[0].HasCaucionLongTenor {
		t.Fatalf("caucion long tenor: %+v", got[0])
	}
}

func TestCollectorMissingPathsOK(t *testing.T) {
	c := newTestCollector([]string{"/nope-byma"}, []string{"/nope-users"}, nil)
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("missing must not error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want empty, got %d", len(got))
	}
}

func TestIsSystemPseudoProfile(t *testing.T) {
	for _, n := range []string{"Public", "default", "ALL USERS", "Shared", "Default User"} {
		if !isSystemPseudoProfile(n) {
			t.Fatalf("expected pseudo profile %q", n)
		}
	}
	if isSystemPseudoProfile("alice") {
		t.Fatal("alice is a real profile")
	}
}

func paths(rs []Row) []string {
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = r.FilePath
	}
	return out
}
