package winargfgs

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindCarteraFGS), "fgs-cartera"},
		{string(KindLICRecord), "fgs-lic-record"},
		{string(KindDirectorioActa), "fgs-directorio-acta"},
		{string(KindComiteActa), "fgs-comite-acta"},
		{string(KindPrimaryAuctionBid), "fgs-primary-auction-bid"},
		{string(KindVotingRecord), "fgs-voting-record"},
		{string(KindSIPAPensionRecord), "fgs-sipa-pension-record"},
		{string(RoleDirector), "director"},
		{string(RoleComiteInversiones), "comite-inversiones"},
		{string(RoleTesoreria), "tesoreria"},
		{string(RoleAnalistaEquity), "analista-equity"},
		{string(PortfolioLIC), "lic"},
		{string(PortfolioARSovBond), "ar-sovereign-bond"},
		{string(WindowBCRAPrimary), "bcra-primary"},
		{string(WindowANSESLIC), "anses-lic"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestIsCandidateName(t *testing.T) {
	yes := []string{
		"cartera_fgs_202606.xlsx",
		"lic_2024-001.xml",
		"letras_intransferibles_2024.xml",
		"directorio_acta_15.pdf",
		"comite_inversiones_202606.pdf",
		"lineamientos_2026.pdf",
		"subasta_bid_001.xml",
		"auction_result_001.xml",
		"custodia_202606.pdf",
		"votacion_asamblea_GGAL.pdf",
		"sipa_202606.csv",
		"fgs_receipt_202606.xml",
		"fgs_config.ini",
		"anses_sustentabilidad.json",
	}
	no := []string{"", "factura.xml", "random.bin", "report.pdf", "notes.txt"}
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
		"cartera_fgs_202606.xlsx":         KindCarteraFGS,
		"lic_2024-001.xml":                KindLICRecord,
		"letras_intransferibles_2024.xml": KindLICRecord,
		"directorio_acta_15.pdf":          KindDirectorioActa,
		"comite_inversiones_202606.pdf":   KindComiteActa,
		"lineamientos_2026.pdf":           KindLineamientosDoc,
		"subasta_bid_001.xml":             KindPrimaryAuctionBid,
		"auction_result_001.xml":          KindPrimaryAuctionResult,
		"custodia_202606.pdf":             KindCustodiaRecord,
		"votacion_asamblea_GGAL.pdf":      KindVotingRecord,
		"sipa_202606.csv":                 KindSIPAPensionRecord,
		"fgs_receipt_202606.xml":          KindFilingReceipt,
		"fgs_config.ini":                  KindConfig,
		"credentials.json":                KindCredentials,
		"fgs_setup.msi":                   KindInstaller,
		"":                                KindUnknown,
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
		{"emisora 30-71234567-8", "30", "5678"},
		{"individuo 27-11111111-4", "27", "1114"},
		{"no cuit", "", ""},
	}
	for _, c := range cases {
		gotP, gotS := CuitFingerprint(c.in)
		if gotP != c.pfx || gotS != c.sfx4 {
			t.Fatalf("CuitFingerprint(%q)=(%q,%q) want (%q,%q)",
				c.in, gotP, gotS, c.pfx, c.sfx4)
		}
	}
}

func TestCuilFingerprint(t *testing.T) {
	cases := []struct {
		in, pfx, sfx4 string
	}{
		{"pensionado 27-11111111-4", "27", "1114"},
		// Entity prefix 30 rejected for CUIL.
		{"emisora 30-71234567-8", "", ""},
	}
	for _, c := range cases {
		gotP, gotS := CuilFingerprint(c.in)
		if gotP != c.pfx || gotS != c.sfx4 {
			t.Fatalf("CuilFingerprint(%q)=(%q,%q) want (%q,%q)",
				c.in, gotP, gotS, c.pfx, c.sfx4)
		}
	}
}

func TestPanelLiderStem(t *testing.T) {
	yes := []string{"GGAL", "YPFD", "PAMP", "ALUA"}
	no := []string{"", "AAPL", "AL30"}
	for _, v := range yes {
		if !IsPanelLiderStem(v) {
			t.Fatalf("expected panel líder: %q", v)
		}
	}
	for _, v := range no {
		if IsPanelLiderStem(v) {
			t.Fatalf("expected NOT panel líder: %q", v)
		}
	}
}

func TestARSovereignBondStem(t *testing.T) {
	yes := []string{"AL30", "GD30", "TX26", "PARP"}
	no := []string{"", "AAPL", "GGAL"}
	for _, v := range yes {
		if !IsARSovereignBondStem(v) {
			t.Fatalf("expected sov bond: %q", v)
		}
	}
	for _, v := range no {
		if IsARSovereignBondStem(v) {
			t.Fatalf("expected NOT sov bond: %q", v)
		}
	}
}

func TestIsCredentialKind(t *testing.T) {
	yes := []ArtifactKind{
		KindCarteraFGS, KindLICRecord,
		KindDirectorioActa, KindComiteActa,
		KindLineamientosDoc,
		KindPrimaryAuctionBid, KindPrimaryAuctionResult,
		KindCustodiaRecord, KindVotingRecord,
		KindSIPAPensionRecord, KindFilingReceipt,
		KindConfig, KindCredentials,
	}
	for _, k := range yes {
		if !IsCredentialKind(k) {
			t.Fatalf("expected cred kind: %q", k)
		}
	}
	for _, k := range []ArtifactKind{KindInstaller, KindOther, KindUnknown} {
		if IsCredentialKind(k) {
			t.Fatalf("expected NOT cred kind: %q", k)
		}
	}
}

func TestIsMarketMovingKind(t *testing.T) {
	yes := []ArtifactKind{
		KindDirectorioActa, KindComiteActa,
		KindPrimaryAuctionBid, KindVotingRecord,
	}
	for _, k := range yes {
		if !IsMarketMovingKind(k) {
			t.Fatalf("expected market-moving kind: %q", k)
		}
	}
	no := []ArtifactKind{
		KindCarteraFGS, KindLICRecord,
		KindLineamientosDoc, KindPrimaryAuctionResult,
		KindCustodiaRecord, KindSIPAPensionRecord,
		KindFilingReceipt,
		KindConfig, KindCredentials,
		KindInstaller, KindOther, KindUnknown,
	}
	for _, k := range no {
		if IsMarketMovingKind(k) {
			t.Fatalf("expected NOT market-moving kind: %q", k)
		}
	}
}

func TestAnnotateExposure(t *testing.T) {
	r := Row{
		ArtifactKind:        KindCarteraFGS,
		HasPasswordInConfig: true,
		ClienteCuitPrefix:   "30",
		ClienteCuitSuffix4:  "5678",
		FileMode:            0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasClienteCuit {
		t.Fatal("cliente cuit must flag")
	}
	if !r.HasCarteraFGS {
		t.Fatal("cartera kind must auto-flag")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("readable + password + cliente = exposure")
	}
}

func TestAnnotateMarketMovingInfo(t *testing.T) {
	r := Row{
		ArtifactKind: KindDirectorioActa,
		FileMode:     0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasDirectorioActa {
		t.Fatal("directorio kind must auto-flag")
	}
	if !r.IsMarketMovingInfoRisk {
		t.Fatal("readable + directorio = market-moving info risk")
	}
}

func TestAnnotatePreDisclosureRisk(t *testing.T) {
	r := Row{
		ArtifactKind:           KindDirectorioActa,
		PanelLiderHoldingCount: PanelLiderHoldingThreshold + 1,
	}
	AnnotateSecurity(&r)
	if !r.HasBYMAPanelLiderHolding {
		t.Fatal("> 3 panel líder must flag BYMA holding")
	}
	if !r.HasPreDisclosureRisk {
		t.Fatal("acta + panel líder = pre-disclosure risk")
	}
}

func TestAnnotateLICAuto(t *testing.T) {
	r := Row{ArtifactKind: KindLICRecord}
	AnnotateSecurity(&r)
	if !r.HasLICRecord {
		t.Fatal("LIC kind must flag")
	}
}

func TestAnnotateInstitutionalPortfolio(t *testing.T) {
	r := Row{
		ArtifactKind:              KindCarteraFGS,
		PortfolioInstrumentsCount: InstitutionalPortfolioInstrumentsThreshold + 1,
	}
	AnnotateSecurity(&r)
	if !r.HasInstitutionalPortfolio {
		t.Fatal("> 100 instruments must flag institutional portfolio")
	}
}

func TestParseCartera(t *testing.T) {
	body := []byte(`<?xml version="1.0"?>
<FGS_Cartera>
  <Position><especie>AL30</especie></Position>
  <Position><especie>GD30</especie></Position>
  <Position><especie>GGAL</especie></Position>
  <Position><especie>YPFD</especie></Position>
  <Position><especie>PAMP</especie></Position>
  <Position><especie>ALUA</especie></Position>
  <Position><especie>BMA</especie></Position>
  <emisora_cuit>30-71234567-8</emisora_cuit>
</FGS_Cartera>`)
	f := ParseCartera(body)
	if f.PortfolioInstrumentsCount != 7 {
		t.Fatalf("instruments=%d want 7", f.PortfolioInstrumentsCount)
	}
	if f.SovBondHoldingCount < 2 {
		t.Fatalf("sov=%d want >=2 (AL30+GD30)", f.SovBondHoldingCount)
	}
	if f.PanelLiderHoldingCount < 5 {
		t.Fatalf("panel líder=%d want >=5 (GGAL+YPFD+PAMP+ALUA+BMA)", f.PanelLiderHoldingCount)
	}
	if f.ClienteCuitRaw == "" {
		t.Fatal("cuit must extract")
	}
}

func TestParseLICRecord(t *testing.T) {
	body := []byte(`{
  "lic_series": "LIC2024-001",
  "lic_face_value": "1000000000000",
  "issuer": "Tesoro Nacional"
}`)
	f := ParseLICRecord(body)
	if f.FGSSeriesCode != "LIC2024-001" {
		t.Fatalf("series=%q", f.FGSSeriesCode)
	}
	if f.LICFaceValueARSMillions != 1_000_000 {
		t.Fatalf("face=%d want 1M millions (1T ARS)", f.LICFaceValueARSMillions)
	}
}

func TestParsePrimaryAuctionBid(t *testing.T) {
	body := []byte(`<?xml version="1.0"?>
<AuctionBid>
  <auction_id>BCRA-2026-Q2-015</auction_id>
  <bid_amount>500000000000</bid_amount>
  <auction_window>BCRA</auction_window>
</AuctionBid>`)
	f := ParsePrimaryAuctionBid(body)
	if f.AuctionID != "BCRA-2026-Q2-015" {
		t.Fatalf("auction=%q", f.AuctionID)
	}
	if f.AuctionBidAmountARSMillions != 500_000 {
		t.Fatalf("bid=%d want 500k M ARS (500B)", f.AuctionBidAmountARSMillions)
	}
	if f.AuctionWindow != WindowBCRAPrimary {
		t.Fatalf("window=%q want bcra-primary", f.AuctionWindow)
	}
}

func TestParseSIPAPensionRecord(t *testing.T) {
	body := []byte(`Id,CUIL,Importe,Estado
1,27-11111111-4,150000,Activo
2,20-22222222-3,180000,Activo
3,23-33333333-4,200000,Activo
trabajador_cuil: 27-11111111-4
`)
	f := ParseSIPAPensionRecord(body)
	if f.SIPAPensionerCount < 3 {
		t.Fatalf("pensioners=%d", f.SIPAPensionerCount)
	}
	if f.TrabajadorCuilRaw == "" {
		t.Fatal("trabajador CUIL must extract")
	}
}

func TestDetectAuctionWindow(t *testing.T) {
	cases := map[string]AuctionWindow{
		`window: BCRA`:               WindowBCRAPrimary,
		`window: Minecon`:            WindowMineconPrimary,
		`window: ANSES_LIC`:          WindowANSESLIC,
		`window: Tesoro_Corto_Plazo`: WindowTesoroCortoPlazo,
		`window: Tesoro_Largo_Plazo`: WindowTesoroLargoPlazo,
		`# generic`:                  WindowUnknown,
	}
	for in, want := range cases {
		got := detectAuctionWindow([]byte(in))
		if got != want {
			t.Fatalf("detect(%q)=%q want %q", in, got, want)
		}
	}
}

func TestClassifyHolder(t *testing.T) {
	if got := classifyHolder(Row{HasDirectorioActa: true}); got != RoleDirector {
		t.Fatalf("directorio -> director, got %q", got)
	}
	if got := classifyHolder(Row{HasComiteActa: true}); got != RoleComiteInversiones {
		t.Fatalf("comite -> comite-inversiones, got %q", got)
	}
	if got := classifyHolder(Row{HasPrimaryAuctionBid: true}); got != RoleTesoreria {
		t.Fatalf("auction -> tesoreria, got %q", got)
	}
	if got := classifyHolder(Row{HasCustodiaRecord: true}); got != RoleCustodia {
		t.Fatalf("custody -> custodia, got %q", got)
	}
	if got := classifyHolder(Row{HasFilingReceipt: true}); got != RoleAuditoriaSIGEN {
		t.Fatalf("receipt -> sigen, got %q", got)
	}
	if got := classifyHolder(Row{HasVotingRecord: true}); got != RoleDirector {
		t.Fatalf("voting -> director, got %q", got)
	}
	if got := classifyHolder(Row{HasSIPAPensionRecord: true}); got != RoleComplianceOfficer {
		t.Fatalf("sipa -> compliance, got %q", got)
	}
	if got := classifyHolder(Row{HasCarteraFGS: true, PanelLiderHoldingCount: 5}); got != RoleAnalistaEquity {
		t.Fatalf("cartera+panel -> analista-equity, got %q", got)
	}
	if got := classifyHolder(Row{HasCarteraFGS: true, SovBondHoldingCount: 5}); got != RoleAnalistaFixedIncome {
		t.Fatalf("cartera+sov -> analista-fixed-income, got %q", got)
	}
	if got := classifyHolder(Row{HasLICRecord: true}); got != RoleAnalistaFixedIncome {
		t.Fatalf("lic -> analista-fixed-income, got %q", got)
	}
	if got := classifyHolder(Row{ArtifactKind: KindConfig}); got != RoleAPI {
		t.Fatalf("config -> api, got %q", got)
	}
	if got := classifyHolder(Row{}); got != RoleUnknown {
		t.Fatalf("unknown, got %q", got)
	}
}

func TestClassifyPortfolio(t *testing.T) {
	if got := classifyPortfolio(Row{HasLICRecord: true, SovBondHoldingCount: 5}); got != PortfolioMultiAsset {
		t.Fatalf("multi -> multi-asset, got %q", got)
	}
	if got := classifyPortfolio(Row{HasLICRecord: true}); got != PortfolioLIC {
		t.Fatalf("lic -> lic, got %q", got)
	}
	if got := classifyPortfolio(Row{SovBondHoldingCount: 5}); got != PortfolioARSovBond {
		t.Fatalf("sov -> ar-sovereign-bond, got %q", got)
	}
	if got := classifyPortfolio(Row{EquityHoldingCount: 5}); got != PortfolioAREquity {
		t.Fatalf("equity -> ar-equity, got %q", got)
	}
	if got := classifyPortfolio(Row{}); got != PortfolioUnknown {
		t.Fatalf("unknown, got %q", got)
	}
}

func TestCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")
	fgsDir := filepath.Join(usersBase, "alice", "AppData", "Roaming", "FGS")
	carteraDir := filepath.Join(fgsDir, "cartera")
	licDir := filepath.Join(fgsDir, "lic")
	dirDir := filepath.Join(fgsDir, "directorio")
	must(t, os.MkdirAll(carteraDir, 0o755))
	must(t, os.MkdirAll(licDir, 0o755))
	must(t, os.MkdirAll(dirDir, 0o755))

	carteraPath := filepath.Join(carteraDir, "cartera_fgs_202606.xml")
	must(t, os.WriteFile(carteraPath, []byte(`<?xml version="1.0"?>
<FGS_Cartera>
  <Position><especie>AL30</especie></Position>
  <Position><especie>GD30</especie></Position>
  <Position><especie>GGAL</especie></Position>
  <Position><especie>YPFD</especie></Position>
  <Position><especie>PAMP</especie></Position>
  <Position><especie>BMA</especie></Position>
  <emisora_cuit>30-71234567-8</emisora_cuit>
</FGS_Cartera>`), 0o644))

	licPath := filepath.Join(licDir, "lic_2024-001.xml")
	must(t, os.WriteFile(licPath, []byte(`<?xml version="1.0"?>
<LIC>
  <lic_series>LIC2024-001</lic_series>
  <lic_face_value>1000000000000</lic_face_value>
</LIC>`), 0o644))

	dirPath := filepath.Join(dirDir, "directorio_acta_15.pdf")
	must(t, os.WriteFile(dirPath, []byte(`Acta de Directorio 15
acta_id: D-2026-15
especie: GGAL
especie: YPFD
especie: PAMP
especie: BMA
`), 0o644))

	must(t, os.WriteFile(filepath.Join(fgsDir, "random.txt"),
		[]byte(`nope`), 0o644))

	pub := filepath.Join(usersBase, "Public", "AppData", "Roaming", "FGS")
	must(t, os.MkdirAll(pub, 0o755))
	must(t, os.WriteFile(filepath.Join(pub, "cartera_fgs.xml"),
		[]byte(`<FGS_Cartera/>`), 0o644))

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
		t.Fatalf("want 3 (cartera+lic+directorio), got %d: %+v", len(got), got)
	}

	var cartera, lic, directorio Row
	for _, r := range got {
		switch r.FilePath {
		case carteraPath:
			cartera = r
		case licPath:
			lic = r
		case dirPath:
			directorio = r
		}
	}

	if cartera.ArtifactKind != KindCarteraFGS {
		t.Fatalf("cartera kind=%q", cartera.ArtifactKind)
	}
	if !cartera.HasCarteraFGS {
		t.Fatalf("cartera must flag: %+v", cartera)
	}
	if cartera.PanelLiderHoldingCount < 4 {
		t.Fatalf("cartera panel líder=%d", cartera.PanelLiderHoldingCount)
	}
	if !cartera.HasBYMAPanelLiderHolding {
		t.Fatalf("cartera must flag panel líder: %+v", cartera)
	}
	if cartera.HolderRole != RoleAnalistaEquity {
		t.Fatalf("cartera should classify as analista-equity, got %q", cartera.HolderRole)
	}

	if lic.ArtifactKind != KindLICRecord {
		t.Fatalf("lic kind=%q", lic.ArtifactKind)
	}
	if !lic.HasLICRecord {
		t.Fatalf("lic must flag: %+v", lic)
	}
	if lic.FGSSeriesCode != "LIC2024-001" {
		t.Fatalf("lic series=%q", lic.FGSSeriesCode)
	}
	if lic.HolderRole != RoleAnalistaFixedIncome {
		t.Fatalf("lic should classify as analista-fixed-income, got %q", lic.HolderRole)
	}
	if lic.PortfolioClass != PortfolioLIC {
		t.Fatalf("lic should classify as portfolio lic, got %q", lic.PortfolioClass)
	}

	if directorio.ArtifactKind != KindDirectorioActa {
		t.Fatalf("directorio kind=%q", directorio.ArtifactKind)
	}
	if !directorio.HasDirectorioActa {
		t.Fatalf("directorio must flag: %+v", directorio)
	}
	if !directorio.IsMarketMovingInfoRisk {
		t.Fatalf("directorio must flag market-moving (readable + acta): %+v", directorio)
	}
	if !directorio.HasPreDisclosureRisk {
		t.Fatalf("directorio with panel líder must flag pre-disclosure: %+v", directorio)
	}
}

func TestCollectorEnvOverride(t *testing.T) {
	tmp := t.TempDir()
	custom := filepath.Join(tmp, "custom-fgs")
	must(t, os.MkdirAll(custom, 0o755))
	must(t, os.WriteFile(filepath.Join(custom, "fgs_config.ini"),
		[]byte(`[FGS]
fgs_password=hello
`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "FGS_DIR" {
				return custom
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
	if len(got) != 1 {
		t.Fatalf("want 1 from env-override, got %d", len(got))
	}
	if !got[0].HasPasswordInConfig {
		t.Fatalf("env-override row must flag password")
	}
}

func TestCollectorMissingPathsOK(t *testing.T) {
	c := &fileCollector{
		installRoots: []string{"/nope-fgs"},
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
	rs := []Row{
		{FilePath: "/b", ArtifactKind: KindCarteraFGS},
		{FilePath: "/a", ArtifactKind: KindLICRecord},
		{FilePath: "/a", ArtifactKind: KindCarteraFGS},
	}
	SortRows(rs)
	if rs[0].FilePath != "/a" || rs[0].ArtifactKind != KindCarteraFGS {
		t.Fatalf("sort drift: %+v", rs)
	}
}

func TestHashSecret(t *testing.T) {
	a := HashSecret("abc")
	b := HashSecret("ABC")
	if a != b {
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
