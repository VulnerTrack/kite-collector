package winargtax

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindFiscalOpinion), "tax-fiscal-opinion"},
		{string(KindTransferPricingMemo), "tax-transfer-pricing-memo"},
		{string(KindAFIPRG5193Filing), "tax-afip-rg5193-filing"},
		{string(KindBienesPersonalesFiling), "tax-bienes-personales-filing"},
		{string(KindAFIPF8125), "tax-afip-f8125"},
		{string(KindArgentinaFATCA), "tax-argentina-fatca"},
		{string(KindTaxPositionUncertainty), "tax-position-uncertainty"},
		{string(FirmPwCTaxArgentina), "pwc-tax-argentina"},
		{string(FirmLisickiLitvin), "lisicki-litvin"},
		{string(FirmPistrelliHenryMartin), "pistrelli-henry-martin"},
		{string(RoleTaxPartner), "tax-partner"},
		{string(RoleTransferPricingSpecialist), "transfer-pricing-specialist"},
		{string(RoleCRSFATCASpecialist), "crs-fatca-specialist"},
		{string(RegimeBienesPersonales), "bienes-personales"},
		{string(RegimeLey23576ONExempt), "ley-23576-on-exempt"},
		{string(RegimeLey27430FCI), "ley-27430-fci"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestIsCandidateName(t *testing.T) {
	yes := []string{
		"fiscal_opinion_ON_GGAL.pdf",
		"transfer_pricing_memo_2026.pdf",
		"afip_rg5193_202606.xml",
		"bienes_personales_202612.pdf",
		"afip_f8125_2026.pdf",
		"argentina_fatca_2025.xml",
		"regimen_industrial_2026.pdf",
		"tax_litigation_defense.pdf",
		"fiscalizacion_response.pdf",
		"tax_position_uncertainty.pdf",
		"fin_48_reserve.pdf",
		"tax_engagement_2026.pdf",
		"billable_hours_tax_q2.csv",
		"pwc_tax_config.ini",
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
		"fiscal_opinion_ON_GGAL.pdf":     KindFiscalOpinion,
		"transfer_pricing_memo_2026.pdf": KindTransferPricingMemo,
		"afip_rg5193_202606.xml":         KindAFIPRG5193Filing,
		"bienes_personales_202612.pdf":   KindBienesPersonalesFiling,
		"afip_f8125_2026.pdf":            KindAFIPF8125,
		"argentina_fatca_2025.xml":       KindArgentinaFATCA,
		"regimen_industrial_2026.pdf":    KindRegimenIndustrial,
		"tax_litigation_defense.pdf":     KindTaxLitigationDefense,
		"fiscalizacion_response.pdf":     KindFiscalizacionResponse,
		"fin_48_reserve.pdf":             KindTaxPositionUncertainty,
		"tax_engagement_2026.pdf":        KindEngagementLetterTax,
		"billable_hours_tax_q2.csv":      KindBillableHoursTax,
		"tax_config.ini":                 KindConfig,
		"credentials.json":               KindCredentials,
		"tax_setup.msi":                  KindInstaller,
		"":                               KindUnknown,
	}
	for in, want := range cases {
		if got := ArtifactKindFromName(in); got != want {
			t.Fatalf("ArtifactKindFromName(%q)=%q want %q", in, got, want)
		}
	}
}

func TestCuitFingerprint(t *testing.T) {
	p, s := CuitFingerprint("cliente 27-11111111-4")
	if p != "27" || s != "1114" {
		t.Fatalf("cuit=(%q,%q)", p, s)
	}
}

func TestCuilFingerprint(t *testing.T) {
	p, s := CuilFingerprint("asesor 27-11111111-4")
	if p != "27" || s != "1114" {
		t.Fatalf("cuil=(%q,%q)", p, s)
	}
	if p2, _ := CuilFingerprint("entity 30-71234567-8"); p2 != "" {
		t.Fatal("entity prefix must reject for CUIL")
	}
}

func TestIsCredentialKind(t *testing.T) {
	yes := []ArtifactKind{
		KindFiscalOpinion, KindTransferPricingMemo,
		KindAFIPRG5193Filing, KindBienesPersonalesFiling,
		KindAFIPF8125, KindArgentinaFATCA,
		KindRegimenIndustrial, KindTaxLitigationDefense,
		KindFiscalizacionResponse, KindTaxPositionUncertainty,
		KindEngagementLetterTax, KindBillableHoursTax,
		KindConfig, KindCredentials,
	}
	for _, k := range yes {
		if !IsCredentialKind(k) {
			t.Fatalf("expected cred: %q", k)
		}
	}
	for _, k := range []ArtifactKind{KindInstaller, KindOther, KindUnknown} {
		if IsCredentialKind(k) {
			t.Fatalf("expected NOT cred: %q", k)
		}
	}
}

func TestIsCrossBorderAttributionKind(t *testing.T) {
	yes := []ArtifactKind{
		KindTransferPricingMemo, KindAFIPF8125, KindArgentinaFATCA,
	}
	for _, k := range yes {
		if !IsCrossBorderAttributionKind(k) {
			t.Fatalf("expected cb-attribution: %q", k)
		}
	}
	no := []ArtifactKind{
		KindFiscalOpinion, KindAFIPRG5193Filing,
		KindBienesPersonalesFiling, KindRegimenIndustrial,
		KindConfig, KindCredentials,
	}
	for _, k := range no {
		if IsCrossBorderAttributionKind(k) {
			t.Fatalf("expected NOT cb-attribution: %q", k)
		}
	}
}

func TestAnnotateExposure(t *testing.T) {
	r := Row{
		ArtifactKind:        KindFiscalOpinion,
		HasPasswordInConfig: true,
		ClienteCuitPrefix:   "30",
		ClienteCuitSuffix4:  "5678",
		FileMode:            0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasClienteCuit {
		t.Fatal("cliente cuit must flag")
	}
	if !r.HasFiscalOpinion {
		t.Fatal("fiscal opinion kind must auto-flag")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("readable + password + cliente = exposure")
	}
}

func TestAnnotateHNWPIIRisk(t *testing.T) {
	r := Row{
		ArtifactKind:            KindBienesPersonalesFiling,
		HNWThresholdARSMillions: HNWBienesPersonalesThresholdARSMillions + 100,
		ClienteCuitPrefix:       "27",
		ClienteCuitSuffix4:      "1114",
		FileMode:                0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasHNWFiling {
		t.Fatal("BP filing above threshold must flag HNW")
	}
	if !r.IsHNWPIIRisk {
		t.Fatal("readable + HNW + cuit = HNW PII risk")
	}
}

func TestAnnotateCrossBorderAttribution(t *testing.T) {
	r := Row{
		ArtifactKind: KindTransferPricingMemo,
		FileMode:     0o644,
	}
	AnnotateSecurity(&r)
	if !r.IsCrossBorderAttributionRisk {
		t.Fatal("readable + TP memo = cross-border attribution risk")
	}
}

func TestAnnotateF8125CrossBorder(t *testing.T) {
	r := Row{
		ArtifactKind: KindAFIPF8125,
		FileMode:     0o644,
	}
	AnnotateSecurity(&r)
	if !r.IsCrossBorderAttributionRisk {
		t.Fatal("readable + F.8125 = cross-border attribution risk")
	}
}

func TestParseFiscalOpinion(t *testing.T) {
	body := []byte(`Fiscal Opinion - ON Galicia 2026
PRIVILEGED - TAX ADVICE ONLY
engagement_id: TAX-2026-0123
client_name: Banco Galicia
tax_firm: PwC Tax Argentina
tax_role: tax partner
tax_regime: Ley 23.576 ON exempt
cliente_cuit: 30-71234567-8
lawyer_cuil: 27-11111111-4
`)
	f := ParseFiscalOpinion(body)
	if f.EngagementID != "TAX-2026-0123" {
		t.Fatalf("engagement=%q", f.EngagementID)
	}
	if f.TaxFirm != FirmPwCTaxArgentina {
		t.Fatalf("firm=%q want pwc-tax-argentina", f.TaxFirm)
	}
	if f.TaxRole != RoleTaxPartner {
		t.Fatalf("role=%q want tax-partner", f.TaxRole)
	}
	if f.TaxRegime != RegimeLey23576ONExempt {
		t.Fatalf("regime=%q want ley-23576-on-exempt", f.TaxRegime)
	}
	if !f.HasPrePublicationDraft {
		t.Fatal("PRIVILEGED must flag pre-pub")
	}
	if f.ClienteCuitRaw == "" {
		t.Fatal("cuit must extract")
	}
	if f.LawyerCuilRaw == "" {
		t.Fatal("cuil must extract")
	}
}

func TestParseBienesPersonalesFiling(t *testing.T) {
	body := []byte(`Bienes Personales - 2026
client_name: HNW Cliente
bp_total: 1500000000
cliente_cuit: 27-11111111-4
`)
	f := ParseBienesPersonalesFiling(body)
	if f.HNWThresholdARSMillions != 1500 {
		t.Fatalf("BP total=%d want 1500 M", f.HNWThresholdARSMillions)
	}
}

func TestParseTaxPositionUncertainty(t *testing.T) {
	body := []byte(`FIN 48 Tax Position Uncertainty
tax_reserve: 25000000
`)
	f := ParseTaxPositionUncertainty(body)
	if f.TaxReserveARSMillions != 25 {
		t.Fatalf("reserve=%d", f.TaxReserveARSMillions)
	}
}

func TestDetectTaxFirm(t *testing.T) {
	cases := map[string]TaxFirm{
		"PwC Tax Argentina":      FirmPwCTaxArgentina,
		"Deloitte Tax":           FirmDeloitteTaxArgentina,
		"EY Tax":                 FirmEYTaxArgentina,
		"KPMG Tax":               FirmKPMGTaxArgentina,
		"BDO Tax":                FirmBDOTaxArgentina,
		"Beccar Varela Tax":      FirmBeccarVarelaTax,
		"Bruchou Tax":            FirmBruchouTax,
		"PAGBAM Tax":             FirmPAGBAMTax,
		"Lisicki Litvin":         FirmLisickiLitvin,
		"Pistrelli Henry Martin": FirmPistrelliHenryMartin,
		"Díaz Sieiro":            FirmDiazSieiro,
		"Estudio Local":          FirmLocalMidTier,
		"unknown":                FirmUnknown,
	}
	for in, want := range cases {
		got := detectTaxFirm(in)
		if got != want {
			t.Fatalf("detect(%q)=%q want %q", in, got, want)
		}
	}
}

func TestDetectTaxRole(t *testing.T) {
	cases := map[string]TaxRole{
		"tax partner":                 RoleTaxPartner,
		"senior manager":              RoleTaxSeniorManager,
		"transfer pricing specialist": RoleTransferPricingSpecialist,
		"cross-border specialist":     RoleCrossBorderSpecialist,
		"CRS FATCA specialist":        RoleCRSFATCASpecialist,
		"litigation partner":          RoleTaxLitigationPartner,
		"billing clerk":               RoleBillingClerk,
		"random":                      RoleUnknown,
	}
	for in, want := range cases {
		got := detectTaxRole(in)
		if got != want {
			t.Fatalf("detect(%q)=%q want %q", in, got, want)
		}
	}
}

func TestDetectTaxRegime(t *testing.T) {
	cases := map[string]TaxRegime{
		"ganancias":            RegimeImpuestoGanancias,
		"bienes personales":    RegimeBienesPersonales,
		"IVA":                  RegimeIVA,
		"transfer pricing":     RegimeTransferPricing,
		"RIPRO":                RegimeRIPRO,
		"Tierra del Fuego":     RegimeTierraDelFuego,
		"minería":              RegimeMineria,
		"Ley 23.576 ON exempt": RegimeLey23576ONExempt,
		"Ley 27.430 FCI":       RegimeLey27430FCI,
		"CEDEAR":               RegimeCEDEAR,
		"sov bond":             RegimeSovBondExempt,
		"CRS":                  RegimeCRSFATCA,
		"random":               RegimeUnknown,
	}
	for in, want := range cases {
		got := detectTaxRegime(in)
		if got != want {
			t.Fatalf("detect(%q)=%q want %q", in, got, want)
		}
	}
}

func TestCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")
	taxDir := filepath.Join(usersBase, "alice", "AppData", "Roaming", "TaxAdvisor")
	must(t, os.MkdirAll(taxDir, 0o755))

	opPath := filepath.Join(taxDir, "fiscal_opinion_ON_GGAL.pdf")
	must(t, os.WriteFile(opPath, []byte(`Fiscal Opinion - GGAL ON
PRIVILEGED - TAX ADVICE ONLY
engagement_id: TAX-2026-0123
tax_firm: PwC Tax Argentina
tax_regime: Ley 23.576 ON exempt
cliente_cuit: 30-71234567-8
`), 0o644))

	bpPath := filepath.Join(taxDir, "bienes_personales_202612.pdf")
	must(t, os.WriteFile(bpPath, []byte(`Bienes Personales 2026
bp_total: 1500000000
cliente_cuit: 27-11111111-4
`), 0o644))

	tpPath := filepath.Join(taxDir, "transfer_pricing_memo_2026.pdf")
	must(t, os.WriteFile(tpPath, []byte(`Transfer Pricing Memo 2026
engagement_id: TAX-2026-0124
tax_regime: transfer pricing
`), 0o644))

	must(t, os.WriteFile(filepath.Join(taxDir, "random.txt"),
		[]byte(`nope`), 0o644))

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
		t.Fatalf("want 3 (op+bp+tp), got %d: %+v", len(got), got)
	}

	var op, bp, tp Row
	for _, r := range got {
		switch r.FilePath {
		case opPath:
			op = r
		case bpPath:
			bp = r
		case tpPath:
			tp = r
		}
	}

	if op.ArtifactKind != KindFiscalOpinion {
		t.Fatalf("op kind=%q", op.ArtifactKind)
	}
	if !op.HasFiscalOpinion {
		t.Fatalf("op must flag: %+v", op)
	}
	if !op.HasPrePublicationDraft {
		t.Fatalf("op must flag PRIVILEGED: %+v", op)
	}
	if op.TaxFirm != FirmPwCTaxArgentina {
		t.Fatalf("op firm=%q", op.TaxFirm)
	}
	if op.TaxRegime != RegimeLey23576ONExempt {
		t.Fatalf("op regime=%q", op.TaxRegime)
	}
	if !op.HasClienteCuit {
		t.Fatalf("op must flag cuit: %+v", op)
	}
	if !op.IsCredentialExposureRisk {
		t.Fatalf("op must flag credential exposure: %+v", op)
	}

	if bp.ArtifactKind != KindBienesPersonalesFiling {
		t.Fatalf("bp kind=%q", bp.ArtifactKind)
	}
	if !bp.HasBienesPersonalesFiling {
		t.Fatalf("bp must flag: %+v", bp)
	}
	if !bp.HasHNWFiling {
		t.Fatalf("bp must flag HNW (1500 M ARS): %+v", bp)
	}
	if !bp.IsHNWPIIRisk {
		t.Fatalf("bp must flag HNW PII risk: %+v", bp)
	}

	if tp.ArtifactKind != KindTransferPricingMemo {
		t.Fatalf("tp kind=%q", tp.ArtifactKind)
	}
	if !tp.HasTransferPricingMemo {
		t.Fatalf("tp must flag: %+v", tp)
	}
	if !tp.IsCrossBorderAttributionRisk {
		t.Fatalf("tp must flag cross-border attribution: %+v", tp)
	}
}

func TestCollectorEnvOverride(t *testing.T) {
	tmp := t.TempDir()
	custom := filepath.Join(tmp, "custom-tax")
	must(t, os.MkdirAll(custom, 0o755))
	must(t, os.WriteFile(filepath.Join(custom, "tax_config.ini"),
		[]byte(`[Tax]
tax_password=hello
`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "TAX_DIR" {
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
		installRoots: []string{"/nope-tax"},
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
		{FilePath: "/b", ArtifactKind: KindFiscalOpinion},
		{FilePath: "/a", ArtifactKind: KindTransferPricingMemo},
		{FilePath: "/a", ArtifactKind: KindFiscalOpinion},
	}
	SortRows(rs)
	if rs[0].FilePath != "/a" || rs[0].ArtifactKind != KindFiscalOpinion {
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
