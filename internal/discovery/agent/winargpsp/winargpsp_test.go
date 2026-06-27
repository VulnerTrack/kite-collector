package winargpsp

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindDebinBatch), "psp-debin-batch"},
		{string(KindCVUCBUResolution), "psp-cvu-cbu-resolution"},
		{string(KindQRInteroperable), "psp-qr-interoperable"},
		{string(KindEcheqIssuance), "psp-echeq-issuance"},
		{string(KindPixARBatch), "psp-pix-ar-batch"},
		{string(KindCompeClearing), "psp-compe-clearing"},
		{string(KindPagoMisCuentas), "psp-pago-mis-cuentas"},
		{string(KindVEPAFIP), "psp-vep-afip"},
		{string(KindPOSAcquirerBatch), "psp-pos-acquirer-batch"},
		{string(KindCashOutBatch), "psp-cash-out-batch"},
		{string(KindMerchantOnboarding), "psp-merchant-onboarding"},
		{string(KindBCRAInfoRegimen), "psp-bcra-info-regimen"},
		{string(NetworkBanelco), "banelco"},
		{string(NetworkMercadoPago), "mercado-pago"},
		{string(NetworkNaranjaX), "naranja-x"},
		{string(NetworkCuentaDNIBAPRO), "cuenta-dni-bapro"},
		{string(RailCompe), "compe"},
		{string(RailDEBIN), "debin"},
		{string(RailTransfer30), "transfer-3-0"},
		{string(RailPIXAR), "pix-ar"},
		{string(RoleChargebackOfficer), "chargeback-officer"},
		{string(RoleAMLOfficer), "aml-officer"},
		{string(TxP2P), "p2p"},
		{string(TxVEPAFIP), "vep-afip"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestIsCandidateName(t *testing.T) {
	yes := []string{
		"debin_batch_20260624.csv",
		"cvu_cbu_resolution_20260624.csv",
		"qr_interoperable_20260624.csv",
		"echeq_issuance_20260624.csv",
		"pix_ar_batch_20260624.csv",
		"compe_clearing_20260624.csv",
		"pago_mis_cuentas_20260624.csv",
		"vep_afip_20260624.csv",
		"pos_acquirer_batch_20260624.csv",
		"cash_out_batch_20260624.csv",
		"merchant_onboarding_202606.csv",
		"bcra_info_regimen_202606.xml",
		"psp_config.ini",
		"banelco_export.csv",
		"link_report.csv",
		"prisma_export.csv",
		"mercado_pago_export.csv",
		"mp_export.csv",
		"uala_export.csv",
		"naranja_x_export.csv",
		"cuenta_dni_export.csv",
		"brubank_export.csv",
		"lemon_export.csv",
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
		"debin_batch_20260624.csv":        KindDebinBatch,
		"cvu_cbu_resolution_20260624.csv": KindCVUCBUResolution,
		"qr_interoperable_20260624.csv":   KindQRInteroperable,
		"qr_interop_20260624.csv":         KindQRInteroperable,
		"echeq_issuance_20260624.csv":     KindEcheqIssuance,
		"pix_ar_batch_20260624.csv":       KindPixARBatch,
		"compe_clearing_20260624.csv":     KindCompeClearing,
		"pago_mis_cuentas_20260624.csv":   KindPagoMisCuentas,
		"pmc_20260624.csv":                KindPagoMisCuentas,
		"vep_afip_20260624.csv":           KindVEPAFIP,
		"pos_acquirer_batch_20260624.csv": KindPOSAcquirerBatch,
		"cash_out_batch_20260624.csv":     KindCashOutBatch,
		"cashout_20260624.csv":            KindCashOutBatch,
		"merchant_onboarding_202606.csv":  KindMerchantOnboarding,
		"kyc_merchant_202606.csv":         KindMerchantOnboarding,
		"bcra_info_regimen_202606.xml":    KindBCRAInfoRegimen,
		"regimen_psp_202606.xml":          KindBCRAInfoRegimen,
		"psp_config.ini":                  KindConfig,
		"credentials.json":                KindCredentials,
		"psp_installer_setup.msi":         KindInstaller,
		"":                                KindUnknown,
		"banelco_export.csv":              KindOther,
	}
	for in, want := range cases {
		if got := ArtifactKindFromName(in); got != want {
			t.Fatalf("ArtifactKindFromName(%q)=%q want %q", in, got, want)
		}
	}
}

func TestPSPNetworkFromName(t *testing.T) {
	cases := map[string]PSPNetwork{
		"banelco_export.csv":      NetworkBanelco,
		"link_report.csv":         NetworkLink,
		"prisma_export.csv":       NetworkPrisma,
		"mercado_pago_export.csv": NetworkMercadoPago,
		"mp_export.csv":           NetworkMercadoPago,
		"uala_export.csv":         NetworkUala,
		"modo_export.csv":         NetworkModo,
		"naranja_x_export.csv":    NetworkNaranjaX,
		"personal_pay_export.csv": NetworkPersonalPay,
		"cuenta_dni_export.csv":   NetworkCuentaDNIBAPRO,
		"bapro_export.csv":        NetworkCuentaDNIBAPRO,
		"brubank_export.csv":      NetworkBrubank,
		"lemon_export.csv":        NetworkLemon,
		"nubi_export.csv":         NetworkNubi,
		"belo_export.csv":         NetworkBelo,
		"random.txt":              NetworkUnknown,
	}
	for in, want := range cases {
		if got := PSPNetworkFromName(in); got != want {
			t.Fatalf("PSPNetworkFromName(%q)=%q want %q", in, got, want)
		}
	}
}

func TestDetectPSPNetwork(t *testing.T) {
	cases := map[string]PSPNetwork{
		"Banelco":          NetworkBanelco,
		"Link":             NetworkLink,
		"Prisma":           NetworkPrisma,
		"Mercado Pago":     NetworkMercadoPago,
		"mercado_pago":     NetworkMercadoPago,
		"Uala":             NetworkUala,
		"Modo":             NetworkModo,
		"Naranja X":        NetworkNaranjaX,
		"Personal Pay":     NetworkPersonalPay,
		"Cuenta DNI Bapro": NetworkCuentaDNIBAPRO,
		"Brubank":          NetworkBrubank,
		"Lemon":            NetworkLemon,
		"random":           NetworkUnknown,
	}
	for in, want := range cases {
		if got := detectPSPNetwork(in); got != want {
			t.Fatalf("detectPSPNetwork(%q)=%q want %q", in, got, want)
		}
	}
}

func TestDetectSettlementRail(t *testing.T) {
	cases := map[string]SettlementRail{
		"compe":              RailCompe,
		"mep":                RailMEP,
		"coelsa":             RailCOELSA,
		"debin":              RailDEBIN,
		"transfer_3_0":       RailTransfer30,
		"transferencias_3_0": RailTransfer30,
		"pix_ar":             RailPIXAR,
		"random":             RailUnknown,
	}
	for in, want := range cases {
		if got := detectSettlementRail(in); got != want {
			t.Fatalf("detectSettlementRail(%q)=%q want %q", in, got, want)
		}
	}
}

func TestDetectTransactionType(t *testing.T) {
	cases := map[string]TransactionType{
		"p2p":             TxP2P,
		"p2m":             TxP2M,
		"m2p":             TxM2P,
		"b2b":             TxB2B,
		"payroll":         TxPayroll,
		"nomina":          TxPayroll,
		"vep_afip":        TxVEPAFIP,
		"tax_collection":  TxTaxCollection,
		"impuesto":        TxTaxCollection,
		"utility_payment": TxUtilityPayment,
		"servicio":        TxUtilityPayment,
		"subscription":    TxSubscription,
		"suscripcion":     TxSubscription,
		"random":          TxUnknown,
	}
	for in, want := range cases {
		if got := detectTransactionType(in); got != want {
			t.Fatalf("detectTransactionType(%q)=%q want %q", in, got, want)
		}
	}
}

func TestIsCredentialKind(t *testing.T) {
	yes := []ArtifactKind{
		KindDebinBatch, KindCVUCBUResolution,
		KindQRInteroperable, KindEcheqIssuance,
		KindPixARBatch, KindCompeClearing,
		KindPagoMisCuentas, KindVEPAFIP,
		KindPOSAcquirerBatch, KindCashOutBatch,
		KindMerchantOnboarding, KindBCRAInfoRegimen,
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

func TestIsPaymentPIIKind(t *testing.T) {
	yes := []ArtifactKind{
		KindDebinBatch, KindCVUCBUResolution,
		KindMerchantOnboarding, KindCashOutBatch,
	}
	for _, k := range yes {
		if !IsPaymentPIIKind(k) {
			t.Fatalf("expected payment PII: %q", k)
		}
	}
}

func TestIsAMLTypologyKind(t *testing.T) {
	yes := []ArtifactKind{KindBCRAInfoRegimen, KindMerchantOnboarding}
	for _, k := range yes {
		if !IsAMLTypologyKind(k) {
			t.Fatalf("expected AML typology: %q", k)
		}
	}
}

func TestIsSettlementChainKind(t *testing.T) {
	yes := []ArtifactKind{
		KindCompeClearing, KindPixARBatch,
		KindEcheqIssuance, KindPOSAcquirerBatch,
	}
	for _, k := range yes {
		if !IsSettlementChainKind(k) {
			t.Fatalf("expected settlement chain: %q", k)
		}
	}
}

func TestAnnotatePaymentPII(t *testing.T) {
	r := Row{
		ArtifactKind: KindDebinBatch,
		FileMode:     0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasDebinBatch {
		t.Fatal("debin kind must flag")
	}
	if !r.IsPaymentPIIRisk {
		t.Fatal("readable + debin = payment PII risk")
	}
}

func TestAnnotateAMLTypologyLeak(t *testing.T) {
	r := Row{
		ArtifactKind: KindBCRAInfoRegimen,
		FileMode:     0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasBCRAInfoRegimen {
		t.Fatal("BCRA regimen kind must flag")
	}
	if !r.IsAMLTypologyLeak {
		t.Fatal("readable + BCRA regimen = AML typology leak")
	}
}

func TestAnnotateSettlementChainDisclosure(t *testing.T) {
	r := Row{
		ArtifactKind: KindCompeClearing,
		FileMode:     0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasCompeClearing {
		t.Fatal("compe kind must flag")
	}
	if !r.IsSettlementChainDisclosure {
		t.Fatal("readable + compe = settlement chain disclosure")
	}
}

func TestAnnotateCredentialExposure(t *testing.T) {
	r := Row{
		ArtifactKind:        KindConfig,
		FileMode:            0o644,
		HasPasswordInConfig: true,
	}
	AnnotateSecurity(&r)
	if !r.IsCredentialExposureRisk {
		t.Fatal("readable + config + password = credential exposure")
	}
}

func TestAnnotateLargeBatchValue(t *testing.T) {
	r := Row{
		ArtifactKind:  KindDebinBatch,
		BatchValueARS: LargeBatchValueARSThreshold + 1,
	}
	AnnotateSecurity(&r)
	if !r.HasLargeBatchValue {
		t.Fatal("> threshold must flag large batch")
	}
}

func TestParsePSP(t *testing.T) {
	body := []byte(`DEBIN Batch
psp_network: Mercado Pago
settlement_rail: debin
transaction_type: p2p
psp_cuit: 30-70308853-4
merchant_cuit: 30-70123456-7
customer_cvu: 0000003100018100000010
batch_id: BTC-2026-0001
transaction_count: 250000
customer_count: 180000
merchant_count: 1200
batch_value_ars: 5500000000
chargeback_count: 45
`)
	f := ParsePSP(body)
	if f.PSPNetwork != NetworkMercadoPago {
		t.Fatalf("network=%q", f.PSPNetwork)
	}
	if f.SettlementRail != RailDEBIN {
		t.Fatalf("rail=%q", f.SettlementRail)
	}
	if f.TransactionType != TxP2P {
		t.Fatalf("tx=%q", f.TransactionType)
	}
	if f.PSPCuitRaw == "" {
		t.Fatal("psp_cuit must extract")
	}
	if f.MerchantCuitRaw == "" {
		t.Fatal("merchant_cuit must extract")
	}
	if f.CustomerCVURaw != "0000003100018100000010" {
		t.Fatalf("cvu=%q", f.CustomerCVURaw)
	}
	if f.BatchID != "BTC-2026-0001" {
		t.Fatalf("batch=%q", f.BatchID)
	}
	if f.TransactionCount != 250000 {
		t.Fatalf("tx_count=%d", f.TransactionCount)
	}
	if f.CustomerCount != 180000 {
		t.Fatalf("cust_count=%d", f.CustomerCount)
	}
	if f.MerchantCount != 1200 {
		t.Fatalf("mer_count=%d", f.MerchantCount)
	}
	if f.BatchValueARS != 5_500_000_000 {
		t.Fatalf("value=%d", f.BatchValueARS)
	}
	if f.ChargebackCount != 45 {
		t.Fatalf("cb=%d", f.ChargebackCount)
	}
}

func TestParsePSPJSONForm(t *testing.T) {
	body := []byte(`{
  "psp_network": "Ualá",
  "settlement_rail": "pix_ar",
  "api_key": "secret"
}`)
	f := ParsePSP(body)
	if !f.HasPassword {
		t.Fatal("api_key must trigger password")
	}
	if f.PSPNetwork != NetworkUala {
		t.Fatalf("network=%q", f.PSPNetwork)
	}
	if f.SettlementRail != RailPIXAR {
		t.Fatalf("rail=%q", f.SettlementRail)
	}
}

func TestCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")
	pspDir := filepath.Join(usersBase, "alice", "psp")
	must(t, os.MkdirAll(pspDir, 0o755))

	debinPath := filepath.Join(pspDir, "debin_batch_20260624.csv")
	must(t, os.WriteFile(debinPath, []byte(`txid,payer_cvu,amount
1,0000003100018100000010,5000
psp_network: Mercado Pago
psp_cuit: 30-70308853-4
customer_cvu: 0000003100018100000010
batch_value_ars: 2500000000
`), 0o644))

	cvuPath := filepath.Join(pspDir, "cvu_cbu_resolution_20260624.csv")
	must(t, os.WriteFile(cvuPath, []byte(`alias,cvu
fulano.mp,0000003100018100000010
transaction_count: 50000
`), 0o644))

	regimenPath := filepath.Join(pspDir, "bcra_info_regimen_202606.xml")
	must(t, os.WriteFile(regimenPath, []byte(`<BCRA><regimen>
<psp_cuit>30-70308853-4</psp_cuit>
<period>202606</period>
</regimen></BCRA>
`), 0o644))

	compePath := filepath.Join(pspDir, "compe_clearing_20260624.csv")
	must(t, os.WriteFile(compePath, []byte(`bank,net_position_ars
GALICIA,1500000000
settlement_rail: compe
`), 0o644))

	kycPath := filepath.Join(pspDir, "merchant_onboarding_202606.csv")
	must(t, os.WriteFile(kycPath, []byte(`merchant_id,cuit,dni
M001,30-70123456-7,12345678
merchant_cuit: 30-70123456-7
merchant_count: 1200
`), 0o644))

	must(t, os.WriteFile(filepath.Join(pspDir, "random.txt"),
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
	if len(got) != 5 {
		t.Fatalf("want 5 (debin+cvu+regimen+compe+kyc), got %d: %+v", len(got), got)
	}

	var debin, cvu, reg, comp, kyc Row
	for _, r := range got {
		switch r.FilePath {
		case debinPath:
			debin = r
		case cvuPath:
			cvu = r
		case regimenPath:
			reg = r
		case compePath:
			comp = r
		case kycPath:
			kyc = r
		}
	}

	if debin.ArtifactKind != KindDebinBatch {
		t.Fatalf("debin kind=%q", debin.ArtifactKind)
	}
	if debin.PSPNetwork != NetworkMercadoPago {
		t.Fatalf("debin network=%q", debin.PSPNetwork)
	}
	if !debin.IsPaymentPIIRisk {
		t.Fatalf("debin must flag payment PII: %+v", debin)
	}
	if !debin.HasPSPCuit {
		t.Fatalf("debin must flag PSP cuit: %+v", debin)
	}
	if !debin.HasCustomerCVU {
		t.Fatalf("debin must flag customer CVU: %+v", debin)
	}
	if !debin.HasLargeBatchValue {
		t.Fatalf("debin must flag large batch: %+v", debin)
	}

	if cvu.ArtifactKind != KindCVUCBUResolution {
		t.Fatalf("cvu kind=%q", cvu.ArtifactKind)
	}
	if !cvu.IsPaymentPIIRisk {
		t.Fatalf("cvu must flag payment PII: %+v", cvu)
	}

	if reg.ArtifactKind != KindBCRAInfoRegimen {
		t.Fatalf("reg kind=%q", reg.ArtifactKind)
	}
	if !reg.IsAMLTypologyLeak {
		t.Fatalf("reg must flag AML leak: %+v", reg)
	}

	if comp.ArtifactKind != KindCompeClearing {
		t.Fatalf("comp kind=%q", comp.ArtifactKind)
	}
	if !comp.IsSettlementChainDisclosure {
		t.Fatalf("comp must flag settlement chain disclosure: %+v", comp)
	}

	if kyc.ArtifactKind != KindMerchantOnboarding {
		t.Fatalf("kyc kind=%q", kyc.ArtifactKind)
	}
	if !kyc.IsPaymentPIIRisk {
		t.Fatalf("kyc must flag payment PII: %+v", kyc)
	}
	if !kyc.IsAMLTypologyLeak {
		t.Fatalf("kyc must also flag AML typology: %+v", kyc)
	}
	if !kyc.HasMerchantCuit {
		t.Fatalf("kyc must flag merchant cuit: %+v", kyc)
	}
}

func TestCollectorEnvOverride(t *testing.T) {
	tmp := t.TempDir()
	custom := filepath.Join(tmp, "custom-psp")
	must(t, os.MkdirAll(custom, 0o755))
	must(t, os.WriteFile(filepath.Join(custom, "psp_config.ini"),
		[]byte(`[PSP]
psp_password=hello
`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "PSP_DIR" {
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
		installRoots: []string{"/nope-psp"},
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
		{FilePath: "/b", ArtifactKind: KindDebinBatch},
		{FilePath: "/a", ArtifactKind: KindCVUCBUResolution},
		{FilePath: "/a", ArtifactKind: KindDebinBatch},
	}
	SortRows(rs)
	// "psp-cvu-cbu-resolution" < "psp-debin-batch" alphabetically.
	if rs[0].FilePath != "/a" || rs[0].ArtifactKind != KindCVUCBUResolution {
		t.Fatalf("sort drift: %+v", rs)
	}
}

func TestHashSecret(t *testing.T) {
	a := HashSecret("0000003100018100000010")
	b := HashSecret("0000003100018100000010")
	if a != b {
		t.Fatal("hash must be deterministic")
	}
	if len(a) != 64 {
		t.Fatalf("hash len=%d", len(a))
	}
}

func TestCuitEntityOnlyFingerprint(t *testing.T) {
	prefix, suffix4 := CuitEntityOnlyFingerprint("psp_cuit: 30-70308853-4")
	if prefix != "30" {
		t.Fatalf("prefix=%q", prefix)
	}
	if suffix4 != "8534" {
		t.Fatalf("suffix4=%q", suffix4)
	}
	prefix, _ = CuitEntityOnlyFingerprint("20-12345678-9")
	if prefix != "" {
		t.Fatalf("individual prefix must be rejected: %q", prefix)
	}
}

func TestCuitAnyFingerprint(t *testing.T) {
	prefix, suffix4 := CuitAnyFingerprint("merchant_cuit: 20-12345678-9")
	if prefix != "20" {
		t.Fatalf("prefix=%q", prefix)
	}
	if suffix4 != "6789" {
		t.Fatalf("suffix4=%q", suffix4)
	}
}

func TestPeriodFromFilename(t *testing.T) {
	if got := PeriodFromFilename("debin_batch_20260624.csv"); got != "202606" {
		t.Fatalf("got=%q", got)
	}
	if got := PeriodFromFilename("psp_annual_2026.pdf"); got != "2026" {
		t.Fatalf("got=%q", got)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
