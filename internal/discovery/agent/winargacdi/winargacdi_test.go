package winargacdi

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindClientKYC), "acdi-client-kyc"},
		{string(KindSuitabilityAssessment), "acdi-suitability-assessment"},
		{string(KindFCISubscriptionOrder), "acdi-fci-subscription-order"},
		{string(KindRetrocessionAgreement), "acdi-retrocession-agreement"},
		{string(KindQuarterlyCommissionReport), "acdi-quarterly-commission-report"},
		{string(KindPLAFTClassification), "acdi-plaft-classification"},
		{string(FCICohenAM), "cohen-am"},
		{string(FCIGalileoAM), "galileo-am"},
		{string(FCISintesisManaged), "sintesis-managed"},
		{string(ClassRetail), "retail"},
		{string(ClassQualifiedInvestor), "qualified-investor"},
		{string(ClassKnowledgeableCounterparty), "knowledgeable-counterparty"},
		{string(PLAFTPEPs), "peps"},
		{string(PLAFTBeneficialOwnerUnclear), "beneficial-owner-unclear"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestIsCandidateName(t *testing.T) {
	yes := []string{
		"client_kyc_alice.pdf",
		"suitability_assessment_alice.pdf",
		"fci_subscription_order_001.pdf",
		"retrocession_cohen.pdf",
		"distribution_agreement_galileo.pdf",
		"commission_report_q2_2026.csv",
		"risk_profile_alice.pdf",
		"plaft_classification.csv",
		"perfil_inversor_alice.pdf",
		"acdi_config.ini",
		"agente_productor.cfg",
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
		"client_kyc_alice.pdf":               KindClientKYC,
		"suitability_assessment_alice.pdf":   KindSuitabilityAssessment,
		"fci_subscription_order_001.pdf":     KindFCISubscriptionOrder,
		"retrocession_cohen.pdf":             KindRetrocessionAgreement,
		"distribution_agreement_galileo.pdf": KindDistributionAgreement,
		"commission_report_q2_2026.csv":      KindQuarterlyCommissionReport,
		"risk_profile_alice.pdf":             KindClientRiskProfile,
		"perfil_inversor_alice.pdf":          KindClientRiskProfile,
		"plaft_classification.csv":           KindPLAFTClassification,
		"acdi_config.ini":                    KindConfig,
		"credentials.json":                   KindCredentials,
		"acdi_setup.msi":                     KindInstaller,
		"":                                   KindUnknown,
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

func TestIsCredentialKind(t *testing.T) {
	yes := []ArtifactKind{
		KindClientKYC, KindSuitabilityAssessment,
		KindFCISubscriptionOrder, KindRetrocessionAgreement,
		KindDistributionAgreement, KindQuarterlyCommissionReport,
		KindClientRiskProfile, KindPLAFTClassification,
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

func TestAnnotateExposure(t *testing.T) {
	r := Row{
		ArtifactKind:        KindClientKYC,
		HasPasswordInConfig: true,
		ClienteCuitPrefix:   "27",
		ClienteCuitSuffix4:  "1114",
		FileMode:            0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasClienteCuit {
		t.Fatal("cliente cuit must flag")
	}
	if !r.HasClientKYC {
		t.Fatal("KYC kind must auto-flag")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("readable + password + cliente = exposure")
	}
	if !r.IsKYCPIIRisk {
		t.Fatal("readable + KYC + CUIT = KYC PII risk")
	}
}

func TestAnnotateQualifiedInvestorFlag(t *testing.T) {
	r := Row{
		ArtifactKind:         KindSuitabilityAssessment,
		ClientClassification: ClassQualifiedInvestor,
	}
	AnnotateSecurity(&r)
	if !r.HasQualifiedInvestorFlag {
		t.Fatal("qualified investor must flag")
	}
}

func TestParseFCISubscriptionOrder(t *testing.T) {
	body := []byte(`FCI Subscription Order
acdi_license_id: ACDI-2026-0001
fci_manager: Cohen AM
client_classification: qualified
subscription_amount: 50000000
cliente_cuit: 27-11111111-4
`)
	f := ParseFCISubscriptionOrder(body)
	if f.ACDILicenseID != "ACDI-2026-0001" {
		t.Fatalf("license=%q", f.ACDILicenseID)
	}
	if f.FCIManager != FCICohenAM {
		t.Fatalf("manager=%q want cohen-am", f.FCIManager)
	}
	if f.ClientClassification != ClassQualifiedInvestor {
		t.Fatalf("class=%q want qualified-investor", f.ClientClassification)
	}
	if f.SubscriptionAmountARSMillions != 50 {
		t.Fatalf("amount=%d want 50 M", f.SubscriptionAmountARSMillions)
	}
	if f.ClienteCuitRaw == "" {
		t.Fatal("cuit must extract")
	}
}

func TestParseRetrocessionAgreement(t *testing.T) {
	body := []byte(`Retrocession Agreement - Cohen AM
fci_manager: Cohen AM
retrocession_bps: 100
`)
	f := ParseRetrocessionAgreement(body)
	if f.RetrocessionBPS != 100 {
		t.Fatalf("bps=%d", f.RetrocessionBPS)
	}
}

func TestParseQuarterlyCommissionReport(t *testing.T) {
	body := []byte(`Q2 2026 Commission Report
commission_total: 15000000
`)
	f := ParseQuarterlyCommissionReport(body)
	if f.CommissionTotalARSMillions != 15 {
		t.Fatalf("commission=%d", f.CommissionTotalARSMillions)
	}
}

func TestDetectFCIManager(t *testing.T) {
	cases := map[string]FCIManager{
		"Cohen AM":   FCICohenAM,
		"Galileo":    FCIGalileoAM,
		"Pellegrini": FCIPellegriniAM,
		"Sintesis":   FCISintesisManaged,
		"BBVA":       FCIBBVAAM,
		"Galicia":    FCIGaliciaAM,
		"Santander":  FCISantanderAM,
		"Itaú":       FCIItauAM,
		"Adcap":      FCIAdcapAM,
		"Mariva":     FCIMarivaAM,
		"Schweber":   FCISchweber,
		"unknown":    FCIUnknown,
	}
	for in, want := range cases {
		got := detectFCIManager(in)
		if got != want {
			t.Fatalf("detect(%q)=%q want %q", in, got, want)
		}
	}
}

func TestDetectClassification(t *testing.T) {
	cases := map[string]ClientClassification{
		"retail":        ClassRetail,
		"minorista":     ClassRetail,
		"professional":  ClassProfessional,
		"profesional":   ClassProfessional,
		"qualified":     ClassQualifiedInvestor,
		"calificado":    ClassQualifiedInvestor,
		"institutional": ClassInstitutional,
		"knowledgeable": ClassKnowledgeableCounterparty,
		"unknown":       ClassUnknown,
	}
	for in, want := range cases {
		got := detectClassification(in)
		if got != want {
			t.Fatalf("detect(%q)=%q want %q", in, got, want)
		}
	}
}

func TestDetectPLAFTRiskClass(t *testing.T) {
	cases := map[string]PLAFTRiskClass{
		"PEPs":       PLAFTPEPs,
		"high":       PLAFTHigh,
		"alto":       PLAFTHigh,
		"medium":     PLAFTMedium,
		"medio":      PLAFTMedium,
		"low":        PLAFTLow,
		"bajo":       PLAFTLow,
		"beneficial": PLAFTBeneficialOwnerUnclear,
		"random":     PLAFTUnknown,
	}
	for in, want := range cases {
		got := detectPLAFTRiskClass(in)
		if got != want {
			t.Fatalf("detect(%q)=%q want %q", in, got, want)
		}
	}
}

func TestCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")
	acdiDir := filepath.Join(usersBase, "alice", "AppData", "Roaming", "ACDI")
	must(t, os.MkdirAll(acdiDir, 0o755))

	kycPath := filepath.Join(acdiDir, "client_kyc_alice.pdf")
	must(t, os.WriteFile(kycPath, []byte(`Client KYC
acdi_license_id: ACDI-2026-0001
client_classification: retail
cliente_cuit: 27-11111111-4
cliente_dni: 12345678
`), 0o644))

	subPath := filepath.Join(acdiDir, "fci_subscription_order_001.pdf")
	must(t, os.WriteFile(subPath, []byte(`Subscription Order
fci_manager: Cohen AM
subscription_amount: 50000000
client_classification: qualified
`), 0o644))

	must(t, os.WriteFile(filepath.Join(acdiDir, "random.txt"),
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
	if len(got) != 2 {
		t.Fatalf("want 2 (kyc+sub), got %d: %+v", len(got), got)
	}

	var kyc, sub Row
	for _, r := range got {
		switch r.FilePath {
		case kycPath:
			kyc = r
		case subPath:
			sub = r
		}
	}

	if kyc.ArtifactKind != KindClientKYC {
		t.Fatalf("kyc kind=%q", kyc.ArtifactKind)
	}
	if !kyc.HasClientKYC {
		t.Fatalf("kyc must flag: %+v", kyc)
	}
	if !kyc.HasClienteCuit {
		t.Fatalf("kyc must flag cuit: %+v", kyc)
	}
	if !kyc.HasClienteDNI {
		t.Fatalf("kyc must flag DNI: %+v", kyc)
	}
	if !kyc.IsKYCPIIRisk {
		t.Fatalf("kyc must flag PII risk: %+v", kyc)
	}

	if sub.ArtifactKind != KindFCISubscriptionOrder {
		t.Fatalf("sub kind=%q", sub.ArtifactKind)
	}
	if !sub.HasFCISubscriptionOrder {
		t.Fatalf("sub must flag: %+v", sub)
	}
	if sub.FCIManager != FCICohenAM {
		t.Fatalf("sub manager=%q", sub.FCIManager)
	}
	if sub.SubscriptionAmountARSMillions != 50 {
		t.Fatalf("sub amount=%d", sub.SubscriptionAmountARSMillions)
	}
	if !sub.HasQualifiedInvestorFlag {
		t.Fatalf("sub qualified must flag: %+v", sub)
	}
}

func TestCollectorEnvOverride(t *testing.T) {
	tmp := t.TempDir()
	custom := filepath.Join(tmp, "custom-acdi")
	must(t, os.MkdirAll(custom, 0o755))
	must(t, os.WriteFile(filepath.Join(custom, "acdi_config.ini"),
		[]byte(`[ACDI]
acdi_password=hello
`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "ACDI_DIR" {
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
		installRoots: []string{"/nope-acdi"},
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
		{FilePath: "/b", ArtifactKind: KindClientKYC},
		{FilePath: "/a", ArtifactKind: KindFCISubscriptionOrder},
		{FilePath: "/a", ArtifactKind: KindClientKYC},
	}
	SortRows(rs)
	if rs[0].FilePath != "/a" || rs[0].ArtifactKind != KindClientKYC {
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
