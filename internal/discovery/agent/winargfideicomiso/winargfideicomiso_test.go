package winargfideicomiso

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindProspecto), "ff-prospecto"},
		{string(KindSuplementoSerie), "ff-suplemento-serie"},
		{string(KindEscrituraFiduciaria), "ff-escritura-fiduciaria"},
		{string(KindCobranzaCSV), "ff-cobranza-csv"},
		{string(KindMoraCSV), "ff-mora-csv"},
		{string(KindTituloSerie), "ff-titulo-serie"},
		{string(KindInvestorList), "ff-investor-list"},
		{string(KindCalificacionReport), "ff-calificacion-report"},
		{string(KindAdministratorReport), "ff-administrator-report"},
		{string(RoleFiduciario), "fiduciario"},
		{string(RoleOriginador), "originador"},
		{string(RoleServicer), "servicer"},
		{string(RoleAgenteControlRevision), "agente-control-revision"},
		{string(UnderlyingTarjetaCredito), "tarjeta-credito"},
		{string(UnderlyingMortgage), "mortgage"},
		{string(UnderlyingSGRPool), "sgr-pool"},
		{string(TrancheVRDSenior), "vrd-senior"},
		{string(TrancheCPEquity), "cp-equity"},
		{string(RatingAAA), "aaa"},
		{string(RatingBBB), "bbb"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestIsCandidateName(t *testing.T) {
	yes := []string{
		"prospecto_ff_naranja.pdf",
		"suplemento_serie_XXIV.pdf",
		"escritura_fiduciaria_naranja.pdf",
		"contrato_fiduciario_naranja.pdf",
		"cobranza_202606.csv",
		"mora_202606.csv",
		"precancelacion_202606.csv",
		"titulo_serie_VRD_001.xml",
		"vrd_naranja_xxiv.xml",
		"inversores_serie_XXIV.csv",
		"calificacion_VRD_001.pdf",
		"reporte_administrador_fiduciario.pdf",
		"audit_revision_202606.pdf",
		"agente_control_202606.pdf",
		"bacs_config.ini",
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
		"prospecto_ff_naranja.pdf":             KindProspecto,
		"suplemento_serie_XXIV.pdf":            KindSuplementoSerie,
		"escritura_fiduciaria_naranja.pdf":     KindEscrituraFiduciaria,
		"contrato_fiduciario_naranja.pdf":      KindContratoFiduciario,
		"cobranza_202606.csv":                  KindCobranzaCSV,
		"mora_202606.csv":                      KindMoraCSV,
		"precancelacion_202606.csv":            KindPrecancelacionCSV,
		"titulo_serie_VRD_001.xml":             KindTituloSerie,
		"vrd_naranja_xxiv.xml":                 KindTituloSerie,
		"inversores_serie_XXIV.csv":            KindInvestorList,
		"calificacion_VRD_001.pdf":             KindCalificacionReport,
		"reporte_administrador_fiduciario.pdf": KindAdministratorReport,
		"agente_control_202606.pdf":            KindAuditReport,
		"ff_receipt_202606.xml":                KindFilingReceipt,
		"fideicomiso_config.ini":               KindConfig,
		"credentials.json":                     KindCredentials,
		"fideicomiso_setup.msi":                KindInstaller,
		"":                                     KindUnknown,
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
		{"deudor 27-11111111-4", "27", "1114"},
		{"emisor 30-71234567-8", "30", "5678"},
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

func TestCuitEntityOnlyFingerprint(t *testing.T) {
	cases := []struct {
		in, pfx, sfx4 string
	}{
		{"originador 30-71234567-8", "30", "5678"},
		// Individual prefix 27 rejected for entity-only fingerprint.
		{"individuo 27-11111111-4", "", ""},
	}
	for _, c := range cases {
		gotP, gotS := CuitEntityOnlyFingerprint(c.in)
		if gotP != c.pfx || gotS != c.sfx4 {
			t.Fatalf("CuitEntityOnlyFingerprint(%q)=(%q,%q) want (%q,%q)",
				c.in, gotP, gotS, c.pfx, c.sfx4)
		}
	}
}

func TestIsCredentialKind(t *testing.T) {
	yes := []ArtifactKind{
		KindProspecto, KindSuplementoSerie,
		KindEscrituraFiduciaria, KindContratoFiduciario,
		KindCobranzaCSV, KindMoraCSV, KindPrecancelacionCSV,
		KindTituloSerie, KindInvestorList,
		KindCalificacionReport, KindAdministratorReport,
		KindAuditReport, KindFilingReceipt,
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

func TestIsInsiderKind(t *testing.T) {
	yes := []ArtifactKind{
		KindEscrituraFiduciaria, KindContratoFiduciario,
		KindAdministratorReport, KindAuditReport,
		KindSuplementoSerie,
	}
	for _, k := range yes {
		if !IsInsiderKind(k) {
			t.Fatalf("expected insider kind: %q", k)
		}
	}
	no := []ArtifactKind{
		KindProspecto, KindCobranzaCSV, KindMoraCSV,
		KindPrecancelacionCSV, KindTituloSerie,
		KindInvestorList, KindCalificacionReport,
		KindFilingReceipt, KindConfig, KindCredentials,
		KindInstaller, KindOther, KindUnknown,
	}
	for _, k := range no {
		if IsInsiderKind(k) {
			t.Fatalf("expected NOT insider kind: %q", k)
		}
	}
}

func TestAnnotateExposure(t *testing.T) {
	r := Row{
		ArtifactKind:        KindCobranzaCSV,
		HasPasswordInConfig: true,
		ClienteCuitPrefix:   "27",
		ClienteCuitSuffix4:  "1114",
		FileMode:            0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasClienteCuit {
		t.Fatal("cliente cuit must flag")
	}
	if !r.HasCobranzaCSV {
		t.Fatal("cobranza kind must auto-flag")
	}
	if !r.HasConsumerCreditPII {
		t.Fatal("cobranza + cuit = consumer credit PII")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatal("readable + password + cliente = exposure")
	}
	if !r.IsConsumerCreditPIIRisk {
		t.Fatal("readable + cobranza + cuit = consumer credit PII risk")
	}
}

func TestAnnotateAdverseCredit(t *testing.T) {
	r := Row{
		ArtifactKind:       KindMoraCSV,
		ClienteCuitPrefix:  "27",
		ClienteCuitSuffix4: "1114",
		FileMode:           0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasAdverseCreditEvent {
		t.Fatal("mora + cuit = adverse credit event")
	}
	if !r.IsConsumerCreditPIIRisk {
		t.Fatal("readable + mora + cuit = consumer credit PII risk")
	}
}

func TestAnnotateInsiderInfo(t *testing.T) {
	r := Row{
		ArtifactKind: KindAdministratorReport,
		FileMode:     0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasAdministratorReport {
		t.Fatal("administrator report must flag")
	}
	if !r.IsInsiderInformationRisk {
		t.Fatal("readable + admin report = insider info risk")
	}
}

func TestAnnotatePreIssuanceDraftRisk(t *testing.T) {
	r := Row{
		ArtifactKind:        KindSuplementoSerie,
		HasPreIssuanceDraft: true,
		FileMode:            0o644,
	}
	AnnotateSecurity(&r)
	if !r.IsInsiderInformationRisk {
		t.Fatal("readable + pre-issuance draft = insider info risk")
	}
}

func TestParseSuplemento(t *testing.T) {
	body := []byte(`Suplemento Serie XXIV
BORRADOR - NO CIRCULAR
series_id: SERIE-XXIV
cnv_authorization: CNV-2026-0123
fideicomiso_nombre: FF Tarjeta Naranja Trust XXIV
underlying: tarjeta credito
tranche: VRD Senior
rating: AAA
issuance_amount: 50000000000
originador_cuit: 30-71234567-8
fiduciario_cuit: 30-99999999-1
`)
	f := ParseSuplemento(body)
	if f.SeriesID != "SERIE-XXIV" {
		t.Fatalf("series=%q", f.SeriesID)
	}
	if f.CNVAuthorizationID != "CNV-2026-0123" {
		t.Fatalf("cnv=%q", f.CNVAuthorizationID)
	}
	if f.UnderlyingClass != UnderlyingTarjetaCredito {
		t.Fatalf("underlying=%q want tarjeta-credito", f.UnderlyingClass)
	}
	if f.TrancheClass != TrancheVRDSenior {
		t.Fatalf("tranche=%q want vrd-senior", f.TrancheClass)
	}
	if f.RatingClass != RatingAAA {
		t.Fatalf("rating=%q want aaa", f.RatingClass)
	}
	if f.IssuanceAmountARSMillions != 50_000 {
		t.Fatalf("issuance=%d want 50k M ARS (50B)", f.IssuanceAmountARSMillions)
	}
	if !f.HasPreIssuanceDraft {
		t.Fatal("BORRADOR marker must flag pre-issuance")
	}
	if f.OriginadorCuitRaw == "" {
		t.Fatal("originador must extract")
	}
	if f.FiduciarioCuitRaw == "" {
		t.Fatal("fiduciario must extract")
	}
}

func TestParseCobranzaCSV(t *testing.T) {
	body := []byte(`Fecha,CUIT,Cuota,Importe,Estado
15/06/2026,27-11111111-4,1,5000,Pagada
16/06/2026,20-22222222-3,1,6000,Pagada
17/06/2026,23-33333333-4,1,7500,Pagada
collection_total: 18500
cliente_cuit: 27-11111111-4
`)
	f := ParseCobranzaCSV(body)
	if f.ReceivableCount < 3 {
		t.Fatalf("receivables=%d", f.ReceivableCount)
	}
	if f.ClienteCuitRaw == "" {
		t.Fatal("cliente cuit must extract")
	}
}

func TestParseMoraCSV(t *testing.T) {
	body := []byte(`Fecha,CUIT,Cuota,Importe,DiasMora
15/06/2026,27-11111111-4,2,5000,30
16/06/2026,20-22222222-3,3,6000,60
17/06/2026,23-33333333-4,4,7500,90
mora_amount: 18500
`)
	f := ParseMoraCSV(body)
	if f.MoraCount < 3 {
		t.Fatalf("mora count=%d", f.MoraCount)
	}
}

func TestDetectUnderlying(t *testing.T) {
	cases := map[string]UnderlyingClass{
		"tarjeta de credito":      UnderlyingTarjetaCredito,
		"credit card":             UnderlyingTarjetaCredito,
		"hipotecario":             UnderlyingMortgage,
		"prendario":               UnderlyingPrendario,
		"leasing":                 UnderlyingLeasing,
		"pyme":                    UnderlyingPYMELoan,
		"sgr":                     UnderlyingSGRPool,
		"real estate development": UnderlyingRealEstateDev,
		"agro commodity":          UnderlyingAgroCommodity,
		"export pre-financing":    UnderlyingExportPreFinance,
		"consumer credit":         UnderlyingConsumerCredit,
		"unknown stuff":           UnderlyingUnknown,
	}
	for in, want := range cases {
		got := detectUnderlying(in)
		if got != want {
			t.Fatalf("detect(%q)=%q want %q", in, got, want)
		}
	}
}

func TestDetectTranche(t *testing.T) {
	cases := map[string]TrancheClass{
		"VRD Senior":       TrancheVRDSenior,
		"VRD Mezzanine":    TrancheVRDMezzanine,
		"VRD Subordinated": TrancheVRDSubordinated,
		"CP Equity":        TrancheCPEquity,
		"CP Senior":        TrancheCPSenior,
		"unknown":          TrancheUnknown,
	}
	for in, want := range cases {
		got := detectTranche(in)
		if got != want {
			t.Fatalf("detect(%q)=%q want %q", in, got, want)
		}
	}
}

func TestDetectRating(t *testing.T) {
	cases := map[string]RatingClass{
		"AAA":  RatingAAA,
		"AA+":  RatingAA,
		"BBB-": RatingBBB,
		"D":    RatingD,
		"XX":   RatingUnknown,
	}
	for in, want := range cases {
		got := detectRating(in)
		if got != want {
			t.Fatalf("detect(%q)=%q want %q", in, got, want)
		}
	}
}

func TestClassifyRole(t *testing.T) {
	if got := classifyRole(Row{HasAdministratorReport: true}); got != RoleFiduciario {
		t.Fatalf("admin -> fiduciario, got %q", got)
	}
	if got := classifyRole(Row{HasAuditReport: true}); got != RoleAgenteControlRevision {
		t.Fatalf("audit -> agente-control, got %q", got)
	}
	if got := classifyRole(Row{HasCobranzaCSV: true}); got != RoleServicer {
		t.Fatalf("cobranza -> servicer, got %q", got)
	}
	if got := classifyRole(Row{HasOriginadorCuit: true}); got != RoleOriginador {
		t.Fatalf("originador -> originador, got %q", got)
	}
	if got := classifyRole(Row{HasInvestorList: true, HasTituloSerie: true}); got != RoleUnderwriter {
		t.Fatalf("titulo+investor -> underwriter, got %q", got)
	}
	if got := classifyRole(Row{HasInvestorList: true}); got != RoleColocador {
		t.Fatalf("investor -> colocador, got %q", got)
	}
	if got := classifyRole(Row{HasCalificacionReport: true}); got != RoleCalificadora {
		t.Fatalf("rating -> calificadora, got %q", got)
	}
	if got := classifyRole(Row{HasTituloSerie: true}); got != RoleCustodio {
		t.Fatalf("titulo -> custodio, got %q", got)
	}
	if got := classifyRole(Row{ArtifactKind: KindConfig}); got != RoleAPI {
		t.Fatalf("config -> api, got %q", got)
	}
	if got := classifyRole(Row{}); got != RoleUnknown {
		t.Fatalf("unknown, got %q", got)
	}
}

func TestCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")
	ffDir := filepath.Join(usersBase, "alice", "AppData", "Roaming",
		"BACS Fiduciario", "FF Naranja XXIV")
	must(t, os.MkdirAll(ffDir, 0o755))

	supPath := filepath.Join(ffDir, "suplemento_serie_XXIV.pdf")
	must(t, os.WriteFile(supPath, []byte(`Suplemento Serie XXIV
BORRADOR
series_id: SERIE-XXIV
underlying: tarjeta credito
tranche: VRD Senior
rating: AAA
issuance_amount: 50000000000
originador_cuit: 30-71234567-8
`), 0o644))

	cobPath := filepath.Join(ffDir, "cobranza_202606.csv")
	must(t, os.WriteFile(cobPath, []byte(`Fecha,CUIT,Cuota,Importe,Estado
15/06/2026,27-11111111-4,1,5000,Pagada
16/06/2026,20-22222222-3,1,6000,Pagada
17/06/2026,23-33333333-4,1,7500,Pagada
cliente_cuit: 27-11111111-4
`), 0o644))

	moraPath := filepath.Join(ffDir, "mora_202606.csv")
	must(t, os.WriteFile(moraPath, []byte(`Fecha,CUIT,Cuota,Importe,DiasMora
15/06/2026,27-11111111-4,2,5000,30
16/06/2026,20-22222222-3,3,6000,60
cliente_cuit: 27-11111111-4
`), 0o644))

	must(t, os.WriteFile(filepath.Join(ffDir, "random.txt"),
		[]byte(`nope`), 0o644))

	pub := filepath.Join(usersBase, "Public", "AppData", "Roaming",
		"BACS Fiduciario")
	must(t, os.MkdirAll(pub, 0o755))
	must(t, os.WriteFile(filepath.Join(pub, "prospecto.pdf"),
		[]byte(`# public`), 0o644))

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
		t.Fatalf("want 3 (sup+cob+mora), got %d: %+v", len(got), got)
	}

	var sup, cob, mora Row
	for _, r := range got {
		switch r.FilePath {
		case supPath:
			sup = r
		case cobPath:
			cob = r
		case moraPath:
			mora = r
		}
	}

	if sup.ArtifactKind != KindSuplementoSerie {
		t.Fatalf("sup kind=%q", sup.ArtifactKind)
	}
	if !sup.HasSuplementoSerie {
		t.Fatalf("sup must flag: %+v", sup)
	}
	if !sup.HasPreIssuanceDraft {
		t.Fatalf("sup must flag BORRADOR pre-issuance: %+v", sup)
	}
	if sup.TrancheClass != TrancheVRDSenior {
		t.Fatalf("sup tranche=%q", sup.TrancheClass)
	}
	if sup.RatingClass != RatingAAA {
		t.Fatalf("sup rating=%q", sup.RatingClass)
	}
	if !sup.IsInsiderInformationRisk {
		t.Fatalf("sup must flag insider info (readable + pre-issuance): %+v", sup)
	}

	if cob.ArtifactKind != KindCobranzaCSV {
		t.Fatalf("cob kind=%q", cob.ArtifactKind)
	}
	if !cob.HasCobranzaCSV {
		t.Fatalf("cob must flag: %+v", cob)
	}
	if !cob.HasConsumerCreditPII {
		t.Fatalf("cob must flag consumer credit PII: %+v", cob)
	}
	if cob.TrustRole != RoleServicer {
		t.Fatalf("cob should classify as servicer, got %q", cob.TrustRole)
	}
	if !cob.IsConsumerCreditPIIRisk {
		t.Fatalf("cob must flag consumer credit PII risk: %+v", cob)
	}

	if mora.ArtifactKind != KindMoraCSV {
		t.Fatalf("mora kind=%q", mora.ArtifactKind)
	}
	if !mora.HasMoraCSV {
		t.Fatalf("mora must flag: %+v", mora)
	}
	if !mora.HasAdverseCreditEvent {
		t.Fatalf("mora must flag adverse credit: %+v", mora)
	}
	if !mora.IsConsumerCreditPIIRisk {
		t.Fatalf("mora must flag consumer credit PII risk: %+v", mora)
	}
}

func TestCollectorEnvOverride(t *testing.T) {
	tmp := t.TempDir()
	custom := filepath.Join(tmp, "custom-ff")
	must(t, os.MkdirAll(custom, 0o755))
	must(t, os.WriteFile(filepath.Join(custom, "fideicomiso_config.ini"),
		[]byte(`[FF]
fiduciario_password=hello
`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "FIDEICOMISO_DIR" {
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
		installRoots: []string{"/nope-ff"},
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
		{FilePath: "/b", ArtifactKind: KindCobranzaCSV},
		{FilePath: "/a", ArtifactKind: KindProspecto},
		{FilePath: "/a", ArtifactKind: KindCobranzaCSV},
	}
	SortRows(rs)
	if rs[0].FilePath != "/a" || rs[0].ArtifactKind != KindCobranzaCSV {
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
