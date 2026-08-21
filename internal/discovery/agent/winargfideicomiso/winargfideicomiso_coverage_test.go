package winargfideicomiso

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// fixedClock pins the house-standard collector clock.
func fixedClock() time.Time { return time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC) }

// newTestCollector wires a fileCollector with real fs seams and the
// fixed clock, mirroring the reference winargbyma helper.
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

func paths(rs []Row) []string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		out = append(out, r.FilePath)
	}
	return out
}

// -- constructor + name -------------------------------------------

func TestNewCollectorName(t *testing.T) {
	c := NewCollector()
	if c == nil {
		t.Fatal("NewCollector returned nil")
	}
	if c.Name() != "winargfideicomiso" {
		t.Fatalf("name=%q want winargfideicomiso", c.Name())
	}
}

// -- default path sets --------------------------------------------

func TestDefaultPathSets(t *testing.T) {
	roots := DefaultInstallRoots()
	if len(roots) != 7 {
		t.Fatalf("install roots=%d want 7", len(roots))
	}
	bases := DefaultUsersBases()
	if len(bases) != 3 {
		t.Fatalf("users bases=%d want 3", len(bases))
	}
	if UserFFDirs() == nil || len(UserFFDirs()) == 0 {
		t.Fatal("user ff dirs must be non-empty")
	}
}

// -- extension / prefix classifiers -------------------------------

func TestIsCandidateExtCoverage(t *testing.T) {
	yes := []string{
		"a.xml", "a.json", "a.cfg", "a.ini", "a.csv", "a.tsv",
		"a.log", "a.txt", "a.xlsx", "a.xls", "a.ods", "a.pdf",
		"a.doc", "a.docx", "a.msi", "a.exe", "a.pkg", "a.dmg",
		"A.PDF", "REPORT.CSV",
	}
	for _, n := range yes {
		if !IsCandidateExt(n) {
			t.Fatalf("expected candidate ext: %q", n)
		}
	}
	no := []string{"", "a.bin", "a.dat", "a.zip", "noext"}
	for _, n := range no {
		if IsCandidateExt(n) {
			t.Fatalf("expected NOT candidate ext: %q", n)
		}
	}
}

func TestIsValidCuitEntityPrefixCoverage(t *testing.T) {
	for _, p := range []string{"20", "23", "24", "27", "30", "33", "34"} {
		if !IsValidCuitEntityPrefix(p) {
			t.Fatalf("expected valid prefix %q", p)
		}
	}
	for _, p := range []string{"99", "00", "", "3"} {
		if IsValidCuitEntityPrefix(p) {
			t.Fatalf("expected invalid prefix %q", p)
		}
	}
	if !IsValidCuitEntityOnlyPrefix("30") || IsValidCuitEntityOnlyPrefix("27") {
		t.Fatal("entity-only prefix membership drift")
	}
}

func TestCuitFingerprintRejectsBadPrefix(t *testing.T) {
	// Prefix 99 is not a valid entity prefix -> rejected.
	if p, s := CuitFingerprint("x 99-11111111-4"); p != "" || s != "" {
		t.Fatalf("bad-prefix fingerprint=(%q,%q) want empty", p, s)
	}
	// No CUIT at all -> empty.
	if p, s := CuitEntityOnlyFingerprint("no cuit here"); p != "" || s != "" {
		t.Fatalf("no-cuit entity fingerprint=(%q,%q) want empty", p, s)
	}
	// Individual prefix 20 valid for generic fingerprint.
	if p, s := CuitFingerprint("deudor 20-33333333-9"); p != "20" || s != "3339" {
		t.Fatalf("fingerprint=(%q,%q) want (20,3339)", p, s)
	}
}

func TestPeriodFromFilenameCoverage(t *testing.T) {
	if got := PeriodFromFilename("cobranza_202606.csv"); got != "202606" {
		t.Fatalf("period=%q want 202606", got)
	}
	if got := PeriodFromFilename("prospecto_2026.pdf"); got != "2026" {
		t.Fatalf("year period=%q want 2026", got)
	}
	if got := PeriodFromFilename("prospecto.pdf"); got != "" {
		t.Fatalf("no-period=%q want empty", got)
	}
}

// -- kind predicates: unknown enum hits trailing return -----------

func TestIsCredentialKindUnknownEnum(t *testing.T) {
	if IsCredentialKind(ArtifactKind("weird-not-a-kind")) {
		t.Fatal("unknown enum must not be credential kind")
	}
	if IsInsiderKind(ArtifactKind("weird-not-a-kind")) {
		t.Fatal("unknown enum must not be insider kind")
	}
}

func TestArtifactKindFromNameExtra(t *testing.T) {
	cases := map[string]ArtifactKind{
		"generic_setup.exe":         KindOther, // exe without FF token
		"session_token.json":        KindCredentials,
		"precancelacion_202606.csv": KindPrecancelacionCSV,
		"escritura_naranja.pdf":     KindEscrituraFiduciaria,
		"contrato_fiduciario_x.pdf": KindContratoFiduciario,
		"filing_receipt_202606.xml": KindFilingReceipt,
		"auditoria_202606.pdf":      KindAuditReport,
		"colocador_notes.txt":       KindOther, // candidate name, no kind token
	}
	for in, want := range cases {
		if got := ArtifactKindFromName(in); got != want {
			t.Fatalf("ArtifactKindFromName(%q)=%q want %q", in, got, want)
		}
	}
}

// -- hashers ------------------------------------------------------

func TestHashSecretEmpty(t *testing.T) {
	if HashSecret("") != "" {
		t.Fatal("empty secret must hash to empty string")
	}
	if HashSecret("   ") != "" {
		t.Fatal("whitespace-only secret must hash to empty string")
	}
	if len(HashContents([]byte("abc"))) != 64 {
		t.Fatal("content hash must be 64 hex chars")
	}
}

// -- rating / tranche detection remaining branches ----------------

func TestDetectRatingAllBranches(t *testing.T) {
	cases := map[string]RatingClass{
		"AAA":  RatingAAA,
		"AA":   RatingAA,
		"A":    RatingA,
		"BBB":  RatingBBB,
		"BB":   RatingBB,
		"B":    RatingB,
		"CCC":  RatingCCC,
		"CC":   RatingCC,
		"C":    RatingC,
		"D":    RatingD,
		"aa+":  RatingAA, // lowercased + trailing modifier stripped
		"bbb-": RatingBBB,
		"zzz":  RatingUnknown,
	}
	for in, want := range cases {
		if got := detectRating(in); got != want {
			t.Fatalf("detectRating(%q)=%q want %q", in, got, want)
		}
	}
}

func TestDetectTrancheDefaults(t *testing.T) {
	// "vrd" with no sub-qualifier falls to the VRD-senior default.
	if got := detectTranche("VRD"); got != TrancheVRDSenior {
		t.Fatalf("detectTranche(VRD)=%q want vrd-senior", got)
	}
	// "cp" with no sub-qualifier falls to the CP-equity default.
	if got := detectTranche("CP"); got != TrancheCPEquity {
		t.Fatalf("detectTranche(CP)=%q want cp-equity", got)
	}
}

// -- parser exact-value assertions --------------------------------

func TestParseProspectoExact(t *testing.T) {
	body := []byte(`Prospecto FF Naranja
CONFIDENCIAL
series_id: SERIE-XXIV
cnv_authorization: CNV-2026-0999
fideicomiso_nombre: FF Tarjeta Naranja Trust XXIV
underlying: tarjeta credito
issuance_amount: 30000000000
originador_cuit: 30-71234567-8
fiduciario_cuit: 33-99999999-1
cliente_cuit: 27-11111111-4
`)
	f := ParseProspecto(body)
	if f.SeriesID != "SERIE-XXIV" {
		t.Fatalf("series=%q", f.SeriesID)
	}
	if f.CNVAuthorizationID != "CNV-2026-0999" {
		t.Fatalf("cnv=%q", f.CNVAuthorizationID)
	}
	if f.UnderlyingClass != UnderlyingTarjetaCredito {
		t.Fatalf("underlying=%q", f.UnderlyingClass)
	}
	if f.IssuanceAmountARSMillions != 30_000 {
		t.Fatalf("issuance=%d want 30000", f.IssuanceAmountARSMillions)
	}
	if !f.HasPreIssuanceDraft {
		t.Fatal("CONFIDENCIAL marker must flag pre-issuance")
	}
	if f.OriginadorCuitRaw != "30-71234567-8" {
		t.Fatalf("originador raw=%q", f.OriginadorCuitRaw)
	}
	if f.FiduciarioCuitRaw != "33-99999999-1" {
		t.Fatalf("fiduciario raw=%q", f.FiduciarioCuitRaw)
	}
	if f.ClienteCuitRaw != "27-11111111-4" {
		t.Fatalf("cliente raw=%q", f.ClienteCuitRaw)
	}
}

func TestParseEscrituraAndContrato(t *testing.T) {
	body := []byte(`Escritura Fiduciaria
BORRADOR - NO CIRCULAR
series_id: SERIE-XV
`)
	e := ParseEscritura(body)
	if e.SeriesID != "SERIE-XV" {
		t.Fatalf("escritura series=%q", e.SeriesID)
	}
	if !e.HasPreIssuanceDraft {
		t.Fatal("escritura BORRADOR must flag pre-issuance")
	}
	// Contrato delegates to escritura.
	c := ParseContratoFiduciario(body)
	if c.SeriesID != "SERIE-XV" || !c.HasPreIssuanceDraft {
		t.Fatalf("contrato mismatch: %+v", c)
	}
	// Plain escritura without markers stays clean.
	clean := ParseEscritura([]byte("Escritura Fiduciaria\nseries_id: SERIE-ZZ\n"))
	if clean.HasPreIssuanceDraft {
		t.Fatal("clean escritura must not flag pre-issuance")
	}
}

func TestParseCobranzaAndPrecancelacionExact(t *testing.T) {
	body := []byte(`Fecha,CUIT,Cuota,Importe,Estado
15/06/2026,27-11111111-4,1,5000,Pagada
16/06/2026,20-22222222-3,1,6000,Pagada
17/06/2026,23-33333333-4,1,7500,Pagada
collection_total: 18000000
cliente_cuit: 27-11111111-4
`)
	f := ParseCobranzaCSV(body)
	if f.ReceivableCount != 3 {
		t.Fatalf("receivables=%d want 3", f.ReceivableCount)
	}
	if f.CollectionTotalARSMillions != 18 {
		t.Fatalf("collection=%d want 18", f.CollectionTotalARSMillions)
	}
	if f.ClienteCuitRaw != "27-11111111-4" {
		t.Fatalf("cliente=%q", f.ClienteCuitRaw)
	}
	// Precancelacion delegates to cobranza.
	p := ParsePrecancelacionCSV(body)
	if p.ReceivableCount != 3 || p.CollectionTotalARSMillions != 18 {
		t.Fatalf("precancelacion mismatch: %+v", p)
	}
}

func TestParseCobranzaKeyFallback(t *testing.T) {
	// No per-row data lines -> fall back to receivable_count key.
	body := []byte("resumen\nreceivable_count: 42\ncollection_total: 9000000\n")
	f := ParseCobranzaCSV(body)
	if f.ReceivableCount != 42 {
		t.Fatalf("receivable_count fallback=%d want 42", f.ReceivableCount)
	}
	if f.CollectionTotalARSMillions != 9 {
		t.Fatalf("collection=%d want 9", f.CollectionTotalARSMillions)
	}
}

func TestParseMoraExactAndFallback(t *testing.T) {
	rows := []byte(`Fecha,CUIT,Cuota,Importe,DiasMora
15/06/2026,27-11111111-4,2,5000,30
16/06/2026,20-22222222-3,3,6000,60
mora_amount: 11000000
`)
	f := ParseMoraCSV(rows)
	if f.MoraCount != 2 {
		t.Fatalf("mora count=%d want 2", f.MoraCount)
	}
	if f.MoraAmountARSMillions != 11 {
		t.Fatalf("mora amount=%d want 11", f.MoraAmountARSMillions)
	}
	// Key fallback when no per-row lines present.
	fk := ParseMoraCSV([]byte("resumen\nmora_count: 7\n"))
	if fk.MoraCount != 7 {
		t.Fatalf("mora_count fallback=%d want 7", fk.MoraCount)
	}
}

func TestParseTituloSerieExact(t *testing.T) {
	body := []byte(`Titulo Serie VRD
tranche: VRD Mezzanine
rating: BBB-
series_id: SERIE-XXIV
`)
	f := ParseTituloSerie(body)
	if f.TrancheClass != TrancheVRDMezzanine {
		t.Fatalf("tranche=%q want vrd-mezzanine", f.TrancheClass)
	}
	if f.RatingClass != RatingBBB {
		t.Fatalf("rating=%q want bbb", f.RatingClass)
	}
	if f.SeriesID != "SERIE-XXIV" {
		t.Fatalf("series=%q", f.SeriesID)
	}
}

func TestParseInvestorListExactAndFallback(t *testing.T) {
	rows := []byte(`Fecha,CUIT,Monto,Serie,Tipo
15/06/2026,30-71234567-8,1000,XXIV,VRD
16/06/2026,33-99999999-1,2000,XXIV,VRD
`)
	f := ParseInvestorList(rows)
	if f.InvestorCount != 2 {
		t.Fatalf("investor count=%d want 2", f.InvestorCount)
	}
	fk := ParseInvestorList([]byte("resumen\ninvestor_count: 15\n"))
	if fk.InvestorCount != 15 {
		t.Fatalf("investor_count fallback=%d want 15", fk.InvestorCount)
	}
}

func TestParseCalificacionExact(t *testing.T) {
	f := ParseCalificacionReport([]byte("Dictamen de Calificacion\nrating: AA+\n"))
	if f.RatingClass != RatingAA {
		t.Fatalf("rating=%q want aa", f.RatingClass)
	}
}

func TestParseAdministratorReportExact(t *testing.T) {
	body := []byte(`Reporte Administrador Fiduciario
INTERNO
collection_total: 25000000
mora_amount: 4000000
`)
	f := ParseAdministratorReport(body)
	if f.CollectionTotalARSMillions != 25 {
		t.Fatalf("collection=%d want 25", f.CollectionTotalARSMillions)
	}
	if f.MoraAmountARSMillions != 4 {
		t.Fatalf("mora amount=%d want 4", f.MoraAmountARSMillions)
	}
	if !f.HasPreIssuanceDraft {
		t.Fatal("INTERNO marker must flag pre-issuance")
	}
}

func TestParseAuditAndFilingReceipt(t *testing.T) {
	a := ParseAuditReport([]byte("Informe Agente Control\nBORRADOR\nseries_id: SERIE-Q\n"))
	if a.SeriesID != "SERIE-Q" || !a.HasPreIssuanceDraft {
		t.Fatalf("audit mismatch: %+v", a)
	}
	r := ParseFilingReceipt([]byte("CNV Filing Receipt\ncnv_authorization: CNV-2026-7777\n"))
	if r.CNVAuthorizationID != "CNV-2026-7777" {
		t.Fatalf("filing cnv=%q", r.CNVAuthorizationID)
	}
}

func TestParseCommonEmptyBody(t *testing.T) {
	f := ParseProspecto(nil)
	if f.SeriesID != "" || f.HasPassword || f.HasPreIssuanceDraft {
		t.Fatalf("empty body must yield zero fields: %+v", f)
	}
	e := ParseFilingReceipt([]byte{})
	if e.CNVAuthorizationID != "" {
		t.Fatal("empty filing receipt must be clean")
	}
}

func TestParseConfigPassword(t *testing.T) {
	f := ParseConfig([]byte("[FF]\nfiduciario_password=hunter2\n"))
	if !f.HasPassword {
		t.Fatal("config with password must flag HasPassword")
	}
}

// -- mergeFields dispatch across every kind -----------------------

func TestMergeFieldsDispatch(t *testing.T) {
	c := newTestCollector(nil, nil, nil)

	// Prospecto: common + issuance + pre-issuance.
	prosBody := []byte(`Prospecto
BORRADOR
series_id: SERIE-A
cnv_authorization: CNV-2026-0001
fideicomiso_nombre: FF Trust One
underlying: mortgage
issuance_amount: 12000000000
originador_cuit: 30-71234567-8
fiduciario_cuit: 33-99999999-1
`)
	pros := Row{ArtifactKind: KindProspecto}
	c.mergeFields(&pros, prosBody)
	if pros.SeriesID != "SERIE-A" || pros.CNVAuthorizationID != "CNV-2026-0001" {
		t.Fatalf("prospecto merge series/cnv: %+v", pros)
	}
	if pros.FFNameHash == "" || len(pros.FFNameHash) != 64 {
		t.Fatalf("prospecto ff name hash: %q", pros.FFNameHash)
	}
	if pros.UnderlyingClass != UnderlyingMortgage {
		t.Fatalf("prospecto underlying=%q", pros.UnderlyingClass)
	}
	if pros.IssuanceAmountARSMillions != 12_000 {
		t.Fatalf("prospecto issuance=%d", pros.IssuanceAmountARSMillions)
	}
	if !pros.HasPreIssuanceDraft {
		t.Fatal("prospecto must flag pre-issuance")
	}
	if pros.OriginadorCuitPrefix != "30" || pros.OriginadorCuitSuffix4 != "5678" {
		t.Fatalf("prospecto originador=(%q,%q)", pros.OriginadorCuitPrefix, pros.OriginadorCuitSuffix4)
	}
	if pros.FiduciarioCuitPrefix != "33" || pros.FiduciarioCuitSuffix4 != "9991" {
		t.Fatalf("prospecto fiduciario=(%q,%q)", pros.FiduciarioCuitPrefix, pros.FiduciarioCuitSuffix4)
	}

	// Suplemento: tranche + rating.
	sup := Row{ArtifactKind: KindSuplementoSerie}
	c.mergeFields(&sup, []byte("tranche: VRD Senior\nrating: AAA\n"))
	if sup.TrancheClass != TrancheVRDSenior || sup.RatingClass != RatingAAA {
		t.Fatalf("suplemento merge: %+v", sup)
	}

	// Cobranza: receivable + collection + password + cliente cuit.
	cob := Row{ArtifactKind: KindCobranzaCSV}
	c.mergeFields(&cob, []byte("password=secret1\ncliente_cuit: 27-11111111-4\n"+
		"receivable_count: 5\ncollection_total: 6000000\n"))
	if !cob.HasPasswordInConfig {
		t.Fatalf("cobranza must merge password: %+v", cob)
	}
	if cob.ReceivableCount != 5 || cob.CollectionTotalARSMillions != 6 {
		t.Fatalf("cobranza counts: %+v", cob)
	}
	if cob.ClienteCuitPrefix != "27" || cob.ClienteCuitSuffix4 != "1114" {
		t.Fatalf("cobranza cliente=(%q,%q)", cob.ClienteCuitPrefix, cob.ClienteCuitSuffix4)
	}

	// Mora: mora count + amount.
	mora := Row{ArtifactKind: KindMoraCSV}
	c.mergeFields(&mora, []byte("mora_count: 8\nmora_amount: 3000000\n"))
	if mora.MoraCount != 8 || mora.MoraAmountARSMillions != 3 {
		t.Fatalf("mora merge: %+v", mora)
	}

	// Investor list: investor count.
	inv := Row{ArtifactKind: KindInvestorList}
	c.mergeFields(&inv, []byte("investor_count: 12\n"))
	if inv.InvestorCount != 12 {
		t.Fatalf("investor merge: %+v", inv)
	}

	// Each remaining dispatch case must not panic and returns a body.
	for _, k := range []ArtifactKind{
		KindEscrituraFiduciaria, KindContratoFiduciario,
		KindPrecancelacionCSV, KindTituloSerie,
		KindCalificacionReport, KindAdministratorReport,
		KindAuditReport, KindFilingReceipt,
		KindConfig, KindCredentials,
	} {
		row := Row{ArtifactKind: k}
		c.mergeFields(&row, []byte("series_id: SERIE-K\nrating: BBB\ntranche: CP Equity\n"))
	}

	// Installer / other / unknown short-circuit with no field changes.
	for _, k := range []ArtifactKind{KindInstaller, KindOther, KindUnknown} {
		row := Row{ArtifactKind: k, SeriesID: "keep"}
		c.mergeFields(&row, []byte("series_id: SERIE-IGNORED\n"))
		if row.SeriesID != "keep" {
			t.Fatalf("kind %q must not merge fields", k)
		}
	}
}

// -- AnnotateSecurity flag + threshold matrix ---------------------

func TestAnnotateSecurityModeMatrix(t *testing.T) {
	// World-readable (0o644): world bit set, group bit set.
	world := Row{ArtifactKind: KindProspecto, FileMode: 0o644}
	AnnotateSecurity(&world)
	if !world.IsWorldReadable {
		t.Fatal("0o644 must be world-readable")
	}
	if !world.IsGroupReadable {
		t.Fatal("0o644 must be group-readable")
	}
	if !world.HasProspecto {
		t.Fatal("prospecto auto-flag")
	}

	// Group-only (0o640): group readable, not world readable.
	group := Row{ArtifactKind: KindInvestorList, FileMode: 0o640}
	AnnotateSecurity(&group)
	if group.IsWorldReadable {
		t.Fatal("0o640 must not be world-readable")
	}
	if !group.IsGroupReadable {
		t.Fatal("0o640 must be group-readable")
	}
	if !group.HasInvestorList {
		t.Fatal("investor list auto-flag")
	}
	// Group readable + investor-list credential signal => exposure.
	if !group.IsCredentialExposureRisk {
		t.Fatalf("group readable investor list = exposure: %+v", group)
	}

	// Locked down (0o600): neither readable bit set.
	locked := Row{
		ArtifactKind:        KindCobranzaCSV,
		HasPasswordInConfig: true,
		ClienteCuitPrefix:   "27",
		ClienteCuitSuffix4:  "1114",
		FileMode:            0o600,
	}
	AnnotateSecurity(&locked)
	if locked.IsWorldReadable || locked.IsGroupReadable {
		t.Fatal("0o600 must not be readable")
	}
	if !locked.HasClienteCuit || !locked.HasConsumerCreditPII {
		t.Fatalf("cobranza + cuit still flags PII regardless of mode: %+v", locked)
	}
	if locked.IsCredentialExposureRisk || locked.IsConsumerCreditPIIRisk {
		t.Fatalf("locked-down file must carry no exposure risk: %+v", locked)
	}

	// FileMode 0 => permission block skipped entirely.
	zero := Row{ArtifactKind: KindProspecto, FileMode: 0}
	AnnotateSecurity(&zero)
	if zero.IsWorldReadable || zero.IsGroupReadable {
		t.Fatal("FileMode 0 leaves readability flags unset")
	}
}

func TestAnnotateSecurityInsiderKinds(t *testing.T) {
	// Readable escritura => insider info risk via IsInsiderKind path.
	esc := Row{ArtifactKind: KindEscrituraFiduciaria, FileMode: 0o644}
	AnnotateSecurity(&esc)
	if !esc.HasEscrituraFiduciaria || !esc.IsInsiderInformationRisk {
		t.Fatalf("escritura insider risk: %+v", esc)
	}

	// Readable contrato => insider info risk.
	con := Row{ArtifactKind: KindContratoFiduciario, FileMode: 0o644}
	AnnotateSecurity(&con)
	if !con.HasContratoFiduciario || !con.IsInsiderInformationRisk {
		t.Fatalf("contrato insider risk: %+v", con)
	}

	// Readable audit report => insider info risk.
	aud := Row{ArtifactKind: KindAuditReport, FileMode: 0o644}
	AnnotateSecurity(&aud)
	if !aud.HasAuditReport || !aud.IsInsiderInformationRisk {
		t.Fatalf("audit insider risk: %+v", aud)
	}

	// Originador CUIT present sets HasOriginadorCuit.
	orig := Row{ArtifactKind: KindProspecto, OriginadorCuitPrefix: "30", FileMode: 0o600}
	AnnotateSecurity(&orig)
	if !orig.HasOriginadorCuit {
		t.Fatal("originador cuit prefix must set HasOriginadorCuit")
	}
	if orig.IsInsiderInformationRisk {
		t.Fatal("prospecto is not insider kind and has no draft => no insider risk")
	}

	// Non-flagging kinds (filing receipt / config) auto-flag nothing.
	fr := Row{ArtifactKind: KindFilingReceipt, FileMode: 0o644}
	AnnotateSecurity(&fr)
	if fr.IsInsiderInformationRisk || fr.IsCredentialExposureRisk {
		t.Fatalf("filing receipt carries no auto risk: %+v", fr)
	}
}

// -- classifyRole remaining branch --------------------------------

func TestClassifyRoleComplianceOfficer(t *testing.T) {
	if got := classifyRole(Row{ArtifactKind: KindFilingReceipt}); got != RoleComplianceOfficer {
		t.Fatalf("filing receipt -> compliance officer, got %q", got)
	}
	if got := classifyRole(Row{ArtifactKind: KindCredentials}); got != RoleAPI {
		t.Fatalf("credentials -> api, got %q", got)
	}
}

// -- SortRows period tiebreaker -----------------------------------

func TestSortRowsPeriodTiebreak(t *testing.T) {
	rs := []Row{
		{FilePath: "/a", ArtifactKind: KindCobranzaCSV, ReportingPeriod: "202608"},
		{FilePath: "/a", ArtifactKind: KindCobranzaCSV, ReportingPeriod: "202601"},
	}
	SortRows(rs)
	if rs[0].ReportingPeriod != "202601" {
		t.Fatalf("period tiebreak drift: %+v", rs)
	}
}

// -- ownerUID non-Stat_t fallback ---------------------------------

type fakeFileInfo struct {
	name string
	size int64
	mode os.FileMode
	mod  time.Time
}

func (f fakeFileInfo) Name() string       { return f.name }
func (f fakeFileInfo) Size() int64        { return f.size }
func (f fakeFileInfo) Mode() os.FileMode  { return f.mode }
func (f fakeFileInfo) ModTime() time.Time { return f.mod }
func (f fakeFileInfo) IsDir() bool        { return f.mode.IsDir() }
func (f fakeFileInfo) Sys() any           { return nil }

func TestOwnerUIDFallback(t *testing.T) {
	if got := ownerUID(fakeFileInfo{}); got != 0 {
		t.Fatalf("ownerUID with non-Stat_t Sys must be 0, got %d", got)
	}
}

// -- collector: install-root walk, dedup, skip-body, seams --------

func TestCollectorWalksInstallTree(t *testing.T) {
	tmp := t.TempDir()
	root := filepath.Join(tmp, "Fideicomiso")
	nested := filepath.Join(root, "Series", "XXIV")
	must(t, os.MkdirAll(nested, 0o755))

	// Prospecto in a nested dir (exercises walk recursion).
	prosPath := filepath.Join(nested, "prospecto_ff_naranja.pdf")
	must(t, os.WriteFile(prosPath, []byte(`Prospecto
CONFIDENCIAL
series_id: SERIE-XXIV
underlying: hipotecario
issuance_amount: 20000000000
`), 0o644))

	// Installer .msi -> skipBody hash-only path.
	msiPath := filepath.Join(root, "fideicomiso_setup.msi")
	must(t, os.WriteFile(msiPath, []byte("MSI fake installer"), 0o644))

	// Candidate name but KindOther -> mergeFields early return.
	otherPath := filepath.Join(root, "bacs_notes.txt")
	must(t, os.WriteFile(otherPath, []byte("just bacs notes"), 0o644))

	// Non-candidate extension skipped by walk.
	must(t, os.WriteFile(filepath.Join(root, "prospecto.bin"), []byte("x"), 0o644))
	// Candidate extension but non-candidate name skipped by walk.
	must(t, os.WriteFile(filepath.Join(root, "random.csv"), []byte("noise"), 0o644))

	c := newTestCollector([]string{root}, nil, nil)
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("want 3 rows, got %d: %v", len(got), paths(got))
	}

	byPath := map[string]Row{}
	for _, r := range got {
		byPath[r.FilePath] = r
	}

	pros := byPath[prosPath]
	if pros.ArtifactKind != KindProspecto {
		t.Fatalf("pros kind=%q", pros.ArtifactKind)
	}
	if pros.UnderlyingClass != UnderlyingMortgage {
		t.Fatalf("pros underlying=%q", pros.UnderlyingClass)
	}
	if pros.IssuanceAmountARSMillions != 20_000 {
		t.Fatalf("pros issuance=%d", pros.IssuanceAmountARSMillions)
	}
	if len(pros.FileHash) != 64 {
		t.Fatalf("pros hash len=%d", len(pros.FileHash))
	}
	if !pros.HasPreIssuanceDraft || !pros.IsInsiderInformationRisk {
		t.Fatalf("pros insider risk: %+v", pros)
	}

	msi := byPath[msiPath]
	if msi.ArtifactKind != KindInstaller {
		t.Fatalf("msi kind=%q", msi.ArtifactKind)
	}
	if len(msi.FileHash) != 64 {
		t.Fatalf("msi hash-only path must populate hash, got %q", msi.FileHash)
	}

	other := byPath[otherPath]
	if other.ArtifactKind != KindOther {
		t.Fatalf("other kind=%q want other", other.ArtifactKind)
	}
}

func TestCollectorDedupesRepeatedRoot(t *testing.T) {
	tmp := t.TempDir()
	root := filepath.Join(tmp, "Fideicomiso")
	must(t, os.MkdirAll(root, 0o755))
	must(t, os.WriteFile(filepath.Join(root, "cobranza_202606.csv"),
		[]byte(`Fecha,CUIT,Cuota,Importe,Estado
15/06/2026,27-11111111-4,1,5000,Pagada
cliente_cuit: 27-11111111-4
`), 0o644))

	// FIDEICOMISO_DIR points at the same root => walked twice, second
	// pass hits the consider() dedup guard.
	c := newTestCollector([]string{root}, nil, func(k string) string {
		if k == "FIDEICOMISO_DIR" {
			return root
		}
		return ""
	})
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("dedup must yield 1 row, got %d: %v", len(got), paths(got))
	}
}

func TestCollectorConsiderErrorSeams(t *testing.T) {
	tmp := t.TempDir()
	root := filepath.Join(tmp, "Fideicomiso")
	must(t, os.MkdirAll(root, 0o755))

	statErrPath := filepath.Join(root, "cobranza_staterr.csv")
	must(t, os.WriteFile(statErrPath, []byte("cliente_cuit: 27-11111111-4\n"), 0o644))
	readErrPath := filepath.Join(root, "mora_readerr.csv")
	must(t, os.WriteFile(readErrPath, []byte("mora_count: 3\n"), 0o644))
	okPath := filepath.Join(root, "prospecto_ok.pdf")
	must(t, os.WriteFile(okPath, []byte("Prospecto\nseries_id: SERIE-OK\n"), 0o644))

	c := &fileCollector{
		installRoots: []string{root},
		usersBases:   nil,
		getenv:       func(string) string { return "" },
		readFile: func(p string) ([]byte, error) {
			if p == readErrPath {
				return nil, errors.New("boom read")
			}
			return os.ReadFile(p)
		},
		readDir: os.ReadDir,
		statFile: func(p string) (os.FileInfo, error) {
			if p == statErrPath {
				return nil, errors.New("boom stat")
			}
			return os.Stat(p)
		},
		now: fixedClock,
	}
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	byPath := map[string]Row{}
	for _, r := range got {
		byPath[r.FilePath] = r
	}
	if _, ok := byPath[statErrPath]; ok {
		t.Fatal("stat-error file must be dropped from output")
	}
	readErr, ok := byPath[readErrPath]
	if !ok {
		t.Fatal("read-error file still produces a stat-only row")
	}
	if readErr.FileHash != "" {
		t.Fatalf("read-error row must have empty hash, got %q", readErr.FileHash)
	}
	ok2, present := byPath[okPath]
	if !present || ok2.SeriesID != "SERIE-OK" {
		t.Fatalf("ok row missing or unparsed: %+v", ok2)
	}
}

func TestCollectorReadDirErrorSkipsUsersBase(t *testing.T) {
	// usersBases points at a file (not a dir) -> readDir errors -> skip.
	tmp := t.TempDir()
	notADir := filepath.Join(tmp, "not-a-dir")
	must(t, os.WriteFile(notADir, []byte("x"), 0o644))

	c := newTestCollector(nil, []string{notADir}, nil)
	got, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want empty, got %d", len(got))
	}
}
