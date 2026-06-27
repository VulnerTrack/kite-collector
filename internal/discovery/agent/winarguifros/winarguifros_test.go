package winarguifros

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindROSExport), "uif-ros-export"},
		{string(KindROIExport), "uif-roi-export"},
		{string(KindRFTExport), "uif-rft-export"},
		{string(KindPEPList), "uif-pep-list"},
		{string(KindSanctionsList), "uif-sanctions-list"},
		{string(KindKYCDossier), "uif-kyc-dossier"},
		{string(KindMonitoringAlert), "uif-monitoring-alert"},
		{string(KindSumario), "uif-sumario"},
		{string(KindComplianceReport), "uif-compliance-report"},
		{string(KindDDJJPEP), "uif-ddjj-pep"},
		{string(KindInstaller), "uif-installer"},
		{string(KindOther), "other"},
		{string(KindUnknown), "unknown"},
		{string(SujetoBank), "bank"},
		{string(SujetoALYC), "alyc"},
		{string(SujetoFCI), "fci"},
		{string(SujetoAFJP), "afjp"},
		{string(SujetoExchange), "exchange"},
		{string(SujetoEscribano), "escribano"},
		{string(SujetoCasaCambio), "casa-cambio"},
		{string(SujetoSeguros), "seguros"},
		{string(SujetoOther), "other"},
		{string(SujetoUnknown), "unknown"},
		{string(SanctionsNone), ""},
		{string(SanctionsOFAC), "ofac"},
		{string(SanctionsUN), "un"},
		{string(SanctionsEU), "eu"},
		{string(SanctionsUKHMT), "uk-hmt"},
		{string(SanctionsARGUIF), "arg-uif"},
		{string(SanctionsOther), "other"},
		{string(StatusDraft), "draft"},
		{string(StatusFiled), "filed"},
		{string(StatusRejected), "rejected"},
		{string(StatusAccepted), "accepted"},
		{string(StatusUnknown), "unknown"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestIsCandidateName(t *testing.T) {
	yes := []string{
		"ros_001_202506.xml",
		"roi_002_202506.xml",
		"rft_003_202506.xml",
		"pep_list_202506.csv",
		"ofac_consol_20260615.csv",
		"sdn_list_20260615.xml",
		"un_consolidated_20260615.xml",
		"eu_sanctions_20260615.csv",
		"kyc_27111111114.xml",
		"due_diligence_30712345678.xml",
		"alerta_monitoring_001.json",
		"sumario_001.pdf",
		"reporte_uif_001.xml",
		"ddjj_pep_27111111114.xml",
		"lavado_activos_001.xml",
		"plaft_compliance.xml",
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
		"ros_001_202506.xml":            KindROSExport,
		"roi_002_202506.xml":            KindROIExport,
		"rft_003_202506.xml":            KindRFTExport,
		"pep_list_202506.csv":           KindPEPList,
		"ofac_consol_20260615.csv":      KindSanctionsList,
		"sdn_list_20260615.xml":         KindSanctionsList,
		"un_consolidated_20260615.xml":  KindSanctionsList,
		"eu_sanctions_20260615.csv":     KindSanctionsList,
		"kyc_27111111114.xml":           KindKYCDossier,
		"due_diligence_30712345678.xml": KindKYCDossier,
		"alerta_monitoring_001.json":    KindMonitoringAlert,
		"sumario_001.pdf":               KindSumario,
		"reporte_uif_001.xml":           KindComplianceReport,
		"ddjj_pep_27111111114.xml":      KindDDJJPEP,
		"uif_v8_installer.msi":          KindInstaller,
		"":                              KindUnknown,
	}
	for in, want := range cases {
		if got := ArtifactKindFromName(in); got != want {
			t.Fatalf("ArtifactKindFromName(%q)=%q want %q", in, got, want)
		}
	}
}

func TestSujetoObligadoFromPath(t *testing.T) {
	cases := map[string]SujetoObligadoKind{
		`C:\UIF\ALYC\ros_001.xml`:             SujetoALYC,
		`C:\Bank\Compliance\uif\ros_001.xml`:  SujetoBank,
		`C:\FCI\UIF\ros_001.xml`:              SujetoFCI,
		`C:\AFJP\UIF\ros_001.xml`:             SujetoAFJP,
		`C:\Exchange\UIF\ros_001.xml`:         SujetoExchange,
		`C:\Compliance\Escribano\ros_001.xml`: SujetoEscribano,
		`C:\Casa_Cambio\UIF\ros_001.xml`:      SujetoCasaCambio,
		`C:\Seguros\UIF\ros_001.xml`:          SujetoSeguros,
		`C:\UIF\generic.xml`:                  SujetoOther,
		`C:\Random\path.txt`:                  SujetoUnknown,
		"":                                    SujetoUnknown,
	}
	for in, want := range cases {
		if got := SujetoObligadoFromPath(in); got != want {
			t.Fatalf("SujetoObligadoFromPath(%q)=%q want %q", in, got, want)
		}
	}
}

func TestIsHighRiskJurisdiction(t *testing.T) {
	yes := []string{"Iran", "iran", "DPRK", "Myanmar", "Venezuela", "Yemen"}
	no := []string{"Argentina", "USA", "Brazil", "", "Spain"}
	for _, v := range yes {
		if !IsHighRiskJurisdiction(v) {
			t.Fatalf("expected high-risk: %q", v)
		}
	}
	for _, v := range no {
		if IsHighRiskJurisdiction(v) {
			t.Fatalf("expected NOT high-risk: %q", v)
		}
	}
}

func TestSanctionsSourceFromName(t *testing.T) {
	cases := map[string]SanctionsSource{
		"ofac_consol_20260615.csv":     SanctionsOFAC,
		"sdn_list_20260615.xml":        SanctionsOFAC,
		"un_consolidated_20260615.xml": SanctionsUN,
		"eu_sanctions_20260615.csv":    SanctionsEU,
		"uk_hmt_consolidated.csv":      SanctionsUKHMT,
		"arg_sanctions_20260615.csv":   SanctionsARGUIF,
		"random_list.csv":              SanctionsOther,
		"":                             SanctionsNone,
	}
	for in, want := range cases {
		if got := SanctionsSourceFromName(in); got != want {
			t.Fatalf("SanctionsSourceFromName(%q)=%q want %q", in, got, want)
		}
	}
}

func TestCuitFingerprint(t *testing.T) {
	cases := []struct {
		in, pfx, sfx4 string
	}{
		{"cliente 27-11111111-4", "27", "1114"},
		{"officer 20-12345678-9", "20", "6789"},
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

func TestIsHumanCuitPrefix(t *testing.T) {
	yes := []string{"20", "23", "24", "27"}
	no := []string{"30", "33", "34", "", "11"}
	for _, v := range yes {
		if !IsHumanCuitPrefix(v) {
			t.Fatalf("expected human: %q", v)
		}
	}
	for _, v := range no {
		if IsHumanCuitPrefix(v) {
			t.Fatalf("expected NOT human: %q", v)
		}
	}
}

func TestPeriodFromFilename(t *testing.T) {
	if PeriodFromFilename("ros_001_202506.xml") != "202506" {
		t.Fatal("period mismatch")
	}
	if PeriodFromFilename("random.xml") != "" {
		t.Fatal("non-period must be empty")
	}
}

func TestIsHighSensitivityKind(t *testing.T) {
	yes := []ArtifactKind{
		KindKYCDossier, KindROSExport, KindROIExport,
		KindRFTExport, KindPEPList, KindMonitoringAlert,
		KindSumario, KindComplianceReport, KindDDJJPEP,
	}
	no := []ArtifactKind{
		KindSanctionsList, KindInstaller, KindOther, KindUnknown,
	}
	for _, k := range yes {
		if !IsHighSensitivityKind(k) {
			t.Fatalf("expected sensitive: %q", k)
		}
	}
	for _, k := range no {
		if IsHighSensitivityKind(k) {
			t.Fatalf("expected NOT sensitive: %q", k)
		}
	}
}

// -- AnnotateSecurity ---------------------------------------------

func TestAnnotateKYCExposure(t *testing.T) {
	r := Row{
		ArtifactKind:       KindKYCDossier,
		SujetoObligadoKind: SujetoALYC,
		ClienteCuitPrefix:  "27",
		ClienteCuitSuffix4: "1114",
		HasKYCBody:         true,
		FileMode:           0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasClienteCuit {
		t.Fatal("cliente CUIT must flag")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatalf("readable + cliente + KYC = exposure: %+v", r)
	}
}

func TestAnnotatePEPMatch(t *testing.T) {
	r := Row{
		ArtifactKind:       KindROSExport,
		PEPNameHash:        "deadbeef",
		ClienteCuitPrefix:  "27",
		ClienteCuitSuffix4: "1114",
		FileMode:           0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasPEPMatch {
		t.Fatal("PEP name hash must flag PEP match")
	}
	if !r.IsCredentialExposureRisk {
		t.Fatalf("readable + cliente + PEP = exposure: %+v", r)
	}
}

func TestAnnotateSanctionsMatch(t *testing.T) {
	r := Row{
		ArtifactKind:        KindROSExport,
		SanctionsListSource: SanctionsOFAC,
		ClienteCuitPrefix:   "30",
		FileMode:            0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasSanctionsMatch {
		t.Fatal("sanctions source must flag")
	}
}

func TestAnnotateHighRiskJurisdiction(t *testing.T) {
	r := Row{
		ArtifactKind:         KindKYCDossier,
		HighRiskJurisdiction: "Iran",
		FileMode:             0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasHighRiskJurisdiction {
		t.Fatal("Iran must flag high-risk-jurisdiction")
	}
}

func TestAnnotateStructuring(t *testing.T) {
	r := Row{
		ArtifactKind:      KindROSExport,
		TransactionCount:  15,
		MaxAmountARSCents: 50_000_000, // 500k ARS, sub-threshold
		FileMode:          0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasStructuringPattern {
		t.Fatalf("15 sub-threshold tx must flag structuring: %+v", r)
	}
}

func TestAnnotateUnusualVolume(t *testing.T) {
	r := Row{
		ArtifactKind:      KindROSExport,
		MaxAmountARSCents: 200_000_000, // 2M ARS, above threshold
		FileMode:          0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasUnusualVolume {
		t.Fatalf("2M ARS must flag unusual: %+v", r)
	}
}

func TestAnnotateLockedDownClean(t *testing.T) {
	r := Row{
		ArtifactKind:       KindKYCDossier,
		ClienteCuitPrefix:  "27",
		ClienteCuitSuffix4: "1114",
		HasKYCBody:         true,
		FileMode:           0o600,
	}
	AnnotateSecurity(&r)
	if r.IsCredentialExposureRisk {
		t.Fatal("0o600 must NOT flag exposure")
	}
}

// -- ParseUIFReport -----------------------------------------------

func TestParseUIFReportROS(t *testing.T) {
	body := []byte(`<?xml version="1.0"?>
<ros>
  <cliente_cuit>27-11111111-4</cliente_cuit>
  <oficial_cumplimiento_cuit>20-12345678-9</oficial_cumplimiento_cuit>
  <pep_name>Juan Politico</pep_name>
  <country>Iran</country>
  <periodo>202506</periodo>
  <estado>filed</estado>
  <alerta><tipo>monitoring</tipo></alerta>
  <alerta><tipo>monitoring</tipo></alerta>
  <operacion><importe>5000000.00</importe></operacion>
  <operacion><importe>3000000.00</importe></operacion>
</ros>`)
	f := ParseUIFReport(body)
	if f.ClienteCuitRaw == "" {
		t.Fatalf("cliente CUIT missing: %+v", f)
	}
	if f.OfficerCuitRaw == "" {
		t.Fatalf("officer CUIT missing: %+v", f)
	}
	if !f.HasPEPMarker {
		t.Fatal("PEP must flag")
	}
	if f.PEPName == "" {
		t.Fatal("PEP name must extract")
	}
	if !f.HasHighRiskJurisdiction {
		t.Fatal("Iran must flag high-risk")
	}
	if f.HighRiskJurisdiction != "Iran" {
		t.Fatalf("country=%q", f.HighRiskJurisdiction)
	}
	if f.Status != "filed" {
		t.Fatalf("status=%q", f.Status)
	}
	if f.AlertCount != 2 {
		t.Fatalf("alerts=%d want 2", f.AlertCount)
	}
	if f.TransactionCount != 2 {
		t.Fatalf("tx=%d want 2", f.TransactionCount)
	}
	if f.MaxAmountCents != 500_000_000 {
		t.Fatalf("max=%d", f.MaxAmountCents)
	}
}

func TestParseUIFReportStructuringMarker(t *testing.T) {
	body := []byte(`{
  "cliente_cuit": "27-11111111-4",
  "alerts": "structuring detected",
  "type": "smurfing"
}`)
	f := ParseUIFReport(body)
	if !f.HasStructuringMarker {
		t.Fatal("structuring/smurfing must flag")
	}
}

func TestParseUIFReportSanctionsMarker(t *testing.T) {
	body := []byte(`OFAC SDN list match: client found in sanctions match
cliente_cuit: 30-71234567-8`)
	f := ParseUIFReport(body)
	if !f.HasSanctionsMarker {
		t.Fatal("OFAC must flag sanctions")
	}
}

func TestParseUIFReportKYC(t *testing.T) {
	body := []byte(`<kyc_dossier>
  <cliente_cuit>27-11111111-4</cliente_cuit>
  <due_diligence>full</due_diligence>
</kyc_dossier>`)
	f := ParseUIFReport(body)
	if !f.HasKYCBody {
		t.Fatal("KYC body must flag")
	}
}

func TestParseUIFReportEmpty(t *testing.T) {
	f := ParseUIFReport(nil)
	if f.HasPEPMarker || f.HasSanctionsMarker || f.HasKYCBody {
		t.Fatalf("empty must not flag: %+v", f)
	}
}

// -- ParseSanctionsList -------------------------------------------

func TestParseSanctionsList(t *testing.T) {
	body := []byte(`# OFAC SDN consolidated list
ABDALLAH; Khalid; Yemen
KIM; Jong Un; DPRK
SOLEIMANI; Qasem; Iran
`)
	f := ParseSanctionsList(body)
	if !f.HasSanctionsMarker {
		t.Fatal("sanctions list must flag")
	}
	if f.AlertCount != 3 {
		t.Fatalf("alerts=%d want 3", f.AlertCount)
	}
}

// -- ParsePEPList -------------------------------------------------

func TestParsePEPList(t *testing.T) {
	body := []byte(`# PEP listado UIF
Politico A
Politico B
`)
	f := ParsePEPList(body)
	if !f.HasPEPMarker {
		t.Fatal("PEP list must flag")
	}
	if f.AlertCount != 2 {
		t.Fatalf("alerts=%d want 2", f.AlertCount)
	}
}

// -- collector end-to-end -----------------------------------------

func TestCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")
	dir := filepath.Join(usersBase, "alice", "Documents", "UIF")
	must(t, os.MkdirAll(dir, 0o755))

	// ROS export, world-readable, with PEP + high-risk.
	rosPath := filepath.Join(dir, "ros_001_202506.xml")
	must(t, os.WriteFile(rosPath, []byte(`<?xml version="1.0"?>
<ros>
  <cliente_cuit>27-11111111-4</cliente_cuit>
  <pep_name>Juan Politico</pep_name>
  <country>Iran</country>
  <periodo>202506</periodo>
  <estado>filed</estado>
  <operacion><importe>5000000.00</importe></operacion>
</ros>`), 0o644))

	// KYC dossier, locked down.
	kycPath := filepath.Join(dir, "kyc_27111111114.xml")
	must(t, os.WriteFile(kycPath, []byte(`<kyc>
  <cliente_cuit>27-11111111-4</cliente_cuit>
  <due_diligence>full</due_diligence>
</kyc>`), 0o600))

	// OFAC sanctions list, world-readable.
	ofacPath := filepath.Join(dir, "ofac_consol_20260615.csv")
	must(t, os.WriteFile(ofacPath, []byte(`# OFAC SDN
ABDALLAH; Khalid; Yemen
KIM; Jong Un; DPRK
`), 0o644))

	// Random ignored.
	must(t, os.WriteFile(filepath.Join(dir, "random.txt"),
		[]byte(`nope`), 0o644))

	// Public skipped.
	pub := filepath.Join(usersBase, "Public", "Documents", "UIF")
	must(t, os.MkdirAll(pub, 0o755))
	must(t, os.WriteFile(filepath.Join(pub, "ros_skip.xml"),
		[]byte(`<ros/>`), 0o644))

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
		t.Fatalf("want 3 (ros+kyc+ofac), got %d: %+v", len(got), got)
	}

	var ros, kyc, ofac Row
	for _, r := range got {
		switch r.FilePath {
		case rosPath:
			ros = r
		case kycPath:
			kyc = r
		case ofacPath:
			ofac = r
		}
	}

	if ros.ArtifactKind != KindROSExport {
		t.Fatalf("ros kind=%q", ros.ArtifactKind)
	}
	if !ros.HasPEPMatch {
		t.Fatalf("ros must flag PEP: %+v", ros)
	}
	if ros.PEPNameHash == "" {
		t.Fatalf("PEP hash must populate: %+v", ros)
	}
	if !ros.HasHighRiskJurisdiction || ros.HighRiskJurisdiction != "Iran" {
		t.Fatalf("ros high-risk: %+v", ros)
	}
	if ros.ReportStatus != StatusFiled {
		t.Fatalf("ros status=%q", ros.ReportStatus)
	}
	if !ros.IsCredentialExposureRisk {
		t.Fatalf("readable + cliente + ros = exposure: %+v", ros)
	}
	if ros.PeriodYYYYMM != "202506" {
		t.Fatalf("ros period=%q", ros.PeriodYYYYMM)
	}
	if !ros.HasUnusualVolume {
		t.Fatalf("5M ARS must flag unusual: %+v", ros)
	}

	if kyc.ArtifactKind != KindKYCDossier {
		t.Fatalf("kyc kind=%q", kyc.ArtifactKind)
	}
	if !kyc.HasKYCBody {
		t.Fatalf("KYC body must flag: %+v", kyc)
	}
	if kyc.IsCredentialExposureRisk {
		t.Fatalf("0o600 must NOT flag: %+v", kyc)
	}

	if ofac.ArtifactKind != KindSanctionsList {
		t.Fatalf("ofac kind=%q", ofac.ArtifactKind)
	}
	if ofac.SanctionsListSource != SanctionsOFAC {
		t.Fatalf("ofac source=%q", ofac.SanctionsListSource)
	}
	if !ofac.HasSanctionsMatch {
		t.Fatalf("sanctions source must flag match: %+v", ofac)
	}
	if ofac.AlertCount != 2 {
		t.Fatalf("ofac alerts=%d want 2", ofac.AlertCount)
	}
}

func TestCollectorRespectsEnv(t *testing.T) {
	tmp := t.TempDir()
	envDir := filepath.Join(tmp, "custom-uif")
	must(t, os.MkdirAll(envDir, 0o755))
	must(t, os.WriteFile(filepath.Join(envDir, "ros_001.xml"),
		[]byte(`<ros><cliente_cuit>27-11111111-4</cliente_cuit></ros>`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "UIF_DIR" {
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
	if len(got) != 1 || got[0].ArtifactKind != KindROSExport {
		t.Fatalf("env: %+v", got)
	}
}

func TestCollectorMissingPathsOK(t *testing.T) {
	c := &fileCollector{
		installRoots: []string{"/nope-uif"},
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
		{FilePath: "z", ArtifactKind: KindROSExport},
		{FilePath: "a", ArtifactKind: KindROSExport},
		{FilePath: "a", ArtifactKind: KindKYCDossier},
	}
	SortRows(in)
	// "uif-kyc-dossier" sorts before "uif-ros-export" alphabetically.
	if in[0].FilePath != "a" || in[0].ArtifactKind != KindKYCDossier {
		t.Fatalf("first=%+v", in[0])
	}
}

func TestHashSecretCaseInsensitive(t *testing.T) {
	a := HashSecret("Juan Politico")
	b := HashSecret("  juan politico  ")
	c := HashSecret("Pedro Politico")
	if a != b {
		t.Fatal("case+whitespace must normalize")
	}
	if a == c {
		t.Fatal("different names must differ")
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
