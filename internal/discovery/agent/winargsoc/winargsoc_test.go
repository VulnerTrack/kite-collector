package winargsoc

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnumStrings(t *testing.T) {
	pairs := []struct{ got, want string }{
		{string(KindSIEMQuery), "soc-siem-query"},
		{string(KindIRRunbook), "soc-ir-runbook"},
		{string(KindIRPostMortem), "soc-ir-post-mortem"},
		{string(KindMITREAttackMapping), "soc-mitre-attack-mapping"},
		{string(KindVulnerabilityScan), "soc-vulnerability-scan"},
		{string(KindPentestReport), "soc-pentest-report"},
		{string(KindCNVRG1023Attestation), "soc-cnv-rg1023-attestation"},
		{string(KindBCRAA8005Filing), "soc-bcra-a8005-filing"},
		{string(KindYARARule), "soc-yara-rule"},
		{string(KindSigmaRule), "soc-sigma-rule"},
		{string(SIEMSplunk), "splunk"},
		{string(SIEMSentinel), "sentinel"},
		{string(SIEMElastic), "elastic"},
		{string(RoleSOCAnalystL1), "soc-analyst-l1"},
		{string(RoleIncidentResponder), "incident-responder"},
		{string(RoleCISO), "ciso"},
		{string(TLPRed), "tlp-red"},
		{string(TLPAmberStrict), "tlp-amber-strict"},
		{string(SevCritical), "critical"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Fatalf("enum drift: got %q want %q", p.got, p.want)
		}
	}
}

func TestIsCandidateName(t *testing.T) {
	yes := []string{
		"siem_query_brute_force.spl",
		"siem_query_lateral_movement.kql",
		"siem_query_dns_exfil.eql",
		"ir_runbook_ransomware.md",
		"threat_hunt_credentials.csv",
		"ir_post_mortem_INC-2026-0001.pdf",
		"mitre_attack_mapping_INC-2026-0001.json",
		"threat_intel_apt39.json",
		"stix_apt29.json",
		"vulnerability_scan_prod.csv",
		"nessus_critical_scan.nessus",
		"pentest_report_2026.pdf",
		"soc2_aws_2026.pdf",
		"csirt_designation.pdf",
		"cnv_rg1023_attestation.xml",
		"bcra_a8005_filing.xml",
		"ioc_blocklist_2026q2.txt",
		"yara_rule_malware.yar",
		"sigma_rule_priv_esc.sigma",
		"soc_config.ini",
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
		"siem_query_brute_force.spl":              KindSIEMQuery,
		"siem_query_lateral_movement.kql":         KindSIEMQuery,
		"siem_query_dns_exfil.eql":                KindSIEMQuery,
		"ir_runbook_ransomware.md":                KindIRRunbook,
		"threat_hunt_credentials.csv":             KindThreatHuntResult,
		"ir_post_mortem_INC-2026-0001.pdf":        KindIRPostMortem,
		"mitre_attack_mapping_INC-2026-0001.json": KindMITREAttackMapping,
		"threat_intel_apt39.json":                 KindThreatIntelFeed,
		"stix_apt29.json":                         KindThreatIntelFeed,
		"vulnerability_scan_prod.csv":             KindVulnerabilityScan,
		"nessus_critical_scan.nessus":             KindVulnerabilityScan,
		"pentest_report_2026.pdf":                 KindPentestReport,
		"soc2_aws_2026.pdf":                       KindSOC2Report,
		"csirt_designation.pdf":                   KindCSIRTDesignation,
		"cnv_rg1023_attestation.xml":              KindCNVRG1023Attestation,
		"bcra_a8005_filing.xml":                   KindBCRAA8005Filing,
		"ioc_blocklist_2026q2.txt":                KindIOCBlocklist,
		"yara_rule_malware.yar":                   KindYARARule,
		"detection_rule.yara":                     KindYARARule,
		"sigma_rule_priv_esc.sigma":               KindSigmaRule,
		"soc_config.ini":                          KindConfig,
		"credentials.json":                        KindCredentials,
		"splunk_setup.msi":                        KindInstaller,
		"":                                        KindUnknown,
	}
	for in, want := range cases {
		if got := ArtifactKindFromName(in); got != want {
			t.Fatalf("ArtifactKindFromName(%q)=%q want %q", in, got, want)
		}
	}
}

func TestSIEMPlatformFromExt(t *testing.T) {
	cases := map[string]SIEMPlatform{
		"query.spl":          SIEMSplunk,
		"sentinel_query.kql": SIEMSentinel,
		"elastic_query.kql":  SIEMElastic,
		"query.kql":          SIEMSentinel,
		"query.eql":          SIEMElastic,
		"query.aql":          SIEMQRadar,
		"random.txt":         SIEMUnknown,
	}
	for in, want := range cases {
		got := SIEMPlatformFromExt(in)
		if got != want {
			t.Fatalf("SIEMPlatformFromExt(%q)=%q want %q", in, got, want)
		}
	}
}

func TestDetectTLP(t *testing.T) {
	cases := map[string]TLPClassification{
		"clear":        TLPClear,
		"white":        TLPClear,
		"green":        TLPGreen,
		"amber":        TLPAmber,
		"amber+strict": TLPAmberStrict,
		"amber-strict": TLPAmberStrict,
		"red":          TLPRed,
		"random":       TLPUnknown,
	}
	for in, want := range cases {
		got := detectTLP(in)
		if got != want {
			t.Fatalf("detectTLP(%q)=%q want %q", in, got, want)
		}
	}
}

func TestDetectSeverity(t *testing.T) {
	cases := map[string]IncidentSeverity{
		"critical":      SevCritical,
		"crit":          SevCritical,
		"high":          SevHigh,
		"medium":        SevMedium,
		"med":           SevMedium,
		"low":           SevLow,
		"informational": SevInformational,
		"info":          SevInformational,
		"random":        SevUnknown,
	}
	for in, want := range cases {
		got := detectSeverity(in)
		if got != want {
			t.Fatalf("detectSeverity(%q)=%q want %q", in, got, want)
		}
	}
}

func TestIsCredentialKind(t *testing.T) {
	yes := []ArtifactKind{
		KindSIEMQuery, KindIRRunbook,
		KindThreatHuntResult, KindIRPostMortem,
		KindMITREAttackMapping, KindThreatIntelFeed,
		KindVulnerabilityScan, KindPentestReport,
		KindSOC2Report, KindCSIRTDesignation,
		KindCNVRG1023Attestation, KindBCRAA8005Filing,
		KindIOCBlocklist, KindYARARule, KindSigmaRule,
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

func TestIsDetectionBypassKind(t *testing.T) {
	yes := []ArtifactKind{
		KindSIEMQuery, KindYARARule, KindSigmaRule,
		KindIOCBlocklist, KindMITREAttackMapping,
	}
	for _, k := range yes {
		if !IsDetectionBypassKind(k) {
			t.Fatalf("expected bypass: %q", k)
		}
	}
	no := []ArtifactKind{
		KindIRRunbook, KindThreatHuntResult, KindIRPostMortem,
		KindThreatIntelFeed, KindVulnerabilityScan,
		KindPentestReport, KindSOC2Report,
		KindCSIRTDesignation, KindCNVRG1023Attestation,
		KindBCRAA8005Filing,
		KindConfig, KindCredentials,
		KindInstaller, KindOther, KindUnknown,
	}
	for _, k := range no {
		if IsDetectionBypassKind(k) {
			t.Fatalf("expected NOT bypass: %q", k)
		}
	}
}

func TestIsIncidentHistoryKind(t *testing.T) {
	yes := []ArtifactKind{KindIRPostMortem, KindThreatHuntResult}
	for _, k := range yes {
		if !IsIncidentHistoryKind(k) {
			t.Fatalf("expected incident history: %q", k)
		}
	}
}

func TestIsComplianceAttestationKind(t *testing.T) {
	yes := []ArtifactKind{
		KindCNVRG1023Attestation, KindBCRAA8005Filing,
		KindCSIRTDesignation, KindSOC2Report,
		KindPentestReport,
	}
	for _, k := range yes {
		if !IsComplianceAttestationKind(k) {
			t.Fatalf("expected attestation: %q", k)
		}
	}
}

func TestAnnotateDetectionBypass(t *testing.T) {
	r := Row{
		ArtifactKind: KindSIEMQuery,
		FileMode:     0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasSIEMQuery {
		t.Fatal("SIEM kind must flag")
	}
	if !r.IsDetectionBypassDisclosureRisk {
		t.Fatal("readable + SIEM query = detection bypass risk")
	}
}

func TestAnnotateIncidentHistory(t *testing.T) {
	r := Row{
		ArtifactKind: KindIRPostMortem,
		FileMode:     0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasIRPostMortem {
		t.Fatal("post-mortem kind must flag")
	}
	if !r.IsIncidentHistoryExposureRisk {
		t.Fatal("readable + post-mortem = incident history risk")
	}
}

func TestAnnotateComplianceAttestationLeak(t *testing.T) {
	r := Row{
		ArtifactKind: KindCNVRG1023Attestation,
		FileMode:     0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasCNVRG1023Attestation {
		t.Fatal("CNV RG 1023 must flag")
	}
	if !r.IsComplianceAttestationLeak {
		t.Fatal("readable + CNV RG 1023 = compliance attestation leak")
	}
}

func TestAnnotateTLPAmberOrRed(t *testing.T) {
	r := Row{
		ArtifactKind:      KindThreatIntelFeed,
		TLPClassification: TLPAmber,
		FileMode:          0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasTLPAmberOrRed {
		t.Fatal("amber must flag")
	}
}

func TestAnnotateUnpatchedCriticalCVE(t *testing.T) {
	r := Row{
		ArtifactKind:     KindVulnerabilityScan,
		CriticalCVECount: CriticalCVEThreshold + 1,
	}
	AnnotateSecurity(&r)
	if !r.HasUnpatchedCriticalCVE {
		t.Fatal("> 5 critical CVE must flag")
	}
}

func TestAnnotateActiveIncident(t *testing.T) {
	r := Row{
		ArtifactKind:     KindIRPostMortem,
		IncidentSeverity: SevHigh,
		FileMode:         0o644,
	}
	AnnotateSecurity(&r)
	if !r.HasActiveIncident {
		t.Fatal("high severity must flag active incident")
	}
}

func TestParseSOC(t *testing.T) {
	body := []byte(`Incident Post-Mortem
incident_id: INC-2026-0001
severity: high
TLP:AMBER
SIEM: Splunk
cve_count: 25
critical_cve_count: 7
detection_rule_count: 150
ioc_count: 850
csirt_org_cuit: 30-71234567-8
`)
	f := ParseSOC(body)
	if f.IncidentID != "INC-2026-0001" {
		t.Fatalf("incident=%q", f.IncidentID)
	}
	if f.IncidentSeverity != SevHigh {
		t.Fatalf("severity=%q", f.IncidentSeverity)
	}
	if f.TLPClassification != TLPAmber {
		t.Fatalf("tlp=%q", f.TLPClassification)
	}
	if f.SIEMPlatform != SIEMSplunk {
		t.Fatalf("siem=%q", f.SIEMPlatform)
	}
	if f.CVECount != 25 {
		t.Fatalf("cve=%d", f.CVECount)
	}
	if f.CriticalCVECount != 7 {
		t.Fatalf("critical=%d", f.CriticalCVECount)
	}
	if f.DetectionRuleCount != 150 {
		t.Fatalf("rules=%d", f.DetectionRuleCount)
	}
	if f.IOCCount != 850 {
		t.Fatalf("iocs=%d", f.IOCCount)
	}
	if f.CSIRTOrgCuitRaw == "" {
		t.Fatal("csirt cuit must extract")
	}
}

func TestCollectorWalksUserTree(t *testing.T) {
	tmp := t.TempDir()
	usersBase := filepath.Join(tmp, "Users")
	socDir := filepath.Join(usersBase, "alice", "soc")
	must(t, os.MkdirAll(socDir, 0o755))

	siemPath := filepath.Join(socDir, "siem_query_brute_force.spl")
	must(t, os.WriteFile(siemPath, []byte(`# Splunk SPL Detection
index=auth sourcetype=login failures>5 by user
TLP:AMBER
`), 0o644))

	pmPath := filepath.Join(socDir, "ir_post_mortem_INC-2026-0001.pdf")
	must(t, os.WriteFile(pmPath, []byte(`Incident Post-Mortem
incident_id: INC-2026-0001
severity: critical
TLP:RED
`), 0o644))

	vsPath := filepath.Join(socDir, "vulnerability_scan_prod.csv")
	must(t, os.WriteFile(vsPath, []byte(`CVE,CVSS,Severity
CVE-2026-0001,9.8,critical
CVE-2026-0002,9.5,critical
critical_cve_count: 12
`), 0o644))

	attPath := filepath.Join(socDir, "cnv_rg1023_attestation.xml")
	must(t, os.WriteFile(attPath, []byte(`<?xml version="1.0"?>
<CNVRG1023Attestation>
  <year>2026</year>
  <csirt_org_cuit>30-71234567-8</csirt_org_cuit>
</CNVRG1023Attestation>
`), 0o644))

	must(t, os.WriteFile(filepath.Join(socDir, "random.txt"),
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
	if len(got) != 4 {
		t.Fatalf("want 4 (siem+pm+vs+att), got %d: %+v", len(got), got)
	}

	var siem, pm, vs, att Row
	for _, r := range got {
		switch r.FilePath {
		case siemPath:
			siem = r
		case pmPath:
			pm = r
		case vsPath:
			vs = r
		case attPath:
			att = r
		}
	}

	if siem.ArtifactKind != KindSIEMQuery {
		t.Fatalf("siem kind=%q", siem.ArtifactKind)
	}
	if siem.SIEMPlatform != SIEMSplunk {
		t.Fatalf("siem platform=%q want splunk", siem.SIEMPlatform)
	}
	if !siem.IsDetectionBypassDisclosureRisk {
		t.Fatalf("siem must flag bypass risk: %+v", siem)
	}
	if !siem.HasTLPAmberOrRed {
		t.Fatalf("siem must flag amber: %+v", siem)
	}

	if pm.ArtifactKind != KindIRPostMortem {
		t.Fatalf("pm kind=%q", pm.ArtifactKind)
	}
	if pm.IncidentSeverity != SevCritical {
		t.Fatalf("pm sev=%q", pm.IncidentSeverity)
	}
	if !pm.HasActiveIncident {
		t.Fatalf("pm critical must flag active: %+v", pm)
	}
	if !pm.IsIncidentHistoryExposureRisk {
		t.Fatalf("pm must flag incident history risk: %+v", pm)
	}

	if vs.ArtifactKind != KindVulnerabilityScan {
		t.Fatalf("vs kind=%q", vs.ArtifactKind)
	}
	if vs.CriticalCVECount != 12 {
		t.Fatalf("vs critical=%d", vs.CriticalCVECount)
	}
	if !vs.HasUnpatchedCriticalCVE {
		t.Fatalf("vs > 5 critical must flag: %+v", vs)
	}

	if att.ArtifactKind != KindCNVRG1023Attestation {
		t.Fatalf("att kind=%q", att.ArtifactKind)
	}
	if !att.IsComplianceAttestationLeak {
		t.Fatalf("att must flag attestation leak: %+v", att)
	}
	if !att.HasCSIRTOrgCuit {
		t.Fatalf("att must flag csirt cuit: %+v", att)
	}
}

func TestCollectorEnvOverride(t *testing.T) {
	tmp := t.TempDir()
	custom := filepath.Join(tmp, "custom-soc")
	must(t, os.MkdirAll(custom, 0o755))
	must(t, os.WriteFile(filepath.Join(custom, "soc_config.ini"),
		[]byte(`[SOC]
soc_password=hello
`), 0o644))

	c := &fileCollector{
		installRoots: nil,
		usersBases:   nil,
		getenv: func(k string) string {
			if k == "SOC_DIR" {
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
		installRoots: []string{"/nope-soc"},
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
		{FilePath: "/b", ArtifactKind: KindSIEMQuery},
		{FilePath: "/a", ArtifactKind: KindIRPostMortem},
		{FilePath: "/a", ArtifactKind: KindSIEMQuery},
	}
	SortRows(rs)
	// "soc-ir-post-mortem" < "soc-siem-query" alphabetically.
	if rs[0].FilePath != "/a" || rs[0].ArtifactKind != KindIRPostMortem {
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
