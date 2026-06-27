package winargsoc

import (
	"regexp"
	"strconv"
	"strings"
)

// SOCFields captures scalar fields the audit pipeline needs.
type SOCFields struct {
	IncidentID         string
	CSIRTOrgCuitRaw    string
	SIEMPlatform       SIEMPlatform
	TLPClassification  TLPClassification
	IncidentSeverity   IncidentSeverity
	CVECount           int64
	CriticalCVECount   int64
	DetectionRuleCount int64
	IOCCount           int64
	HasPassword        bool
}

// passwordRE matches a password row in INI / JSON / XML form.
var passwordRE = regexp.MustCompile(
	`(?im)^\s*"?(?:password|passwd|clave|soc[_\-]?password|splunk[_\-]?password|elastic[_\-]?password|api[_\-]?token)"?\s*[:=]\s*\S+`)

// passwordInlineRE matches `password="..."` mid-line.
var passwordInlineRE = regexp.MustCompile(
	`(?i)"?\b(?:password|passwd|api_key|api_secret|soc[_\-]?password|splunk[_\-]?password|elastic[_\-]?password|bearer[_\-]?token)\b"?\s*[:=]\s*["'][^"']{1,}["']`)

// passwordXMLRE matches `<password>secret</password>` form.
var passwordXMLRE = regexp.MustCompile(
	`(?i)<\s*(?:password|passwd|soc[_\-]?password|splunk[_\-]?password)\s*>([^<]{1,})<\s*/`)

// incidentIDRE matches an incident identifier.
var incidentIDRE = regexp.MustCompile(
	`(?i)"?(?:incident[_\- ]?id|case[_\- ]?id|inc[_\- ]?id|ticket)"?\s*[:=>]\s*"?([A-Z0-9\-]{3,32})"?`)

// tlpRE matches a TLP classification field.
var tlpRE = regexp.MustCompile(
	`(?i)\b(?:tlp:?\s*(clear|white|green|amber|amber\+strict|amber-strict|red))\b`)

// severityRE matches an incident-severity field.
var severityRE = regexp.MustCompile(
	`(?i)"?(?:severity|sev|criticality|priority|incident[_\- ]?severity)"?\s*[:=>]\s*"?(informational|info|low|medium|med|high|critical|crit)"?`)

// siemPlatformRE matches a SIEM platform marker in body.
var siemPlatformRE = regexp.MustCompile(
	`(?i)\b(splunk|elastic|elasticsearch|microsoft sentinel|sentinel|qradar|sumo logic|sumologic|devo)\b`)

// cveCountRE matches a total CVE count.
var cveCountRE = regexp.MustCompile(
	`(?i)"?(?:cve[_\- ]?count|cve[_\- ]?total|vulnerabilities[_\- ]?count|total[_\- ]?cves)"?\s*[:=>]\s*"?(\d{1,12})`)

// criticalCVECountRE matches a critical CVE count.
var criticalCVECountRE = regexp.MustCompile(
	`(?i)"?(?:critical[_\- ]?cve[_\- ]?count|critical[_\- ]?count|critical[_\- ]?vulns|cvss[_\- ]?critical)"?\s*[:=>]\s*"?(\d{1,12})`)

// detectionRuleCountRE matches a detection-rule count.
var detectionRuleCountRE = regexp.MustCompile(
	`(?i)"?(?:detection[_\- ]?rule[_\- ]?count|rules[_\- ]?count|detection[_\- ]?count)"?\s*[:=>]\s*"?(\d{1,12})`)

// iocCountRE matches an IOC count.
var iocCountRE = regexp.MustCompile(
	`(?i)"?(?:ioc[_\- ]?count|indicators[_\- ]?count|total[_\- ]?iocs)"?\s*[:=>]\s*"?(\d{1,12})`)

// csirtOrgCuitKeyRE matches `csirt_org_cuit: NN-NNNNNNNN-N`.
var csirtOrgCuitKeyRE = regexp.MustCompile(
	`(?i)"?(?:csirt[_\- ]?org[_\- ]?cuit|org[_\- ]?cuit|entidad[_\- ]?cuit|cnv[_\- ]?cuit|cuit)"?\s*[:=>]\s*"?(\d{2}-?\d{8}-?\d)"?`)

// ParseSOC parses any SOC artifact body (shared parser).
func ParseSOC(body []byte) SOCFields {
	var out SOCFields
	if len(body) == 0 {
		return out
	}
	if passwordRE.Match(body) || passwordInlineRE.Match(body) ||
		passwordXMLRE.Match(body) {
		out.HasPassword = true
	}
	if m := incidentIDRE.FindSubmatch(body); len(m) > 1 {
		out.IncidentID = string(m[1])
	}
	if m := tlpRE.FindSubmatch(body); len(m) > 1 {
		out.TLPClassification = detectTLP(string(m[1]))
	}
	if m := severityRE.FindSubmatch(body); len(m) > 1 {
		out.IncidentSeverity = detectSeverity(string(m[1]))
	}
	if m := siemPlatformRE.FindSubmatch(body); len(m) > 1 {
		out.SIEMPlatform = detectSIEMPlatform(string(m[1]))
	}
	if m := cveCountRE.FindSubmatch(body); len(m) > 1 {
		if v, err := strconv.ParseInt(string(m[1]), 10, 64); err == nil {
			out.CVECount = v
		}
	}
	if m := criticalCVECountRE.FindSubmatch(body); len(m) > 1 {
		if v, err := strconv.ParseInt(string(m[1]), 10, 64); err == nil {
			out.CriticalCVECount = v
		}
	}
	if m := detectionRuleCountRE.FindSubmatch(body); len(m) > 1 {
		if v, err := strconv.ParseInt(string(m[1]), 10, 64); err == nil {
			out.DetectionRuleCount = v
		}
	}
	if m := iocCountRE.FindSubmatch(body); len(m) > 1 {
		if v, err := strconv.ParseInt(string(m[1]), 10, 64); err == nil {
			out.IOCCount = v
		}
	}
	if c := csirtOrgCuitFromBody(body); c != "" {
		out.CSIRTOrgCuitRaw = c
	}
	return out
}

// csirtOrgCuitFromBody returns the first CSIRT-org CUIT match.
func csirtOrgCuitFromBody(body []byte) string {
	if m := csirtOrgCuitKeyRE.FindSubmatch(body); len(m) > 1 {
		return string(m[1])
	}
	return ""
}

// detectTLP normalizes a TLP string to the pinned enum.
func detectTLP(s string) TLPClassification {
	t := strings.ToLower(strings.TrimSpace(s))
	switch {
	case strings.Contains(t, "clear") || strings.Contains(t, "white"):
		return TLPClear
	case strings.Contains(t, "green"):
		return TLPGreen
	case strings.Contains(t, "amber") &&
		(strings.Contains(t, "+strict") || strings.Contains(t, "-strict") ||
			strings.Contains(t, " strict")):
		return TLPAmberStrict
	case strings.Contains(t, "amber"):
		return TLPAmber
	case strings.Contains(t, "red"):
		return TLPRed
	}
	return TLPUnknown
}

// detectSeverity normalizes a severity string.
func detectSeverity(s string) IncidentSeverity {
	t := strings.ToLower(strings.TrimSpace(s))
	switch {
	case strings.Contains(t, "informational") ||
		strings.Contains(t, "info"):
		return SevInformational
	case strings.Contains(t, "critical") || strings.Contains(t, "crit"):
		return SevCritical
	case strings.Contains(t, "high"):
		return SevHigh
	case strings.Contains(t, "medium") || strings.Contains(t, "med"):
		return SevMedium
	case strings.Contains(t, "low"):
		return SevLow
	}
	return SevUnknown
}

// detectSIEMPlatform normalizes a SIEM-platform string.
func detectSIEMPlatform(s string) SIEMPlatform {
	t := strings.ToLower(strings.TrimSpace(s))
	switch {
	case strings.Contains(t, "splunk"):
		return SIEMSplunk
	case strings.Contains(t, "sentinel"):
		return SIEMSentinel
	case strings.Contains(t, "elastic"):
		return SIEMElastic
	case strings.Contains(t, "qradar"):
		return SIEMQRadar
	case strings.Contains(t, "sumo"):
		return SIEMSumoLogic
	case strings.Contains(t, "devo"):
		return SIEMDevo
	}
	return SIEMUnknown
}
