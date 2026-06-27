package winargma

import (
	"regexp"
	"strconv"
	"strings"
)

// MAFields captures scalar fields the audit pipeline needs from
// an M&A artifact.
type MAFields struct {
	DealID                     string
	ProjectName                string
	TargetCuitRaw              string
	BidderCuitRaw              string
	AdvisorFirm                AdvisorFirm
	MandateType                MandateType
	DealStage                  DealStage
	BidderCount                int64
	DataroomFileCount          int64
	EnterpriseValueARSMillions int64
	AdvisoryFeeARSMillions     int64
	SuccessFeeBPS              int64
	HasPassword                bool
	HasPreAnnouncementDraft    bool
	HasCrossBorderTarget       bool
	HasPublicTarget            bool
}

// passwordRE matches a password row in INI / JSON / XML form.
var passwordRE = regexp.MustCompile(
	`(?im)^\s*"?(?:password|passwd|clave|ib[_\-]?password|deal[_\-]?password|dataroom[_\-]?password|intralinks[_\-]?password|datasite[_\-]?password)"?\s*[:=]\s*\S+`)

// passwordInlineRE matches `password="..."` mid-line.
var passwordInlineRE = regexp.MustCompile(
	`(?i)"?\b(?:password|passwd|api_key|api_secret|ib[_\-]?password|deal[_\-]?password|dataroom[_\-]?password)\b"?\s*[:=]\s*["'][^"']{1,}["']`)

// passwordXMLRE matches `<password>secret</password>` form.
var passwordXMLRE = regexp.MustCompile(
	`(?i)<\s*(?:password|passwd|ib[_\-]?password|deal[_\-]?password)\s*>([^<]{1,})<\s*/`)

// dealIDRE matches a deal identifier (e.g. "DEAL-2026-0123" or
// "Project Tango").
var dealIDRE = regexp.MustCompile(
	`(?i)"?(?:deal[_\- ]?id|project[_\- ]?id|mandate[_\- ]?id|engagement[_\- ]?id)"?\s*[:=>]\s*"?([A-Z0-9\-]{4,32})"?`)

// projectNameRE matches the project codename.
var projectNameRE = regexp.MustCompile(
	`(?i)"?(?:project[_\- ]?name|codename|deal[_\- ]?codename|operation[_\- ]?name)"?\s*[:=>]\s*"?([A-Za-zÀ-ÿ0-9 .\-_]{3,60})"?`)

// advisorFirmRE matches the advisor-firm self-identification.
var advisorFirmRE = regexp.MustCompile(
	`(?i)"?(?:advisor[_\- ]?firm|advisor|firm|investment[_\- ]?bank|asesor[_\- ]?financiero)"?\s*[:=>]\s*"?([A-Za-z0-9 .\-_&]{3,60})`)

// mandateTypeRE matches a mandate-type field.
var mandateTypeRE = regexp.MustCompile(
	`(?i)"?(?:mandate[_\- ]?type|mandate|tipo[_\- ]?mandato)"?\s*[:=>]\s*"?([A-Za-z\-_ ]{4,30})`)

// dealStageRE matches a deal-stage field.
var dealStageRE = regexp.MustCompile(
	`(?i)"?(?:deal[_\- ]?stage|stage|etapa|fase[_\- ]?deal)"?\s*[:=>]\s*"?([A-Za-z\-_ ]{4,30})`)

// preAnnouncementMarkerRE matches DRAFT / RESTRICTED /
// CONFIDENTIAL / "NOT FOR DISTRIBUTION" markers in pre-
// announcement M&A documents.
var preAnnouncementMarkerRE = regexp.MustCompile(
	`(?im)\b(?:DRAFT|BORRADOR|RESTRICTED|CONFIDENTIAL|CONFIDENCIAL|PRIVILEGED|PRIVILEGED[_\- ]?AND[_\- ]?CONFIDENTIAL|FOR[_\- ]?DISCUSSION[_\- ]?ONLY|FOR[_\- ]?INTERNAL[_\- ]?USE|NOT[_\- ]?FOR[_\- ]?DISTRIBUTION|NO[_\- ]?CIRCULAR|EYES[_\- ]?ONLY|PROJECT[_\- ]?CODENAME)\b`)

// publicTargetRE matches a marker indicating the target is
// publicly traded (BYMA-listed, US ADR, or bare exchange ticker
// in document body).
var publicTargetRE = regexp.MustCompile(
	`(?i)\b(?:public[_\- ]?target|publicly[_\- ]?traded|listed[_\- ]?company|byma[_\- ]?listed|nyse[_\- ]?listed|nasdaq[_\- ]?listed|adr|cnv[_\- ]?listed|nyse|nasdaq|byma|merval|panel[_\- ]?lider)\b`)

// crossBorderRE matches a marker indicating cross-border target.
var crossBorderRE = regexp.MustCompile(
	`(?i)\b(?:cross[_\- ]?border|foreign[_\- ]?target|us[_\- ]?target|brazil[_\- ]?target|cross[_\- ]?jurisdiction|inbound|outbound[_\- ]?ma)\b`)

// bidderCountRE matches a bidder-count field.
var bidderCountRE = regexp.MustCompile(
	`(?i)"?(?:bidder[_\- ]?count|cantidad[_\- ]?oferentes|nro[_\- ]?oferentes|num[_\- ]?bidders)"?\s*[:=>]\s*"?(\d{1,12})`)

// bidderRosterRowRE matches a per-bidder CSV row anchored on
// CUIT pattern.
var bidderRosterRowRE = regexp.MustCompile(
	`(?im)^[A-Z0-9\-]+,\d{2}-?\d{8}-?\d,`)

// dataroomFileCountRE matches a dataroom-file-count field.
var dataroomFileCountRE = regexp.MustCompile(
	`(?i)"?(?:dataroom[_\- ]?file[_\- ]?count|file[_\- ]?count|cantidad[_\- ]?archivos|nro[_\- ]?archivos|total[_\- ]?files)"?\s*[:=>]\s*"?(\d{1,12})`)

// dataroomRowRE matches a per-file row in dataroom manifest
// CSV.
var dataroomRowRE = regexp.MustCompile(
	`(?im)^(?:DOC|FILE|F)[_\- ]?\d+,`)

// enterpriseValueRE matches enterprise value in ARS.
var enterpriseValueRE = regexp.MustCompile(
	`(?i)"?(?:enterprise[_\- ]?value|ev|valor[_\- ]?empresa|equity[_\- ]?value|deal[_\- ]?value|deal[_\- ]?size)"?\s*[:=>]\s*"?\$?(\d{1,15}(?:[.,]\d+)?)`)

// advisoryFeeRE matches advisory fee in ARS.
var advisoryFeeRE = regexp.MustCompile(
	`(?i)"?(?:advisory[_\- ]?fee|honorarios[_\- ]?asesoria|fee[_\- ]?advisor)"?\s*[:=>]\s*"?\$?(\d{1,15}(?:[.,]\d+)?)`)

// successFeeBPSRE matches success-fee basis-points.
var successFeeBPSRE = regexp.MustCompile(
	`(?i)"?(?:success[_\- ]?fee[_\- ]?bps|success[_\- ]?fee|fee[_\- ]?bps)"?\s*[:=>]\s*"?(\d{1,6})(?:\s*bps)?`)

// targetCuitKeyRE matches `target_cuit: NN-NNNNNNNN-N`.
var targetCuitKeyRE = regexp.MustCompile(
	`(?i)"?(?:target[_\- ]?cuit|cuit[_\- ]?target|seller[_\- ]?cuit|cuit[_\- ]?seller|emisor[_\- ]?cuit|cuit[_\- ]?emisor|cuit)"?\s*[:=>]\s*"?(\d{2}-?\d{8}-?\d)"?`)

// bidderCuitKeyRE matches `bidder_cuit: NN-NNNNNNNN-N`.
var bidderCuitKeyRE = regexp.MustCompile(
	`(?i)"?(?:bidder[_\- ]?cuit|cuit[_\- ]?bidder|buyer[_\- ]?cuit|cuit[_\- ]?buyer|oferente[_\- ]?cuit|cuit[_\- ]?oferente)"?\s*[:=>]\s*"?(\d{2}-?\d{8}-?\d)"?`)

// ParsePitchDeck parses a pitch deck body.
func ParsePitchDeck(body []byte) MAFields {
	return parseCommon(body)
}

// ParseNDA parses an NDA body.
func ParseNDA(body []byte) MAFields {
	return parseCommon(body)
}

// ParseInformationMemorandum parses an IM body.
func ParseInformationMemorandum(body []byte) MAFields {
	out := parseCommon(body)
	if v, ok := sumARSMillions(body, enterpriseValueRE); ok {
		out.EnterpriseValueARSMillions = v
	}
	return out
}

// ParseDataroomManifest parses a DR manifest body.
func ParseDataroomManifest(body []byte) MAFields {
	out := parseCommon(body)
	if m := dataroomFileCountRE.FindSubmatch(body); len(m) > 1 {
		if v, err := strconv.ParseInt(string(m[1]), 10, 64); err == nil {
			out.DataroomFileCount = v
		}
	}
	if out.DataroomFileCount == 0 {
		out.DataroomFileCount = int64(len(dataroomRowRE.FindAllIndex(body, -1)))
	}
	return out
}

// ParseBidderRoster parses a bidder roster body.
func ParseBidderRoster(body []byte) MAFields {
	out := parseCommon(body)
	if m := bidderCountRE.FindSubmatch(body); len(m) > 1 {
		if v, err := strconv.ParseInt(string(m[1]), 10, 64); err == nil {
			out.BidderCount = v
		}
	}
	if out.BidderCount == 0 {
		out.BidderCount = int64(len(bidderRosterRowRE.FindAllIndex(body, -1)))
	}
	return out
}

// ParseProcessLetter parses a process letter body.
func ParseProcessLetter(body []byte) MAFields {
	return parseCommon(body)
}

// ParseBidEvaluation parses a bid evaluation body.
func ParseBidEvaluation(body []byte) MAFields {
	out := parseCommon(body)
	if m := bidderCountRE.FindSubmatch(body); len(m) > 1 {
		if v, err := strconv.ParseInt(string(m[1]), 10, 64); err == nil {
			out.BidderCount = v
		}
	}
	if out.BidderCount == 0 {
		out.BidderCount = int64(len(bidderRosterRowRE.FindAllIndex(body, -1)))
	}
	return out
}

// ParseDCFModel parses a DCF model body.
func ParseDCFModel(body []byte) MAFields {
	out := parseCommon(body)
	if v, ok := sumARSMillions(body, enterpriseValueRE); ok {
		out.EnterpriseValueARSMillions = v
	}
	return out
}

// ParseLBOModel parses an LBO model body.
func ParseLBOModel(body []byte) MAFields {
	return ParseDCFModel(body)
}

// ParseMergerModel parses a merger model body.
func ParseMergerModel(body []byte) MAFields {
	return ParseDCFModel(body)
}

// ParseQofEReport parses a QofE report body.
func ParseQofEReport(body []byte) MAFields {
	return parseCommon(body)
}

// ParseSPADraft parses an SPA draft body.
func ParseSPADraft(body []byte) MAFields {
	out := parseCommon(body)
	if v, ok := sumARSMillions(body, enterpriseValueRE); ok {
		out.EnterpriseValueARSMillions = v
	}
	return out
}

// ParseDisclosureSchedules parses a disclosure schedules body.
func ParseDisclosureSchedules(body []byte) MAFields {
	return parseCommon(body)
}

// ParseClosingMemo parses a closing memo body.
func ParseClosingMemo(body []byte) MAFields {
	out := parseCommon(body)
	if v, ok := sumARSMillions(body, enterpriseValueRE); ok {
		out.EnterpriseValueARSMillions = v
	}
	if v, ok := sumARSMillions(body, advisoryFeeRE); ok {
		out.AdvisoryFeeARSMillions = v
	}
	if m := successFeeBPSRE.FindSubmatch(body); len(m) > 1 {
		if v, err := strconv.ParseInt(string(m[1]), 10, 64); err == nil {
			out.SuccessFeeBPS = v
		}
	}
	return out
}

// ParseFairnessOpinion parses a fairness opinion body.
func ParseFairnessOpinion(body []byte) MAFields {
	return parseCommon(body)
}

// ParseSynergyAnalysis parses a synergy analysis body.
func ParseSynergyAnalysis(body []byte) MAFields {
	return parseCommon(body)
}

// ParseAntitrustMemo parses an antitrust memo body.
func ParseAntitrustMemo(body []byte) MAFields {
	return parseCommon(body)
}

// ParseHechoRelevanteDraft parses a pre-publication hecho
// relevante body.
func ParseHechoRelevanteDraft(body []byte) MAFields {
	out := parseCommon(body)
	out.HasPreAnnouncementDraft = true
	return out
}

// ParseConfig parses a generic IB-tool config body.
func ParseConfig(body []byte) MAFields {
	return parseCommon(body)
}

// parseCommon extracts the cross-cutting fields.
func parseCommon(body []byte) MAFields {
	var out MAFields
	if len(body) == 0 {
		return out
	}
	if passwordRE.Match(body) || passwordInlineRE.Match(body) ||
		passwordXMLRE.Match(body) {
		out.HasPassword = true
	}
	if m := dealIDRE.FindSubmatch(body); len(m) > 1 {
		out.DealID = string(m[1])
	}
	if m := projectNameRE.FindSubmatch(body); len(m) > 1 {
		out.ProjectName = strings.TrimSpace(string(m[1]))
	}
	if m := advisorFirmRE.FindSubmatch(body); len(m) > 1 {
		out.AdvisorFirm = detectAdvisorFirm(string(m[1]))
	}
	if m := mandateTypeRE.FindSubmatch(body); len(m) > 1 {
		out.MandateType = detectMandateType(string(m[1]))
	}
	if m := dealStageRE.FindSubmatch(body); len(m) > 1 {
		out.DealStage = detectDealStage(string(m[1]))
	}
	if preAnnouncementMarkerRE.Match(body) {
		out.HasPreAnnouncementDraft = true
	}
	if publicTargetRE.Match(body) {
		out.HasPublicTarget = true
	}
	if crossBorderRE.Match(body) {
		out.HasCrossBorderTarget = true
	}
	if c := targetCuitFromBody(body); c != "" {
		out.TargetCuitRaw = c
	}
	if c := bidderCuitFromBody(body); c != "" {
		out.BidderCuitRaw = c
	}
	return out
}

// targetCuitFromBody returns the first target CUIT match.
func targetCuitFromBody(body []byte) string {
	if m := targetCuitKeyRE.FindSubmatch(body); len(m) > 1 {
		return string(m[1])
	}
	return ""
}

// bidderCuitFromBody returns the first bidder CUIT match.
func bidderCuitFromBody(body []byte) string {
	if m := bidderCuitKeyRE.FindSubmatch(body); len(m) > 1 {
		return string(m[1])
	}
	return ""
}

// detectAdvisorFirm sniffs the advisor-firm name string.
func detectAdvisorFirm(s string) AdvisorFirm {
	t := strings.ToLower(strings.TrimSpace(s))
	switch {
	case strings.Contains(t, "galicia") && strings.Contains(t, "ecm"):
		return FirmBancoGaliciaECM
	case strings.Contains(t, "galicia"):
		return FirmBancoGaliciaECM
	case strings.Contains(t, "cohen"):
		return FirmCohenIB
	case strings.Contains(t, "btg pactual") || strings.Contains(t, "btg"):
		return FirmBTGPactualArgentina
	case strings.Contains(t, "adcap"):
		return FirmAdcapSecuritiesIB
	case strings.Contains(t, "allaria"):
		return FirmAllariaLedesmaIB
	case strings.Contains(t, "balanz"):
		return FirmBalanzIB
	case strings.Contains(t, "jpmorgan") || strings.Contains(t, "jp morgan"):
		return FirmJPMorganArgentina
	case strings.Contains(t, "morgan stanley"):
		return FirmMorganStanleyArgentina
	case strings.Contains(t, "citi"):
		return FirmCitiArgentina
	case strings.Contains(t, "itau") || strings.Contains(t, "itaú"):
		return FirmItauBBAArgentina
	case strings.Contains(t, "bbva"):
		return FirmBBVAArgentinaIB
	case strings.Contains(t, "santander"):
		return FirmSantanderRioIB
	case strings.Contains(t, "boutique"):
		return FirmLocalBoutique
	}
	return FirmUnknown
}

// detectMandateType sniffs the mandate-type string.
func detectMandateType(s string) MandateType {
	t := strings.ToLower(strings.TrimSpace(s))
	switch {
	case strings.Contains(t, "sell-side") || strings.Contains(t, "sell side"):
		return MandateSellSide
	case strings.Contains(t, "buy-side") || strings.Contains(t, "buy side"):
		return MandateBuySide
	case strings.Contains(t, "fairness"):
		return MandateFairnessOpinion
	case strings.Contains(t, "defense"):
		return MandateDefense
	case strings.Contains(t, "divest"):
		return MandateDivestiture
	case strings.Contains(t, "spin-off") || strings.Contains(t, "spin off"):
		return MandateSpinOff
	case strings.Contains(t, "capital raise") || strings.Contains(t, "capital-raise"):
		return MandateCapitalRaise
	case strings.Contains(t, "restructuring") || strings.Contains(t, "reestructuracion"):
		return MandateRestructuring
	}
	return MandateUnknown
}

// detectDealStage sniffs the deal-stage string.
func detectDealStage(s string) DealStage {
	t := strings.ToLower(strings.TrimSpace(s))
	switch {
	case strings.Contains(t, "origination"):
		return StageOrigination
	case strings.Contains(t, "pitch"):
		return StagePitch
	case strings.Contains(t, "exclusivity"):
		return StageExclusivity
	case strings.Contains(t, "execution") || strings.Contains(t, "ejecucion"):
		return StageExecution
	case strings.Contains(t, "post-closing") || strings.Contains(t, "post closing"):
		return StagePostClosing
	case strings.Contains(t, "closing") || strings.Contains(t, "cierre"):
		return StageClosing
	}
	return StageUnknown
}

// sumARSMillions totals ARS amounts (returns millions).
func sumARSMillions(body []byte, re *regexp.Regexp) (int64, bool) {
	var sum int64
	found := false
	for _, m := range re.FindAllSubmatch(body, -1) {
		if len(m) <= 1 {
			continue
		}
		raw := strings.ReplaceAll(string(m[1]), ".", "")
		raw = strings.ReplaceAll(raw, ",", "")
		if v, err := strconv.ParseInt(raw, 10, 64); err == nil {
			sum += v
			found = true
		}
	}
	return sum / 1_000_000, found
}
