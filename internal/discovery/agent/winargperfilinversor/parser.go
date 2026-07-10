package winargperfilinversor

import (
	"bytes"
	"math"
	"regexp"
	"strconv"
	"strings"
)

// PerfilFields captures scalar fields the audit pipeline
// needs from a Perfil del Inversor artifact.
type PerfilFields struct {
	BrokerMatricula      string
	ClienteCuitRaw       string
	RiskCategory         RiskCategory
	LastReviewDate       string
	NextReviewDate       string
	Period               string
	InstrumentClassList  string
	DeclaredAnnualIncome int64
	DeclaredNetWorth     int64
	HasMissingSignature  bool
	HasNoKYCLink         bool
	HasAggressiveNoTest  bool
}

// riskCategoryRE matches `risk_category: <name>` /
// `categoria_inversor: <name>` rows.
var riskCategoryRE = regexp.MustCompile(
	`(?i)("|')?(risk[_\- ]?category|categoria[_\- ]?inversor|categoria[_\- ]?riesgo|categoria|risk[_\- ]?profile)("|')?\s*[:=>]\s*"?([A-Za-zÁÉÍÓÚáéíóúñÑ ]{4,40})"?`,
)

// lastReviewDateRE matches `last_review_date: YYYY-MM-DD`.
var lastReviewDateRE = regexp.MustCompile(
	`(?i)("|')?(last[_\- ]?review[_\- ]?date|fecha[_\- ]?revision|ultima[_\- ]?revision|fecha[_\- ]?perfil)("|')?\s*[:=>]\s*"?(20\d{2}-\d{2}-\d{2})`,
)

// nextReviewDateRE matches `next_review_date: YYYY-MM-DD`.
var nextReviewDateRE = regexp.MustCompile(
	`(?i)("|')?(next[_\- ]?review[_\- ]?date|proxima[_\- ]?revision|fecha[_\- ]?proxima)("|')?\s*[:=>]\s*"?(20\d{2}-\d{2}-\d{2})`,
)

// annualIncomeRE matches `annual_income: NN` / `ingreso_anual: NN`.
var annualIncomeRE = regexp.MustCompile(
	`(?i)("|')?(annual[_\- ]?income|ingreso[_\- ]?anual|ingresos[_\- ]?declarados|salario[_\- ]?anual)("|')?\s*[:=>]\s*"?([0-9]+(?:\.[0-9]{3})*(?:[.,][0-9]{1,4})?)`,
)

// netWorthRE matches `net_worth: NN` / `patrimonio_neto: NN`.
var netWorthRE = regexp.MustCompile(
	`(?i)("|')?(net[_\- ]?worth|patrimonio[_\- ]?neto|patrimonio[_\- ]?declarado)("|')?\s*[:=>]\s*"?([0-9]+(?:\.[0-9]{3})*(?:[.,][0-9]{1,4})?)`,
)

// instrumentClassListRE matches `instrument_classes: [list]` /
// `instrumentos: lista` rows.
var instrumentClassListRE = regexp.MustCompile(
	`(?i)("|')?(instrument[_\- ]?classes|instrumentos[_\- ]?habilitados|operatoria[_\- ]?autorizada)("|')?\s*[:=>]\s*("|'|\[)?([A-Za-z0-9_,\- ]{2,200})`,
)

// missingSignatureRE detects a missing-signature marker.
var missingSignatureRE = regexp.MustCompile(
	`(?i)(?:firma[_\- ]?falta|missing[_\- ]?signature|sin[_\- ]?firma|signature[_\- ]?missing|no[_\- ]?firmado|unsigned)`,
)

// noKYCLinkRE detects an explicit no-KYC-link marker.
var noKYCLinkRE = regexp.MustCompile(
	`(?i)(?:kyc[_\- ]?missing|sin[_\- ]?kyc|no[_\- ]?kyc[_\- ]?link|kyc[_\- ]?ref[_\- ]?missing)`,
)

// aggressiveNoTestRE detects an aggressive-without-test
// marker.
var aggressiveNoTestRE = regexp.MustCompile(
	`(?i)(?:agresiva[_\- ]?sin[_\- ]?test|aggressive[_\- ]?no[_\- ]?test|test[_\- ]?riesgo[_\- ]?falta)`,
)

// matriculaIniRE matches `BrokerMatricula=NNN` / `Matricula=NNN`.
var matriculaIniRE = regexp.MustCompile(
	`(?im)^\s*"?(?:Matricula|BrokerMatricula|AAGMatricula|AgenteMatricula)"?\s*[:=>]\s*"?(\d{1,5})"?`,
)

// matriculaXMLRE matches `<matricula>NNN</matricula>` so XML
// bodies don't need a separate parser.
var matriculaXMLRE = regexp.MustCompile(
	`(?i)<(?:matricula|broker_matricula|agente_matricula)>(\d{1,5})</`,
)

// clienteCuitKeyRE matches `cliente_cuit: NN-NNNNNNNN-N`.
var clienteCuitKeyRE = regexp.MustCompile(
	`(?i)"?(?:cliente[_\- ]?cuit|cuit[_\- ]?cliente|titular[_\- ]?cuit|cuit)"?\s*[:=>]\s*"?(\d{2}-?\d{8}-?\d)"?`,
)

// ParsePerfilArtifact parses a Perfil del Inversor body and
// extracts scalar fields.
func ParsePerfilArtifact(body []byte) PerfilFields {
	out := PerfilFields{RiskCategory: CategoryUnknown}
	if len(body) == 0 {
		return out
	}
	body = bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF})

	if m := riskCategoryRE.FindSubmatch(body); len(m) > 4 {
		out.RiskCategory = NormalizeRiskCategory(string(m[4]))
	}
	if m := lastReviewDateRE.FindSubmatch(body); len(m) > 4 {
		out.LastReviewDate = string(m[4])
	}
	if m := nextReviewDateRE.FindSubmatch(body); len(m) > 4 {
		out.NextReviewDate = string(m[4])
	}
	if m := annualIncomeRE.FindSubmatch(body); len(m) > 4 {
		out.DeclaredAnnualIncome = decimalToCents(string(m[4]))
	}
	if m := netWorthRE.FindSubmatch(body); len(m) > 4 {
		out.DeclaredNetWorth = decimalToCents(string(m[4]))
	}
	if m := instrumentClassListRE.FindSubmatch(body); len(m) > 5 {
		out.InstrumentClassList = strings.TrimSpace(string(m[5]))
	}
	if missingSignatureRE.Match(body) {
		out.HasMissingSignature = true
	}
	if noKYCLinkRE.Match(body) {
		out.HasNoKYCLink = true
	}
	if aggressiveNoTestRE.Match(body) {
		out.HasAggressiveNoTest = true
	}
	if m := matriculaIniRE.FindSubmatch(body); m != nil {
		out.BrokerMatricula = string(m[1])
	}
	if out.BrokerMatricula == "" {
		if m := matriculaXMLRE.FindSubmatch(body); m != nil {
			out.BrokerMatricula = string(m[1])
		}
	}
	if m := clienteCuitKeyRE.FindSubmatch(body); m != nil {
		out.ClienteCuitRaw = string(m[1])
	}
	if out.ClienteCuitRaw == "" {
		if m := cuitRE.FindSubmatch(body); m != nil {
			out.ClienteCuitRaw = string(m[1]) + string(m[2]) + string(m[3])
		}
	}
	return out
}

// decimalToCents parses positive decimal to cents.
func decimalToCents(s string) int64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	if strings.Count(s, ".") > 0 && strings.Count(s, ",") > 0 {
		s = strings.ReplaceAll(s, ".", "")
		s = strings.ReplaceAll(s, ",", ".")
	} else {
		s = strings.ReplaceAll(s, ",", ".")
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0
	}
	if math.IsNaN(f) || math.IsInf(f, 0) || f <= 0 {
		return 0
	}
	return int64(math.Round(f * 100))
}
