package winargipo

import (
	"regexp"
	"strconv"
	"strings"
)

// IPOFields captures scalar fields the audit pipeline needs.
type IPOFields struct {
	BookrunnerALYC    BookrunnerALYC
	BookrunnerRole    BookrunnerRole
	OfferingType      OfferingType
	ListingVenue      ListingVenue
	IssuerCuitRaw     string
	BookrunnerCuitRaw string
	DealCodename      string
	InvestorCount     int64
	AllocationCount   int64
	InsiderCount      int64
	OfferingSizeARS   int64
	GreenshoeSizeARS  int64
	BookrunnerFeeBps  int64
	HasPassword       bool
}

// passwordRE matches a password row in INI / JSON / XML form.
var passwordRE = regexp.MustCompile(
	`(?im)^\s*"?(?:password|passwd|clave|ipo[_\-]?password|ecm[_\-]?password|api[_\-]?token|api[_\-]?key|api[_\-]?secret)"?\s*[:=]\s*\S+`,
)

// passwordInlineRE matches `password="..."` mid-line.
var passwordInlineRE = regexp.MustCompile(
	`(?i)"?\b(?:password|passwd|api_key|api_secret|ipo[_\-]?password|ecm[_\-]?password|bearer[_\-]?token)\b"?\s*[:=]\s*["'][^"']{1,}["']`,
)

// passwordXMLRE matches `<password>secret</password>` form.
var passwordXMLRE = regexp.MustCompile(
	`(?i)<\s*(?:password|passwd|ipo[_\-]?password|ecm[_\-]?password)\s*>([^<]{1,})<\s*/`,
)

// bookrunnerALYCRE matches a bookrunner-ALYC marker in body.
var bookrunnerALYCRE = regexp.MustCompile(
	`(?i)\b(santander[_\- ]?investment|galicia[_\- ]?investments|bbva[_\- ]?ar|macro[_\- ]?securities|btg[_\- ]?pactual[_\- ]?ar|btg[_\- ]?pactual|allaria|cohen[_\- ]?bursatil|bacs|balanz[_\- ]?capital|itau[_\- ]?ar)\b`,
)

// bookrunnerRoleRE matches a bookrunner-role field.
var bookrunnerRoleRE = regexp.MustCompile(
	`(?i)"?(?:bookrunner[_\- ]?role|role|rol)"?\s*[:=>]\s*"?(lead[_\- ]?bookrunner|joint[_\- ]?bookrunner|co[_\- ]?manager|senior[_\- ]?co[_\- ]?manager|selling[_\- ]?group[_\- ]?member|stabilizing[_\- ]?agent|listing[_\- ]?agent)"?`,
)

// offeringTypeRE matches an offering-type field.
var offeringTypeRE = regexp.MustCompile(
	`(?i)"?(?:offering[_\- ]?type|tipo[_\- ]?oferta|deal[_\- ]?type)"?\s*[:=>]\s*"?(ipo|spo|follow[_\- ]?on|rights[_\- ]?issue|block[_\- ]?trade|private[_\- ]?placement[_\- ]?pre[_\- ]?ipo|direct[_\- ]?listing|spac[_\- ]?merger|adr[_\- ]?issuance)"?`,
)

// listingVenueRE matches a listing-venue field.
var listingVenueRE = regexp.MustCompile(
	`(?i)"?(?:listing[_\- ]?venue|venue|listing|mercado[_\- ]?listing)"?\s*[:=>]\s*"?(byma|bcba|mae|nyse|nasdaq|lse|bme|ssx|b3)"?`,
)

// issuerCuitKeyRE matches issuer CUIT field.
var issuerCuitKeyRE = regexp.MustCompile(
	`(?i)"?(?:issuer[_\- ]?cuit|emisor[_\- ]?cuit|company[_\- ]?cuit|cuit[_\- ]?emisor)"?\s*[:=>]\s*"?(\d{2}-?\d{8}-?\d)"?`,
)

// bookrunnerCuitKeyRE matches bookrunner CUIT field.
var bookrunnerCuitKeyRE = regexp.MustCompile(
	`(?i)"?(?:bookrunner[_\- ]?cuit|alyc[_\- ]?cuit|underwriter[_\- ]?cuit|cuit[_\- ]?alyc|cuit)"?\s*[:=>]\s*"?(\d{2}-?\d{8}-?\d)"?`,
)

// dealCodenameRE matches a deal codename (e.g. "Project Pampa").
var dealCodenameRE = regexp.MustCompile(
	`(?i)"?(?:deal[_\- ]?codename|project[_\- ]?codename|deal[_\- ]?name|code[_\- ]?name)"?\s*[:=>]\s*"?([A-Z][A-Za-z0-9\-\._ ]{2,64})"?`,
)

// investorCountRE matches investor count.
var investorCountRE = regexp.MustCompile(
	`(?i)"?(?:investor[_\- ]?count|investors[_\- ]?total|inversores[_\- ]?count)"?\s*[:=>]\s*"?(\d{1,12})`,
)

// allocationCountRE matches allocation count.
var allocationCountRE = regexp.MustCompile(
	`(?i)"?(?:allocation[_\- ]?count|allocations[_\- ]?total|asignaciones[_\- ]?count)"?\s*[:=>]\s*"?(\d{1,12})`,
)

// insiderCountRE matches insider count.
var insiderCountRE = regexp.MustCompile(
	`(?i)"?(?:insider[_\- ]?count|insiders[_\- ]?count|insiders[_\- ]?total)"?\s*[:=>]\s*"?(\d{1,12})`,
)

// offeringSizeRE matches offering size in ARS.
var offeringSizeRE = regexp.MustCompile(
	`(?i)"?(?:offering[_\- ]?size[_\- ]?ars|deal[_\- ]?size[_\- ]?ars|tama(?:n|ñ)o[_\- ]?oferta[_\- ]?ars)"?\s*[:=>]\s*"?(\d{1,15})`,
)

// greenshoeSizeRE matches greenshoe size in ARS.
var greenshoeSizeRE = regexp.MustCompile(
	`(?i)"?(?:greenshoe[_\- ]?size[_\- ]?ars|over[_\- ]?allotment[_\- ]?ars|opcion[_\- ]?greenshoe[_\- ]?ars)"?\s*[:=>]\s*"?(\d{1,15})`,
)

// bookrunnerFeeBpsRE matches bookrunner fee basis points.
var bookrunnerFeeBpsRE = regexp.MustCompile(
	`(?i)"?(?:bookrunner[_\- ]?fee[_\- ]?bps|underwriting[_\- ]?fee[_\- ]?bps|fee[_\- ]?bps|comision[_\- ]?bps)"?\s*[:=>]\s*"?(\d{1,7})`,
)

// ParseIPO parses any IPO artifact body (shared parser).
func ParseIPO(body []byte) IPOFields {
	var out IPOFields
	if len(body) == 0 {
		return out
	}
	if passwordRE.Match(body) || passwordInlineRE.Match(body) ||
		passwordXMLRE.Match(body) {
		out.HasPassword = true
	}
	if m := bookrunnerALYCRE.FindSubmatch(body); len(m) > 1 {
		out.BookrunnerALYC = detectBookrunnerALYC(string(m[1]))
	}
	if m := bookrunnerRoleRE.FindSubmatch(body); len(m) > 1 {
		out.BookrunnerRole = detectBookrunnerRole(string(m[1]))
	}
	if m := offeringTypeRE.FindSubmatch(body); len(m) > 1 {
		out.OfferingType = detectOfferingType(string(m[1]))
	}
	if m := listingVenueRE.FindSubmatch(body); len(m) > 1 {
		out.ListingVenue = detectListingVenue(string(m[1]))
	}
	if c := issuerCuitFromBody(body); c != "" {
		out.IssuerCuitRaw = c
	}
	if c := bookrunnerCuitFromBody(body); c != "" {
		out.BookrunnerCuitRaw = c
	}
	if m := dealCodenameRE.FindSubmatch(body); len(m) > 1 {
		out.DealCodename = string(m[1])
	}
	if m := investorCountRE.FindSubmatch(body); len(m) > 1 {
		if v, err := strconv.ParseInt(string(m[1]), 10, 64); err == nil {
			out.InvestorCount = v
		}
	}
	if m := allocationCountRE.FindSubmatch(body); len(m) > 1 {
		if v, err := strconv.ParseInt(string(m[1]), 10, 64); err == nil {
			out.AllocationCount = v
		}
	}
	if m := insiderCountRE.FindSubmatch(body); len(m) > 1 {
		if v, err := strconv.ParseInt(string(m[1]), 10, 64); err == nil {
			out.InsiderCount = v
		}
	}
	if m := offeringSizeRE.FindSubmatch(body); len(m) > 1 {
		if v, err := strconv.ParseInt(string(m[1]), 10, 64); err == nil {
			out.OfferingSizeARS = v
		}
	}
	if m := greenshoeSizeRE.FindSubmatch(body); len(m) > 1 {
		if v, err := strconv.ParseInt(string(m[1]), 10, 64); err == nil {
			out.GreenshoeSizeARS = v
		}
	}
	if m := bookrunnerFeeBpsRE.FindSubmatch(body); len(m) > 1 {
		if v, err := strconv.ParseInt(string(m[1]), 10, 64); err == nil {
			out.BookrunnerFeeBps = v
		}
	}
	return out
}

// issuerCuitFromBody returns the first issuer CUIT match.
func issuerCuitFromBody(body []byte) string {
	if m := issuerCuitKeyRE.FindSubmatch(body); len(m) > 1 {
		return string(m[1])
	}
	return ""
}

// bookrunnerCuitFromBody returns the first bookrunner CUIT
// match.
func bookrunnerCuitFromBody(body []byte) string {
	if m := bookrunnerCuitKeyRE.FindSubmatch(body); len(m) > 1 {
		return string(m[1])
	}
	return ""
}

// detectBookrunnerALYC normalizes a bookrunner-ALYC string.
func detectBookrunnerALYC(s string) BookrunnerALYC {
	t := strings.ToLower(strings.TrimSpace(s))
	switch {
	case strings.Contains(t, "santander"):
		return ALYCSantanderInvestment
	case strings.Contains(t, "galicia"):
		return ALYCGaliciaInvestments
	case strings.Contains(t, "bbva"):
		return ALYCBBVAAR
	case strings.Contains(t, "macro"):
		return ALYCMacroSecurities
	case strings.Contains(t, "btg") || strings.Contains(t, "pactual"):
		return ALYCBTGPactualAR
	case strings.Contains(t, "allaria"):
		return ALYCAllaria
	case strings.Contains(t, "cohen"):
		return ALYCCohenBursatil
	case t == "bacs" || strings.Contains(t, "bacs "):
		return ALYCBACS
	case strings.Contains(t, "balanz"):
		return ALYCBalanzCapital
	case strings.Contains(t, "itau"):
		return ALYCItauAR
	}
	return ALYCUnknown
}

// detectBookrunnerRole normalizes a bookrunner-role string.
func detectBookrunnerRole(s string) BookrunnerRole {
	t := strings.ToLower(strings.TrimSpace(s))
	switch {
	case strings.Contains(t, "lead"):
		return RoleLeadBookrunner
	case strings.Contains(t, "joint"):
		return RoleJointBookrunner
	case strings.Contains(t, "senior") && strings.Contains(t, "co"):
		return RoleSeniorCoManager
	case strings.Contains(t, "co") && strings.Contains(t, "manager"):
		return RoleCoManager
	case strings.Contains(t, "selling"):
		return RoleSellingGroupMember
	case strings.Contains(t, "stabiliz"):
		return RoleStabilizingAgent
	case strings.Contains(t, "listing"):
		return RoleListingAgent
	}
	return RoleUnknown
}

// detectOfferingType normalizes an offering-type string.
func detectOfferingType(s string) OfferingType {
	t := strings.ToLower(strings.TrimSpace(s))
	switch {
	case strings.Contains(t, "private") && strings.Contains(t, "pre"):
		return OfferingPrivatePlacementPreIPO
	case strings.Contains(t, "direct"):
		return OfferingDirectListing
	case strings.Contains(t, "spac"):
		return OfferingSPACMerger
	case strings.Contains(t, "adr"):
		return OfferingADRIssuance
	case strings.Contains(t, "block"):
		return OfferingBlockTrade
	case strings.Contains(t, "rights"):
		return OfferingRightsIssue
	case strings.Contains(t, "follow"):
		return OfferingFollowOn
	case t == "spo":
		return OfferingSPO
	case t == "ipo":
		return OfferingIPO
	}
	return OfferingUnknown
}

// detectListingVenue normalizes a listing-venue string.
func detectListingVenue(s string) ListingVenue {
	t := strings.ToLower(strings.TrimSpace(s))
	switch t {
	case "byma":
		return VenueBYMA
	case "bcba":
		return VenueBCBA
	case "mae":
		return VenueMAE
	case "nyse":
		return VenueNYSE
	case "nasdaq":
		return VenueNASDAQ
	case "lse":
		return VenueLSE
	case "bme":
		return VenueBME
	case "ssx":
		return VenueSSX
	case "b3":
		return VenueB3
	}
	return VenueUnknown
}
