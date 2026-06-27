package winargcrs

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// MaxWalkDepth bounds per-root tree depth.
const MaxWalkDepth = 6

// fileCollector walks AFIP CRS / FATCA install roots + per-user
// dirs.
type fileCollector struct {
	now          func() time.Time
	getenv       func(string) string
	readFile     func(string) ([]byte, error)
	readDir      func(string) ([]os.DirEntry, error)
	statFile     func(string) (os.FileInfo, error)
	installRoots []string
	usersBases   []string
}

// NewCollector returns a Collector wired to canonical paths.
func NewCollector() Collector {
	return &fileCollector{
		installRoots: DefaultInstallRoots(),
		usersBases:   DefaultUsersBases(),
		getenv:       os.Getenv,
		readFile:     os.ReadFile,
		readDir:      os.ReadDir,
		statFile:     os.Stat,
		now:          time.Now,
	}
}

func (c *fileCollector) Name() string { return "winargcrs" }

func (c *fileCollector) Collect(_ context.Context) ([]Row, error) {
	out := make([]Row, 0, 16)

	roots := append([]string{}, c.installRoots...)
	if p := strings.TrimSpace(c.getenv("AFIP_CRS_DIR")); p != "" {
		roots = append([]string{p}, roots...)
	}

	for _, r := range roots {
		c.walk(r, "", &out, 0)
		if len(out) >= MaxRows {
			break
		}
	}

	for _, base := range c.usersBases {
		entries, err := c.readDir(base)
		if err != nil {
			continue
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			name := e.Name()
			if isSystemPseudoProfile(name) || strings.HasPrefix(name, ".") {
				continue
			}
			for _, rel := range UserCRSDirs() {
				c.walk(filepath.Join(append([]string{base, name}, rel...)...),
					name, &out, 0)
				if len(out) >= MaxRows {
					break
				}
			}
			if len(out) >= MaxRows {
				break
			}
		}
		if len(out) >= MaxRows {
			break
		}
	}

	if len(out) > MaxRows {
		out = out[:MaxRows]
	}
	SortRows(out)
	return out, nil
}

func (c *fileCollector) walk(dir, user string, out *[]Row, depth int) {
	if depth > MaxWalkDepth {
		return
	}
	entries, err := c.readDir(dir)
	if err != nil {
		return
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, e := range entries {
		full := filepath.Join(dir, e.Name())
		if e.IsDir() {
			c.walk(full, user, out, depth+1)
			if len(*out) >= MaxRows {
				return
			}
			continue
		}
		if !IsCandidateExt(e.Name()) {
			continue
		}
		if !IsCandidateName(e.Name()) {
			continue
		}
		c.consider(full, user, out)
		if len(*out) >= MaxRows {
			return
		}
	}
}

func (c *fileCollector) consider(path, user string, out *[]Row) {
	for _, existing := range *out {
		if existing.FilePath == path {
			return
		}
	}
	fi, err := c.statFile(path)
	if err != nil {
		return
	}
	base := filepath.Base(path)
	row := Row{
		FilePath:           path,
		FileSize:           fi.Size(),
		FileMode:           int(fi.Mode().Perm()),
		FileOwnerUID:       ownerUID(fi),
		UserProfile:        user,
		ArtifactKind:       ArtifactKindFromName(base),
		ReportingRegime:    RegimeUnknown,
		InstitutionClass:   InstitutionUnknown,
		AccountHolderClass: HolderUnknown,
		CompetentAuthority: CAUnknown,
		ReportingPeriod:    PeriodFromFilename(base),
	}
	if prefix, suffix := CuitFingerprint(base); prefix != "" {
		row.ClienteCuitPrefix = prefix
		row.ClienteCuitSuffix4 = suffix
	}

	ext := strings.ToLower(filepath.Ext(path))
	skipBody := ext == ".msi" || ext == ".exe" || ext == ".pkg" || ext == ".dmg"
	if !skipBody && fi.Size() <= MaxFileBytes {
		body, err := c.readFile(path)
		if err == nil {
			row.FileHash = HashContents(body)
			c.mergeFields(&row, body)
		}
	} else if skipBody && fi.Size() <= MaxFileBytes {
		body, err := c.readFile(path)
		if err == nil {
			row.FileHash = HashContents(body)
		}
	}

	if c.now().Sub(fi.ModTime()) <= RecentlyWindow {
		row.IsRecent = true
	}

	AnnotateSecurity(&row)
	row.InstitutionClass = classifyInstitution(row)
	row.AccountHolderClass = classifyAccountHolder(row)
	*out = append(*out, row)
}

func (c *fileCollector) mergeFields(row *Row, body []byte) {
	var fields CRSFields
	switch row.ArtifactKind {
	case KindCRSXMLBody:
		fields = ParseCRSBody(body)
	case KindFATCAXMLBody:
		fields = ParseFATCABody(body)
	case KindCompetentAuthoritySend:
		fields = ParseCompetentAuthority(body)
	case KindAccountHolderRecord:
		fields = ParseAccountHolder(body)
	case KindSelfCertification:
		fields = ParseSelfCertification(body)
	case KindW8BENForm:
		fields = ParseW8BEN(body)
	case KindW9Form:
		fields = ParseW9(body)
	case KindBalanceReport, KindIncomeReport:
		fields = ParseBalanceReport(body)
	case KindAFIPRG4056Receipt:
		fields = ParseAFIPReceipt(body)
		if fields.ReportingRegime == "" || fields.ReportingRegime == RegimeUnknown {
			fields.ReportingRegime = RegimeRG4056
		}
	case KindAFIPRG3826Receipt:
		fields = ParseAFIPReceipt(body)
		if fields.ReportingRegime == "" || fields.ReportingRegime == RegimeUnknown {
			fields.ReportingRegime = RegimeRG3826
		}
	case KindAFIPRG4838Receipt:
		fields = ParseAFIPReceipt(body)
		if fields.ReportingRegime == "" || fields.ReportingRegime == RegimeUnknown {
			fields.ReportingRegime = RegimeRG4838
		}
	case KindCRSConfig, KindCRSCredentials:
		fields = ParseConfig(body)
	case KindInstaller, KindOther, KindUnknown:
		return
	}

	if fields.HasPassword {
		row.HasPasswordInConfig = true
	}
	if fields.HasCRSXML {
		row.HasCRSXMLBody = true
	}
	if fields.HasFATCAXML {
		row.HasFATCAXMLBody = true
	}
	if fields.HasMultiResidence {
		row.HasMultiResidenceClaim = true
	}
	if fields.ForeignTIN != "" {
		row.ForeignTINHash = HashSecret(fields.ForeignTIN)
	}
	if fields.ForeignTINCountryCode != "" {
		row.ForeignTINCountryCode = fields.ForeignTINCountryCode
	}
	if fields.ReportingFIGIIN != "" {
		row.ReportingFIGIIN = fields.ReportingFIGIIN
	}
	if fields.AFIPReceiptID != "" {
		row.AFIPReceiptID = fields.AFIPReceiptID
	}
	if fields.ReportingRegime != "" && fields.ReportingRegime != RegimeUnknown {
		row.ReportingRegime = fields.ReportingRegime
	}
	if fields.CompetentAuthority != "" && fields.CompetentAuthority != CAUnknown {
		row.CompetentAuthority = fields.CompetentAuthority
	}
	if fields.AccountHolderCount > 0 {
		row.AccountHolderCount = fields.AccountHolderCount
	}
	if fields.BalanceTotalUSDThousands > 0 {
		row.BalanceTotalUSDThousands = fields.BalanceTotalUSDThousands
	}
	if fields.ReportableJurisdictions > 0 {
		row.ReportableJurisdictions = fields.ReportableJurisdictions
	}
	if row.ClienteCuitPrefix == "" && fields.ClienteCuitRaw != "" {
		if p, s := CuitFingerprint(fields.ClienteCuitRaw); p != "" {
			row.ClienteCuitPrefix = p
			row.ClienteCuitSuffix4 = s
		}
	}
}

// classifyInstitution picks the institution class. Order:
//
//  1. Compliance officer (filing receipt or CA transmission =
//     broker-wide reporting authority).
//  2. Investment entity (CRS XML body from ALYC).
//  3. Custodial institution (FATCA XML body from custodian).
//  4. ALYC (account-holder + cliente CUIT = AR ALYC).
//  5. Reporting FI (CRS or FATCA body present).
//  6. API (config without filing context).
func classifyInstitution(r Row) InstitutionClass {
	if r.HasAFIPFilingReceipt || r.HasCompetentAuthority {
		return InstitutionComplianceOfficer
	}
	if r.HasCRSXMLBody {
		return InstitutionInvestmentEntity
	}
	if r.HasFATCAXMLBody {
		return InstitutionCustodial
	}
	if r.HasAccountHolderRecord && r.ClienteCuitPrefix != "" {
		return InstitutionALYC
	}
	if r.HasCRSXMLBody || r.HasFATCAXMLBody {
		return InstitutionReportingFI
	}
	if r.ArtifactKind == KindCRSConfig || r.ArtifactKind == KindCRSCredentials {
		return InstitutionAPI
	}
	return InstitutionUnknown
}

// classifyAccountHolder picks the account-holder class. Order:
//
//  1. HNW (> $250k USD balance).
//  2. US person (W-9 attestation).
//  3. Foreign individual (W-8BEN attestation with country code).
//  4. AR entity (cliente CUIT prefix 30/33/34).
//  5. AR individual (cliente CUIT prefix 20/23/24/27).
//  6. Passive NFFE (account-holder record without US/AR markers).
func classifyAccountHolder(r Row) AccountHolderClass {
	if r.HasHighNetWorthAccount {
		return HolderHighNetWorth
	}
	if r.HasW9Attestation {
		return HolderUSPerson
	}
	if r.HasW8BENAttestation && r.ForeignTINCountryCode != "" {
		return HolderForeignIndividual
	}
	switch r.ClienteCuitPrefix {
	case "30", "33", "34":
		return HolderAREntity
	case "20", "23", "24", "27":
		return HolderARIndividual
	}
	if r.HasForeignTIN && r.ForeignTINCountryCode != "" {
		if r.ForeignTINCountryCode == "US" {
			return HolderUSPerson
		}
		return HolderForeignIndividual
	}
	if r.HasAccountHolderRecord {
		return HolderPassiveNFFE
	}
	return HolderUnknown
}

func isSystemPseudoProfile(name string) bool {
	for _, p := range []string{
		"Public", "Default", "Default User", "All Users", "Shared",
	} {
		if strings.EqualFold(name, p) {
			return true
		}
	}
	return false
}
