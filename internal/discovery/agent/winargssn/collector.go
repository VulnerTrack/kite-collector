package winargssn

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

// fileCollector walks SSN install roots + per-user dirs.
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

func (c *fileCollector) Name() string { return "winargssn" }

func (c *fileCollector) Collect(_ context.Context) ([]Row, error) {
	out := make([]Row, 0, 16)

	roots := append([]string{}, c.installRoots...)
	if p := strings.TrimSpace(c.getenv("SSN_DIR")); p != "" {
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
			for _, rel := range UserSSNDirs() {
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
		FilePath:        path,
		FileSize:        fi.Size(),
		FileMode:        int(fi.Mode().Perm()),
		FileOwnerUID:    ownerUID(fi),
		UserProfile:     user,
		ArtifactKind:    ArtifactKindFromName(base),
		InsurerClass:    InsurerUnknown,
		PortfolioClass:  PortfolioUnknown,
		LineOfBusiness:  LOBUnknown,
		ReportingPeriod: PeriodFromFilename(base),
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
	row.InsurerClass = classifyInsurer(row)
	row.PortfolioClass = classifyPortfolio(row)
	*out = append(*out, row)
}

func (c *fileCollector) mergeFields(row *Row, body []byte) {
	var fields SSNFields
	switch row.ArtifactKind {
	case KindInvestmentPortfolio:
		fields = ParseInvestmentPortfolio(body)
	case KindCustodyProof:
		fields = ParseCustodyProof(body)
	case KindFinancialStatement:
		fields = ParseFinancialStatement(body)
	case KindPremiumReport:
		fields = ParsePremiumReport(body)
	case KindClaimReport:
		fields = ParseClaimReport(body)
	case KindReserveReport:
		fields = ParseReserveReport(body)
	case KindCyberPolicyReport:
		fields = ParseCyberPolicyReport(body)
	case KindReinsuranceTreaty:
		fields = ParseReinsuranceTreaty(body)
	case KindARTClaimRecord:
		fields = ParseARTClaim(body)
	case KindFilingReceipt:
		fields = ParseFilingReceipt(body)
	case KindConfig, KindCredentials:
		fields = ParseConfig(body)
	case KindInstaller, KindOther, KindUnknown:
		return
	}

	if fields.HasPassword {
		row.HasPasswordInConfig = true
	}
	if fields.HasLimitBreach {
		row.HasInvestmentLimitBreach = true
	}
	if fields.HasCrossBorderReinsurance {
		row.HasCrossBorderReinsurance = true
	}
	if fields.SSNEntityCode != "" {
		row.SSNEntityCode = fields.SSNEntityCode
	}
	if fields.SSNReceiptID != "" {
		row.SSNReceiptID = fields.SSNReceiptID
	}
	if fields.LineOfBusiness != "" && fields.LineOfBusiness != LOBUnknown {
		row.LineOfBusiness = fields.LineOfBusiness
	}
	if fields.PortfolioInstrumentsCount > 0 {
		row.PortfolioInstrumentsCount = fields.PortfolioInstrumentsCount
	}
	if fields.SovBondPositionCount > 0 {
		row.SovBondPositionCount = fields.SovBondPositionCount
	}
	if fields.FCIPositionCount > 0 {
		row.FCIPositionCount = fields.FCIPositionCount
	}
	if fields.EquityPositionCount > 0 {
		row.EquityPositionCount = fields.EquityPositionCount
	}
	if fields.CEDEARPositionCount > 0 {
		row.CEDEARPositionCount = fields.CEDEARPositionCount
	}
	if fields.PortfolioTotalARSMillions > 0 {
		row.PortfolioTotalARSMillions = fields.PortfolioTotalARSMillions
	}
	if fields.PremiumTotalARSMillions > 0 {
		row.PremiumTotalARSMillions = fields.PremiumTotalARSMillions
	}
	if fields.ClaimCount > 0 {
		row.ClaimCount = fields.ClaimCount
	}
	if row.ClienteCuitPrefix == "" && fields.ClienteCuitRaw != "" {
		if p, s := CuitFingerprint(fields.ClienteCuitRaw); p != "" {
			row.ClienteCuitPrefix = p
			row.ClienteCuitSuffix4 = s
		}
	}
	if row.TrabajadorCuilPrefix == "" && fields.TrabajadorCuilRaw != "" {
		if p, s := CuilFingerprint(fields.TrabajadorCuilRaw); p != "" {
			row.TrabajadorCuilPrefix = p
			row.TrabajadorCuilSuffix4 = s
		}
	}
}

// classifyInsurer picks the insurer class.
//
// Order:
//
//  1. Compliance officer (filing receipt = entity-wide auth).
//  2. ART insurer (ART-claim record).
//  3. Reinsurer (reinsurance treaty).
//  4. Life / non-life / health by LOB.
//  5. Actuary (reserve report = actuarial output).
//  6. API (config without filing context).
func classifyInsurer(r Row) InsurerClass {
	if r.HasFilingReceipt {
		return InsurerComplianceOfficer
	}
	if r.HasARTClaimRecord {
		return InsurerART
	}
	if r.HasReinsuranceTreaty {
		return InsurerReinsurer
	}
	switch r.LineOfBusiness {
	case LOBVidaIndividual, LOBVidaColectivo, LOBRetiro:
		return InsurerLife
	case LOBAutomotor, LOBIncendio, LOBCombinado,
		LOBCaucion, LOBRespCivil, LOBTransporte,
		LOBAgropecuario, LOBCyber:
		return InsurerNonLife
	case LOBSalud:
		return InsurerHealth
	case LOBRiesgosTrabajo:
		return InsurerART
	case LOBReaseguro:
		return InsurerReinsurer
	case LOBCustom, LOBNone, LOBUnknown:
		// Fall through to later signals (reserve, config).
	}
	if r.HasReserveReport {
		return InsurerActuary
	}
	if r.ArtifactKind == KindConfig || r.ArtifactKind == KindCredentials {
		return InsurerAPI
	}
	return InsurerUnknown
}

// classifyPortfolio picks the dominant portfolio class. Order:
//
//  1. Multi-asset (>= 2 distinct portfolio classes present).
//  2. Single dominant class by count.
func classifyPortfolio(r Row) PortfolioClass {
	classes := 0
	if r.SovBondPositionCount > 0 {
		classes++
	}
	if r.FCIPositionCount > 0 {
		classes++
	}
	if r.EquityPositionCount > 0 {
		classes++
	}
	if r.CEDEARPositionCount > 0 {
		classes++
	}
	if classes >= 2 {
		return PortfolioMultiAsset
	}
	switch {
	case r.SovBondPositionCount > 0:
		return PortfolioARSovBond
	case r.FCIPositionCount > 0:
		return PortfolioARFCI
	case r.EquityPositionCount > 0:
		return PortfolioAREquity
	case r.CEDEARPositionCount > 0:
		return PortfolioCEDEAR
	}
	return PortfolioUnknown
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
