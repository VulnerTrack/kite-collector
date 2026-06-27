package winargfgs

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

// fileCollector walks FGS install roots + per-user dirs.
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

func (c *fileCollector) Name() string { return "winargfgs" }

func (c *fileCollector) Collect(_ context.Context) ([]Row, error) {
	out := make([]Row, 0, 16)

	roots := append([]string{}, c.installRoots...)
	if p := strings.TrimSpace(c.getenv("FGS_DIR")); p != "" {
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
			for _, rel := range UserFGSDirs() {
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
		HolderRole:      RoleUnknown,
		PortfolioClass:  PortfolioUnknown,
		AuctionWindow:   WindowUnknown,
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
	row.HolderRole = classifyHolder(row)
	row.PortfolioClass = classifyPortfolio(row)
	*out = append(*out, row)
}

func (c *fileCollector) mergeFields(row *Row, body []byte) {
	var fields FGSFields
	switch row.ArtifactKind {
	case KindCarteraFGS:
		fields = ParseCartera(body)
	case KindLICRecord:
		fields = ParseLICRecord(body)
	case KindDirectorioActa:
		fields = ParseDirectorioActa(body)
	case KindComiteActa:
		fields = ParseComiteActa(body)
	case KindLineamientosDoc:
		fields = ParseLineamientosDoc(body)
	case KindPrimaryAuctionBid:
		fields = ParsePrimaryAuctionBid(body)
	case KindPrimaryAuctionResult:
		fields = ParsePrimaryAuctionResult(body)
	case KindCustodiaRecord:
		fields = ParseCustodiaRecord(body)
	case KindVotingRecord:
		fields = ParseVotingRecord(body)
	case KindSIPAPensionRecord:
		fields = ParseSIPAPensionRecord(body)
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
	if fields.FGSSeriesCode != "" {
		row.FGSSeriesCode = fields.FGSSeriesCode
	}
	if fields.AuctionID != "" {
		row.AuctionID = fields.AuctionID
	}
	if fields.ActaID != "" {
		row.ActaID = fields.ActaID
	}
	if fields.AuctionWindow != "" && fields.AuctionWindow != WindowUnknown {
		row.AuctionWindow = fields.AuctionWindow
	}
	if fields.PortfolioInstrumentsCount > 0 {
		row.PortfolioInstrumentsCount = fields.PortfolioInstrumentsCount
	}
	if fields.LICFaceValueARSMillions > 0 {
		row.LICFaceValueARSMillions = fields.LICFaceValueARSMillions
	}
	if fields.EquityHoldingCount > 0 {
		row.EquityHoldingCount = fields.EquityHoldingCount
	}
	if fields.SovBondHoldingCount > 0 {
		row.SovBondHoldingCount = fields.SovBondHoldingCount
	}
	if fields.PanelLiderHoldingCount > 0 {
		row.PanelLiderHoldingCount = fields.PanelLiderHoldingCount
	}
	if fields.AuctionBidAmountARSMillions > 0 {
		row.AuctionBidAmountARSMillions = fields.AuctionBidAmountARSMillions
	}
	if fields.SIPAPensionerCount > 0 {
		row.SIPAPensionerCount = fields.SIPAPensionerCount
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

// classifyHolder picks the holder role.
//
// Order:
//
//  1. Director (board minutes).
//  2. Comité Inversiones (committee minutes / lineamientos).
//  3. Tesorería (primary auction bid).
//  4. Custodia (custody record).
//  5. SIGEN auditor (filing receipt = audit trail).
//  6. Analista equity (cartera with panel-líder dominant).
//  7. Analista fixed income (cartera with LIC / sov bond
//     dominant).
//  8. API (config without filing context).
func classifyHolder(r Row) HolderRole {
	if r.HasDirectorioActa {
		return RoleDirector
	}
	if r.HasComiteActa || r.HasLineamientosDoc {
		return RoleComiteInversiones
	}
	if r.HasPrimaryAuctionBid || r.HasPrimaryAuctionResult {
		return RoleTesoreria
	}
	if r.HasCustodiaRecord {
		return RoleCustodia
	}
	if r.HasFilingReceipt {
		return RoleAuditoriaSIGEN
	}
	if r.HasVotingRecord {
		return RoleDirector
	}
	if r.HasSIPAPensionRecord {
		return RoleComplianceOfficer
	}
	if r.HasCarteraFGS {
		switch {
		case r.PanelLiderHoldingCount > 0:
			return RoleAnalistaEquity
		case r.SovBondHoldingCount > 0 || r.HasLICRecord:
			return RoleAnalistaFixedIncome
		}
	}
	if r.HasLICRecord {
		return RoleAnalistaFixedIncome
	}
	if r.ArtifactKind == KindConfig || r.ArtifactKind == KindCredentials {
		return RoleAPI
	}
	return RoleUnknown
}

// classifyPortfolio picks the dominant portfolio class.
func classifyPortfolio(r Row) PortfolioClass {
	classes := 0
	if r.HasLICRecord || r.LICFaceValueARSMillions > 0 {
		classes++
	}
	if r.SovBondHoldingCount > 0 {
		classes++
	}
	if r.EquityHoldingCount > 0 {
		classes++
	}
	if classes >= 2 {
		return PortfolioMultiAsset
	}
	switch {
	case r.HasLICRecord || r.LICFaceValueARSMillions > 0:
		return PortfolioLIC
	case r.SovBondHoldingCount > 0:
		return PortfolioARSovBond
	case r.EquityHoldingCount > 0:
		return PortfolioAREquity
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
