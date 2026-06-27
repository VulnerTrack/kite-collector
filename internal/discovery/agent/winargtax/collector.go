package winargtax

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const MaxWalkDepth = 6

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

func (c *fileCollector) Name() string { return "winargtax" }

func (c *fileCollector) Collect(_ context.Context) ([]Row, error) {
	out := make([]Row, 0, 16)

	roots := append([]string{}, c.installRoots...)
	if p := strings.TrimSpace(c.getenv("TAX_DIR")); p != "" {
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
			for _, rel := range UserTaxDirs() {
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
		TaxFirm:         FirmUnknown,
		TaxRole:         RoleUnknown,
		TaxRegime:       RegimeUnknown,
		ReportingPeriod: PeriodFromFilename(base),
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
	*out = append(*out, row)
}

func (c *fileCollector) mergeFields(row *Row, body []byte) {
	var fields TaxFields
	switch row.ArtifactKind {
	case KindFiscalOpinion:
		fields = ParseFiscalOpinion(body)
	case KindTransferPricingMemo:
		fields = ParseTransferPricingMemo(body)
	case KindAFIPRG5193Filing:
		fields = ParseAFIPRG5193Filing(body)
	case KindBienesPersonalesFiling:
		fields = ParseBienesPersonalesFiling(body)
	case KindAFIPF8125:
		fields = ParseAFIPF8125(body)
	case KindArgentinaFATCA:
		fields = ParseArgentinaFATCA(body)
	case KindRegimenIndustrial:
		fields = ParseRegimenIndustrial(body)
	case KindTaxLitigationDefense:
		fields = ParseTaxLitigationDefense(body)
	case KindFiscalizacionResponse:
		fields = ParseFiscalizacionResponse(body)
	case KindTaxPositionUncertainty:
		fields = ParseTaxPositionUncertainty(body)
	case KindEngagementLetterTax:
		fields = ParseEngagementLetterTax(body)
	case KindBillableHoursTax:
		fields = ParseBillableHoursTax(body)
	case KindConfig, KindCredentials:
		fields = ParseConfig(body)
	case KindInstaller, KindOther, KindUnknown:
		return
	}

	if fields.HasPassword {
		row.HasPasswordInConfig = true
	}
	if fields.HasPrePublicationDraft {
		row.HasPrePublicationDraft = true
	}
	if fields.EngagementID != "" {
		row.EngagementID = fields.EngagementID
	}
	if fields.ClientName != "" {
		row.ClientNameHash = HashSecret(fields.ClientName)
	}
	if fields.AFIPFilingID != "" {
		row.AFIPFilingID = fields.AFIPFilingID
	}
	if fields.TaxFirm != "" && fields.TaxFirm != FirmUnknown {
		row.TaxFirm = fields.TaxFirm
	}
	if fields.TaxRole != "" && fields.TaxRole != RoleUnknown {
		row.TaxRole = fields.TaxRole
	}
	if fields.TaxRegime != "" && fields.TaxRegime != RegimeUnknown {
		row.TaxRegime = fields.TaxRegime
	}
	if fields.BillableHoursCount > 0 {
		row.BillableHoursCount = fields.BillableHoursCount
	}
	if fields.HNWThresholdARSMillions > 0 {
		row.HNWThresholdARSMillions = fields.HNWThresholdARSMillions
	}
	if fields.TaxReserveARSMillions > 0 {
		row.TaxReserveARSMillions = fields.TaxReserveARSMillions
	}
	if fields.ClienteCuitRaw != "" {
		if p, s := CuitFingerprint(fields.ClienteCuitRaw); p != "" {
			row.ClienteCuitPrefix = p
			row.ClienteCuitSuffix4 = s
		}
	}
	if fields.LawyerCuilRaw != "" {
		if p, s := CuilFingerprint(fields.LawyerCuilRaw); p != "" {
			row.LawyerCuilPrefix = p
			row.LawyerCuilSuffix4 = s
		}
	}
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
