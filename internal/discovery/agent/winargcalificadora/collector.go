package winargcalificadora

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

// fileCollector walks calificadora install roots + per-user dirs.
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

func (c *fileCollector) Name() string { return "winargcalificadora" }

func (c *fileCollector) Collect(_ context.Context) ([]Row, error) {
	out := make([]Row, 0, 16)

	roots := append([]string{}, c.installRoots...)
	if p := strings.TrimSpace(c.getenv("CALIFICADORA_DIR")); p != "" {
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
			for _, rel := range UserCalDirs() {
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
		CalificadoraID:  CalUnknown,
		AnalystRole:     RoleUnknown,
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
	row.AnalystRole = classifyAnalystRole(row)
	*out = append(*out, row)
}

func (c *fileCollector) mergeFields(row *Row, body []byte) {
	var fields CalFields
	switch row.ArtifactKind {
	case KindRatingLetter:
		fields = ParseRatingLetter(body)
	case KindMethodologyDoc:
		fields = ParseMethodologyDoc(body)
	case KindCommitteeMinutes:
		fields = ParseCommitteeMinutes(body)
	case KindMonitoringReport:
		fields = ParseMonitoringReport(body)
	case KindWatchlist:
		fields = ParseWatchlist(body)
	case KindConflictOfInterestDoc:
		fields = ParseConflictOfInterestDoc(body)
	case KindFeeSchedule:
		fields = ParseFeeSchedule(body)
	case KindInternalCreditModel:
		fields = ParseInternalCreditModel(body)
	case KindDissentingOpinion:
		fields = ParseDissentingOpinion(body)
	case KindIssuerRoster:
		fields = ParseIssuerRoster(body)
	case KindCNVFiling:
		fields = ParseCNVFiling(body)
	case KindSOCReport:
		fields = ParseSOCReport(body)
	case KindConfig, KindCredentials:
		fields = ParseConfig(body)
	case KindInstaller, KindOther, KindUnknown:
		return
	}

	if fields.HasPassword {
		row.HasPasswordInConfig = true
	}
	if fields.HasMethodologyChange {
		row.HasMethodologyChange = true
	}
	if fields.HasCrossIssuerComparable {
		row.HasCrossIssuerComparable = true
	}
	if fields.RatingID != "" {
		row.RatingID = fields.RatingID
	}
	if fields.MethodologyVersion != "" {
		row.MethodologyVersion = fields.MethodologyVersion
	}
	if fields.SeriesID != "" {
		row.SeriesID = fields.SeriesID
	}
	if fields.CalificadoraID != "" && fields.CalificadoraID != CalUnknown {
		row.CalificadoraID = fields.CalificadoraID
	}
	if fields.RatingClass != "" && fields.RatingClass != RatingUnknown {
		row.RatingClass = fields.RatingClass
	}
	if fields.WatchStatus != "" && fields.WatchStatus != WatchUnknown {
		row.WatchStatus = fields.WatchStatus
	}
	if fields.IssuerClass != "" && fields.IssuerClass != IssuerUnknown {
		row.IssuerClass = fields.IssuerClass
	}
	if fields.IssuerCount > 0 {
		row.IssuerCount = fields.IssuerCount
	}
	if fields.WatchIssuerCount > 0 {
		row.WatchIssuerCount = fields.WatchIssuerCount
	}
	if fields.DissentingOpinionCount > 0 {
		row.DissentingOpinionCount = fields.DissentingOpinionCount
	}
	if fields.ModelInputParamCount > 0 {
		row.ModelInputParamCount = fields.ModelInputParamCount
	}
	if fields.FeeTotalARSMillions > 0 {
		row.FeeTotalARSMillions = fields.FeeTotalARSMillions
	}
	if fields.ClienteEmisorCuitRaw != "" {
		if p, s := CuitEntityOnlyFingerprint(fields.ClienteEmisorCuitRaw); p != "" {
			row.ClienteEmisorCuitPrefix = p
			row.ClienteEmisorCuitSuffix4 = s
		}
	}
	if fields.ClienteAnalystCuilRaw != "" {
		if p, s := CuilFingerprint(fields.ClienteAnalystCuilRaw); p != "" {
			row.ClienteAnalystCuilPrefix = p
			row.ClienteAnalystCuilSuffix4 = s
		}
	}
}

// classifyAnalystRole picks the analyst role.
//
// Order:
//
//  1. Compliance officer (CNV filing / SOC report = entity-wide).
//  2. Methodology officer (methodology doc + internal model).
//  3. Committee chair (committee minutes WITH dissenting opinion
//     present — chair manages split outcomes).
//  4. Committee member (committee minutes without dissent).
//  5. Lead analyst (rating letter + watch).
//  6. Quality control (audit-style monitoring + COI doc).
//  7. CRM (issuer roster / fee schedule).
//  8. API (config without filing context).
func classifyAnalystRole(r Row) AnalystRole {
	if r.HasCNVFiling || r.HasSOCReport {
		return RoleComplianceOfficer
	}
	if r.HasMethodologyDoc || r.HasInternalCreditModel {
		return RoleMethodologyOfficer
	}
	if r.HasCommitteeMinutes && r.HasCommitteeSplit {
		return RoleCommitteeChair
	}
	if r.HasCommitteeMinutes || r.HasDissentingOpinion {
		return RoleCommitteeMember
	}
	if r.HasRatingLetter || r.HasWatchlist || r.HasMonitoringReport {
		return RoleLeadAnalyst
	}
	if r.HasConflictOfInterestDoc {
		return RoleQualityControl
	}
	if r.HasIssuerRoster || r.HasFeeSchedule {
		return RoleCRM
	}
	if r.ArtifactKind == KindConfig || r.ArtifactKind == KindCredentials {
		return RoleAPI
	}
	return RoleUnknown
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
