package winargperito

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

// fileCollector walks auditor install roots + per-user dirs.
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

func (c *fileCollector) Name() string { return "winargperito" }

func (c *fileCollector) Collect(_ context.Context) ([]Row, error) {
	out := make([]Row, 0, 16)

	roots := append([]string{}, c.installRoots...)
	if p := strings.TrimSpace(c.getenv("AUDITOR_DIR")); p != "" {
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
			for _, rel := range UserPeritoDirs() {
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
		AuditFirm:       FirmUnknown,
		EngagementRole:  RoleUnknown,
		ClientClass:     ClientUnknown,
		AuditPhase:      PhaseUnknown,
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
	row.EngagementRole = classifyEngagementRole(row)
	*out = append(*out, row)
}

func (c *fileCollector) mergeFields(row *Row, body []byte) {
	var fields PeritoFields
	switch row.ArtifactKind {
	case KindWorkpaper:
		fields = ParseWorkpaper(body)
	case KindEngagementLetter:
		fields = ParseEngagementLetter(body)
	case KindInternalControlAssessment:
		fields = ParseInternalControlAssessment(body)
	case KindConfirmationBank:
		fields = ParseConfirmationBank(body)
	case KindConfirmationBrokerage:
		fields = ParseConfirmationBrokerage(body)
	case KindConfirmationLegal:
		fields = ParseConfirmationLegal(body)
	case KindLetterRepresentations:
		fields = ParseLetterRepresentations(body)
	case KindInternalControlDeficiency:
		fields = ParseInternalControlDeficiency(body)
	case KindAuditFeeSchedule:
		fields = ParseAuditFeeSchedule(body)
	case KindAuditCommitteeMinutes:
		fields = ParseAuditCommitteeMinutes(body)
	case KindManagementLetter:
		fields = ParseManagementLetter(body)
	case KindAuditPlan:
		fields = ParseAuditPlan(body)
	case KindGoingConcernOpinion:
		fields = ParseGoingConcernOpinion(body)
	case KindSOCRelianceReport:
		fields = ParseSOCRelianceReport(body)
	case KindSubsequentEventsReview:
		fields = ParseSubsequentEventsReview(body)
	case KindConfig, KindCredentials:
		fields = ParseConfig(body)
	case KindInstaller, KindOther, KindUnknown:
		return
	}

	if fields.HasPassword {
		row.HasPasswordInConfig = true
	}
	if fields.HasDraftMarker {
		row.HasDraftMarker = true
	}
	if fields.HasCrossListedUSIssuer {
		row.HasCrossListedUSIssuer = true
	}
	if fields.EngagementID != "" {
		row.EngagementID = fields.EngagementID
	}
	if fields.ClientName != "" {
		row.ClientNameHash = HashSecret(fields.ClientName)
	}
	if fields.AuditFirm != "" && fields.AuditFirm != FirmUnknown {
		row.AuditFirm = fields.AuditFirm
	}
	if fields.ClientClass != "" && fields.ClientClass != ClientUnknown {
		row.ClientClass = fields.ClientClass
	}
	if fields.AuditPhase != "" && fields.AuditPhase != PhaseUnknown {
		row.AuditPhase = fields.AuditPhase
	}
	if fields.ConfirmationCount > 0 {
		row.ConfirmationCount = fields.ConfirmationCount
	}
	if fields.DeficiencyCount > 0 {
		row.DeficiencyCount = fields.DeficiencyCount
	}
	if fields.AuditFeeARSMillions > 0 {
		row.AuditFeeARSMillions = fields.AuditFeeARSMillions
	}
	if fields.NonAuditFeeARSMillions > 0 {
		row.NonAuditFeeARSMillions = fields.NonAuditFeeARSMillions
	}
	if fields.WorkpaperCount > 0 {
		row.WorkpaperCount = fields.WorkpaperCount
	}
	if fields.ClienteEmisorCuitRaw != "" {
		if p, s := CuitEntityOnlyFingerprint(fields.ClienteEmisorCuitRaw); p != "" {
			row.ClienteEmisorCuitPrefix = p
			row.ClienteEmisorCuitSuffix4 = s
		}
	}
	if fields.AuditorCuilRaw != "" {
		if p, s := CuilFingerprint(fields.AuditorCuilRaw); p != "" {
			row.AuditorCuilPrefix = p
			row.AuditorCuilSuffix4 = s
		}
	}
}

// classifyEngagementRole picks the engagement role.
//
// Order:
//
//  1. Compliance officer (SOC reliance + non-audit fees = COI
//     monitoring authority).
//  2. Quality reviewer (audit committee minutes + going concern
//     = independent reviewer signature).
//  3. Engagement team leader (engagement letter + audit plan =
//     partner-level engagement setup).
//  4. Partner (going concern opinion + management letter =
//     partner signatures).
//  5. Senior manager (internal control assessment + ICDR).
//  6. Senior auditor (working papers + confirmations).
//  7. Staff auditor (subsequent events review).
//  8. API (config without engagement context).
func classifyEngagementRole(r Row) EngagementRole {
	if r.HasSOCRelianceReport || r.HasIndependenceBreach {
		return RoleComplianceOfficer
	}
	if r.HasAuditCommitteeMinutes && r.HasGoingConcernOpinion {
		return RoleQualityReviewer
	}
	if r.HasEngagementLetter && r.HasAuditPlan {
		return RoleEngagementTeamLeader
	}
	if r.HasGoingConcernOpinion || r.HasManagementLetter {
		return RolePartner
	}
	if r.HasInternalControlAssessment || r.HasInternalControlDeficiency {
		return RoleSeniorManager
	}
	if r.HasWorkpaper || r.HasConfirmationBank ||
		r.HasConfirmationBrokerage || r.HasConfirmationLegal {
		return RoleSeniorAuditor
	}
	if r.HasSubsequentEventsReview {
		return RoleStaffAuditor
	}
	if r.HasAuditCommitteeMinutes {
		return RoleQualityReviewer
	}
	if r.HasEngagementLetter || r.HasAuditPlan {
		return RoleEngagementTeamLeader
	}
	if r.HasLetterRepresentations || r.HasAuditFeeSchedule {
		return RoleManager
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
