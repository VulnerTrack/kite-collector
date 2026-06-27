package winargma

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

// fileCollector walks M&A install roots + per-user dirs.
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

func (c *fileCollector) Name() string { return "winargma" }

func (c *fileCollector) Collect(_ context.Context) ([]Row, error) {
	out := make([]Row, 0, 16)

	roots := append([]string{}, c.installRoots...)
	if p := strings.TrimSpace(c.getenv("MA_DIR")); p != "" {
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
			for _, rel := range UserMADirs() {
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
		AdvisorFirm:     FirmUnknown,
		DealRole:        RoleUnknown,
		MandateType:     MandateUnknown,
		DealStage:       StageUnknown,
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
	row.DealRole = classifyDealRole(row)
	*out = append(*out, row)
}

func (c *fileCollector) mergeFields(row *Row, body []byte) {
	var fields MAFields
	switch row.ArtifactKind {
	case KindPitchDeck:
		fields = ParsePitchDeck(body)
	case KindNDA:
		fields = ParseNDA(body)
	case KindInformationMemorandum:
		fields = ParseInformationMemorandum(body)
	case KindDataroomManifest:
		fields = ParseDataroomManifest(body)
	case KindBidderRoster:
		fields = ParseBidderRoster(body)
	case KindProcessLetter:
		fields = ParseProcessLetter(body)
	case KindBidEvaluation:
		fields = ParseBidEvaluation(body)
	case KindDCFModel:
		fields = ParseDCFModel(body)
	case KindLBOModel:
		fields = ParseLBOModel(body)
	case KindMergerModel:
		fields = ParseMergerModel(body)
	case KindQofEReport:
		fields = ParseQofEReport(body)
	case KindSPADraft:
		fields = ParseSPADraft(body)
	case KindDisclosureSchedules:
		fields = ParseDisclosureSchedules(body)
	case KindClosingMemo:
		fields = ParseClosingMemo(body)
	case KindFairnessOpinion:
		fields = ParseFairnessOpinion(body)
	case KindSynergyAnalysis:
		fields = ParseSynergyAnalysis(body)
	case KindAntitrustMemo:
		fields = ParseAntitrustMemo(body)
	case KindHechoRelevanteDraft:
		fields = ParseHechoRelevanteDraft(body)
	case KindConfig, KindCredentials:
		fields = ParseConfig(body)
	case KindInstaller, KindOther, KindUnknown:
		return
	}

	if fields.HasPassword {
		row.HasPasswordInConfig = true
	}
	if fields.HasPreAnnouncementDraft {
		row.HasPreAnnouncementDraft = true
	}
	if fields.HasCrossBorderTarget {
		row.HasCrossBorderTarget = true
	}
	if fields.HasPublicTarget {
		row.HasPublicTarget = true
	}
	if fields.DealID != "" {
		row.DealID = fields.DealID
	}
	if fields.ProjectName != "" {
		row.ProjectNameHash = HashSecret(fields.ProjectName)
	}
	if fields.AdvisorFirm != "" && fields.AdvisorFirm != FirmUnknown {
		row.AdvisorFirm = fields.AdvisorFirm
	}
	if fields.MandateType != "" && fields.MandateType != MandateUnknown {
		row.MandateType = fields.MandateType
	}
	if fields.DealStage != "" && fields.DealStage != StageUnknown {
		row.DealStage = fields.DealStage
	}
	if fields.BidderCount > 0 {
		row.BidderCount = fields.BidderCount
	}
	if fields.DataroomFileCount > 0 {
		row.DataroomFileCount = fields.DataroomFileCount
	}
	if fields.EnterpriseValueARSMillions > 0 {
		row.EnterpriseValueARSMillions = fields.EnterpriseValueARSMillions
	}
	if fields.AdvisoryFeeARSMillions > 0 {
		row.AdvisoryFeeARSMillions = fields.AdvisoryFeeARSMillions
	}
	if fields.SuccessFeeBPS > 0 {
		row.SuccessFeeBPS = fields.SuccessFeeBPS
	}
	if fields.TargetCuitRaw != "" {
		if p, s := CuitEntityOnlyFingerprint(fields.TargetCuitRaw); p != "" {
			row.TargetCuitPrefix = p
			row.TargetCuitSuffix4 = s
		}
	}
	if fields.BidderCuitRaw != "" {
		if p, s := CuitEntityOnlyFingerprint(fields.BidderCuitRaw); p != "" {
			row.BidderCuitPrefix = p
			row.BidderCuitSuffix4 = s
		}
	}
}

// classifyDealRole picks the deal role.
//
// Order:
//
//  1. Compliance officer (hecho relevante draft = compliance
//     pre-publication review).
//  2. Antitrust counsel (antitrust memo).
//  3. Engagement team leader (pitch + IM = partner-level pitch).
//  4. Managing director (fairness opinion + closing memo).
//  5. Director (SPA draft + disclosure schedules).
//  6. VP (DCF / LBO / merger model + synergy).
//  7. Associate (IM + dataroom + bidder roster).
//  8. Analyst (QofE + comparable analysis).
//  9. Data-room admin (dataroom manifest).
//  10. Operations (NDA + process letter).
//  11. API (config without deal context).
func classifyDealRole(r Row) DealRole {
	if r.HasHechoRelevanteDraft {
		return RoleComplianceOfficer
	}
	if r.HasAntitrustMemo {
		return RoleAntitrustCounsel
	}
	if r.HasPitchDeck && r.HasInformationMemorandum {
		return RoleEngagementTeamLeader
	}
	if r.HasFairnessOpinion || r.HasClosingMemo {
		return RoleManagingDirector
	}
	if r.HasSPADraft || r.HasDisclosureSchedules {
		return RoleDirector
	}
	if r.HasDCFModel || r.HasLBOModel ||
		r.HasMergerModel || r.HasSynergyAnalysis {
		return RoleVP
	}
	if r.HasInformationMemorandum || r.HasBidderRoster ||
		r.HasBidEvaluation {
		return RoleAssociate
	}
	if r.HasQofEReport {
		return RoleAnalyst
	}
	if r.HasDataroomManifest {
		return RoleDataRoomAdmin
	}
	if r.HasPitchDeck {
		return RoleEngagementTeamLeader
	}
	if r.HasNDA || r.HasProcessLetter {
		return RoleOperations
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
