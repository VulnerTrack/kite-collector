package winargabogado

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

// fileCollector walks legal install roots + per-user dirs.
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

func (c *fileCollector) Name() string { return "winargabogado" }

func (c *fileCollector) Collect(_ context.Context) ([]Row, error) {
	out := make([]Row, 0, 16)

	roots := append([]string{}, c.installRoots...)
	if p := strings.TrimSpace(c.getenv("ABOGADO_DIR")); p != "" {
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
			for _, rel := range UserAbogadoDirs() {
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
		LawFirm:         FirmUnknown,
		LegalRole:       RoleUnknown,
		MatterClass:     MatterUnknown,
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
	row.LegalRole = classifyLegalRole(row)
	*out = append(*out, row)
}

func (c *fileCollector) mergeFields(row *Row, body []byte) {
	var fields AbogadoFields
	switch row.ArtifactKind {
	case KindLegalOpinion:
		fields = ParseLegalOpinion(body)
	case KindTrueSaleOpinion:
		fields = ParseTrueSaleOpinion(body)
	case Kind10b5Letter:
		fields = Parse10b5Letter(body)
	case KindNoActionLetter:
		fields = ParseNoActionLetter(body)
	case KindEngagementLetter:
		fields = ParseEngagementLetter(body)
	case KindBillableHours:
		fields = ParseBillableHours(body)
	case KindProspectoLegalReview:
		fields = ParseProspectoLegalReview(body)
	case KindCovenantComplianceMemo:
		fields = ParseCovenantComplianceMemo(body)
	case KindBondholderConsent:
		fields = ParseBondholderConsent(body)
	case KindRestructuringPlan:
		fields = ParseRestructuringPlan(body)
	case KindEnforcementDefense:
		fields = ParseEnforcementDefense(body)
	case KindPrivilegedCommunication:
		fields = ParsePrivilegedCommunication(body)
	case KindClassActionDefense:
		fields = ParseClassActionDefense(body)
	case KindConfig, KindCredentials:
		fields = ParseConfig(body)
	case KindInstaller, KindOther, KindUnknown:
		return
	}

	if fields.HasPassword {
		row.HasPasswordInConfig = true
	}
	if fields.HasPrivilegedMarker {
		row.HasPrivilegedMarker = true
	}
	if fields.HasPrePublicationDraft {
		row.HasPrePublicationDraft = true
	}
	if fields.HasCovenantBreach {
		row.HasCovenantBreach = true
	}
	if fields.HasCrossBorderMatter {
		row.HasCrossBorderMatter = true
	}
	if fields.MatterID != "" {
		row.MatterID = fields.MatterID
	}
	if fields.MatterName != "" {
		row.MatterNameHash = HashSecret(fields.MatterName)
	}
	if fields.BarNumber != "" {
		row.BarNumber = fields.BarNumber
	}
	if fields.LawFirm != "" && fields.LawFirm != FirmUnknown {
		row.LawFirm = fields.LawFirm
	}
	if fields.MatterClass != "" && fields.MatterClass != MatterUnknown {
		row.MatterClass = fields.MatterClass
	}
	if fields.BillableHoursCount > 0 {
		row.BillableHoursCount = fields.BillableHoursCount
	}
	if fields.HourlyRateARS > 0 {
		row.HourlyRateARS = fields.HourlyRateARS
	}
	if fields.RetainerARSMillions > 0 {
		row.RetainerARSMillions = fields.RetainerARSMillions
	}
	if fields.ClienteEmisorCuitRaw != "" {
		if p, s := CuitEntityOnlyFingerprint(fields.ClienteEmisorCuitRaw); p != "" {
			row.ClienteEmisorCuitPrefix = p
			row.ClienteEmisorCuitSuffix4 = s
		}
	}
	if fields.LawyerCuilRaw != "" {
		if p, s := CuilFingerprint(fields.LawyerCuilRaw); p != "" {
			row.LawyerCuilPrefix = p
			row.LawyerCuilSuffix4 = s
		}
	}
}

// classifyLegalRole picks the legal role.
//
// Order:
//
//  1. Compliance officer (enforcement defense + cross-border).
//  2. Partner (opinion + engagement = partner-level review).
//  3. Senior associate (true sale OR 10b-5 letter = senior
//     analytical work).
//  4. Associate (covenant memo OR consent solicitation).
//  5. Of counsel (restructuring plan).
//  6. Knowledge management (no-action letter, KM repository).
//  7. Billing clerk (billable hours).
//  8. Paralegal (prospecto review + class action defense).
//  9. Legal tech (config without engagement context).
//  10. API.
func classifyLegalRole(r Row) LegalRole {
	if r.HasEnforcementDefense && r.HasCrossBorderMatter {
		return RoleComplianceOfficer
	}
	if r.HasLegalOpinion && r.HasEngagementLetter {
		return RolePartner
	}
	if r.HasTrueSaleOpinion || r.Has10b5Letter {
		return RoleSeniorAssociate
	}
	if r.HasCovenantComplianceMemo || r.HasBondholderConsent {
		return RoleAssociate
	}
	if r.HasRestructuringPlan {
		return RoleOfCounsel
	}
	if r.HasNoActionLetter {
		return RoleKnowledgeManagement
	}
	if r.HasBillableHours {
		return RoleBillingClerk
	}
	if r.HasProspectoLegalReview || r.HasClassActionDefense {
		return RoleParalegal
	}
	if r.HasLegalOpinion {
		return RolePartner
	}
	if r.HasEngagementLetter {
		return RolePartner
	}
	if r.HasPrivilegedCommunication {
		return RoleAssociate
	}
	if r.HasEnforcementDefense {
		return RoleComplianceOfficer
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
