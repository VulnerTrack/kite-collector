package winargir

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

// fileCollector walks IR install roots + per-user dirs.
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

func (c *fileCollector) Name() string { return "winargir" }

func (c *fileCollector) Collect(_ context.Context) ([]Row, error) {
	out := make([]Row, 0, 16)

	roots := append([]string{}, c.installRoots...)
	if p := strings.TrimSpace(c.getenv("IR_DIR")); p != "" {
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
			for _, rel := range UserIRDirs() {
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
		IssuerClass:     IssuerUnknown,
		IRRole:          RoleUnknown,
		DisclosurePhase: PhaseUnknown,
		ReportingPeriod: PeriodFromFilename(base),
	}

	ext := strings.ToLower(filepath.Ext(path))
	skipBody := ext == ".msi" || ext == ".exe" || ext == ".pkg" || ext == ".dmg" ||
		ext == ".mp3" || ext == ".wav" || ext == ".m4a" || ext == ".ogg"
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
	row.IRRole = classifyIRRole(row)
	*out = append(*out, row)
}

func (c *fileCollector) mergeFields(row *Row, body []byte) {
	var fields IRFields
	switch row.ArtifactKind {
	case KindHechoRelevanteDraft:
		fields = ParseHechoRelevanteDraft(body)
	case KindInsiderList:
		fields = ParseInsiderList(body)
	case KindEarningsCallScript:
		fields = ParseEarningsCallScript(body)
	case KindEarningsCallQA:
		fields = ParseEarningsCallQA(body)
	case KindPressRelease:
		fields = ParsePressRelease(body)
	case KindAnalystReport:
		fields = ParseAnalystReport(body)
	case KindAnalystCoverageList:
		fields = ParseAnalystCoverageList(body)
	case KindRoadshow:
		fields = ParseRoadshow(body)
	case KindConferenceCallRecording:
		fields = ParseConferenceCallRecording(body)
	case KindSustainabilityReport:
		fields = ParseSustainabilityReport(body)
	case KindESGDisclosure:
		fields = ParseESGDisclosure(body)
	case KindMemoriaAnual:
		fields = ParseMemoriaAnual(body)
	case KindEstadosContablesPublic:
		fields = ParseEstadosContablesPublic(body)
	case KindConflictDisclosure:
		fields = ParseConflictDisclosure(body)
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
	if fields.HasCrossListedUSIssuer {
		row.HasCrossListedUSIssuer = true
	}
	if fields.CNVFilingID != "" {
		row.CNVFilingID = fields.CNVFilingID
	}
	if fields.IssuerName != "" {
		row.IssuerNameHash = HashSecret(fields.IssuerName)
	}
	if fields.IssuerClass != "" && fields.IssuerClass != IssuerUnknown {
		row.IssuerClass = fields.IssuerClass
	}
	if fields.DisclosurePhase != "" && fields.DisclosurePhase != PhaseUnknown {
		row.DisclosurePhase = fields.DisclosurePhase
	}
	if fields.InsiderCount > 0 {
		row.InsiderCount = fields.InsiderCount
	}
	if fields.AnalystCount > 0 {
		row.AnalystCount = fields.AnalystCount
	}
	if fields.ClienteEmisorCuitRaw != "" {
		if p, s := CuitEntityOnlyFingerprint(fields.ClienteEmisorCuitRaw); p != "" {
			row.ClienteEmisorCuitPrefix = p
			row.ClienteEmisorCuitSuffix4 = s
		}
	}
	if fields.InsiderCuilRaw != "" {
		if p, s := CuilFingerprint(fields.InsiderCuilRaw); p != "" {
			row.InsiderCuilPrefix = p
			row.InsiderCuilSuffix4 = s
		}
	}
}

// classifyIRRole picks the IR role.
//
// Order:
//
//  1. Compliance officer (HR draft + insider list = legal-mandate
//     authority under Ley 26.831 art.103).
//  2. CFO (estados contables + memoria anual = CFO sign-off).
//  3. CEO (memoria anual alone — annual CEO message).
//  4. Board secretary (conflict disclosure + insider list).
//  5. IR director (HR draft + roadshow = senior IR).
//  6. IR manager (earnings call script + Q&A).
//  7. IR analyst (analyst report + coverage list).
//  8. Communications lead (press release + sustainability).
//  9. General counsel (conflict disclosure alone — legal review).
//  10. API.
func classifyIRRole(r Row) IRRole {
	if r.HasHechoRelevanteDraft && r.HasInsiderList {
		return RoleComplianceOfficer
	}
	if r.HasEstadosContablesPublic && r.HasMemoriaAnual {
		return RoleCFO
	}
	if r.HasMemoriaAnual {
		return RoleCEO
	}
	if r.HasConflictDisclosure && r.HasInsiderList {
		return RoleBoardSecretary
	}
	if r.HasHechoRelevanteDraft && r.HasRoadshowMaterial {
		return RoleIRDirector
	}
	if r.HasEarningsCallScript || r.HasEarningsCallQA {
		return RoleIRManager
	}
	if r.HasAnalystReport || r.HasAnalystCoverageList {
		return RoleIRAnalyst
	}
	if r.HasPressReleaseDraft || r.HasSustainabilityReport ||
		r.HasESGDisclosure {
		return RoleCommunicationsLead
	}
	if r.HasHechoRelevanteDraft {
		return RoleIRDirector
	}
	if r.HasInsiderList {
		return RoleComplianceOfficer
	}
	if r.HasConflictDisclosure {
		return RoleGeneralCounsel
	}
	if r.HasRoadshowMaterial || r.HasConferenceCallRecording {
		return RoleIRDirector
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
