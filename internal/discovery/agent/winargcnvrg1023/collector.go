package winargcnvrg1023

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

// fileCollector walks RG 1023 compliance install roots +
// per-user dirs.
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

func (c *fileCollector) Name() string { return "winargcnvrg1023" }

func (c *fileCollector) Collect(_ context.Context) ([]Row, error) {
	out := make([]Row, 0, 16)

	roots := append([]string{}, c.installRoots...)
	if p := strings.TrimSpace(c.getenv("CNV_RG1023_DIR")); p != "" {
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
			for _, rel := range UserCybersecDirs() {
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
	row := Row{
		FilePath:           path,
		FileSize:           fi.Size(),
		FileMode:           int(fi.Mode().Perm()),
		FileOwnerUID:       ownerUID(fi),
		UserProfile:        user,
		ArtifactKind:       ArtifactKindFromName(filepath.Base(path)),
		ComplianceStatus:   StatusUnknown,
		MaxSeverity:        SeverityUnknown,
		SujetoReguladoKind: SujetoReguladoFromPath(path),
		PeriodYYYYMM:       PeriodFromFilename(filepath.Base(path)),
	}
	if row.SujetoReguladoKind == SujetoUnknown {
		row.SujetoReguladoKind = SujetoOther
	}

	ext := strings.ToLower(filepath.Ext(path))
	// PDF / DOCX / XLSX are binary — we hash them and skip
	// body parsing (the collector doesn't ship a PDF text
	// extractor). Compliance officers typically also stash a
	// parallel JSON / YAML / Markdown summary that this
	// collector will pick up.
	skipBody := ext == ".msi" || ext == ".exe" || ext == ".pdf" ||
		ext == ".docx" || ext == ".doc" ||
		ext == ".xlsx" || ext == ".xls"
	if !skipBody && fi.Size() <= MaxFileBytes {
		body, err := c.readFile(path)
		if err == nil {
			row.FileHash = HashContents(body)
			c.mergeFields(&row, body)
		}
	} else if skipBody {
		body, err := c.readFile(path)
		if err == nil {
			row.FileHash = HashContents(body)
		}
	}

	if c.now().Sub(fi.ModTime()) <= RecentlyWindow {
		row.IsRecent = true
	}

	// Overdue review computation needs `now` — done here.
	if IsReviewOverdue(row.ArtifactKind, row.LastReviewDate, c.now()) {
		row.HasOverdueReview = true
	}

	AnnotateSecurity(&row)
	*out = append(*out, row)
}

func (c *fileCollector) mergeFields(row *Row, body []byte) {
	if row.ArtifactKind == KindInstaller || row.ArtifactKind == KindOther ||
		row.ArtifactKind == KindUnknown {
		return
	}

	fields := ParseRG1023Artifact(body)
	if fields.ComplianceStatus != "" {
		row.ComplianceStatus = ComplianceStatus(fields.ComplianceStatus)
	}
	if SeverityRank(fields.MaxSeverity) > SeverityRank(row.MaxSeverity) {
		row.MaxSeverity = fields.MaxSeverity
	}
	if row.LastReviewDate == "" && fields.LastReviewDate != "" {
		row.LastReviewDate = fields.LastReviewDate
	}
	if row.NextReviewDate == "" && fields.NextReviewDate != "" {
		row.NextReviewDate = fields.NextReviewDate
	}
	if row.ClienteCuitPrefix == "" && fields.ClienteCuitRaw != "" {
		if p, s := CuitFingerprint(fields.ClienteCuitRaw); p != "" {
			row.ClienteCuitPrefix = p
			row.ClienteCuitSuffix4 = s
		}
	}
	if row.OfficerCuitPrefix == "" && fields.OfficerCuitRaw != "" {
		if p, s := CuitFingerprint(fields.OfficerCuitRaw); p != "" {
			if IsHumanCuitPrefix(p) {
				row.OfficerCuitPrefix = p
				row.OfficerCuitSuffix4 = s
			}
		}
	}
	row.FindingCount = fields.FindingCount
	row.CriticalCount = fields.CriticalCount
	row.HighCount = fields.HighCount
	row.MediumCount = fields.MediumCount
	row.OpenFindingCount = fields.OpenFindingCount
	row.ThirdPartyCount = fields.ThirdPartyCount
	row.ThirdPartyUnassessedCount = fields.ThirdPartyUnassessedCount
	row.MFAEntryCount = fields.MFAEntryCount

	// Incident-without-playbook: only meaningful on incident
	// registries.
	if row.ArtifactKind == KindIncidentRegistry &&
		fields.HasIncidentMarker && !fields.HasPlaybookReference {
		row.HasIncidentWithoutPlaybook = true
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
