package winarguifros

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

// fileCollector walks UIF install roots + per-user dirs.
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

func (c *fileCollector) Name() string { return "winarguifros" }

func (c *fileCollector) Collect(_ context.Context) ([]Row, error) {
	out := make([]Row, 0, 16)

	roots := append([]string{}, c.installRoots...)
	if p := strings.TrimSpace(c.getenv("UIF_DIR")); p != "" {
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
			for _, rel := range UserUIFDirs() {
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
		SujetoObligadoKind: SujetoObligadoFromPath(path),
		PeriodYYYYMM:       PeriodFromFilename(filepath.Base(path)),
	}
	if row.SujetoObligadoKind == SujetoUnknown {
		row.SujetoObligadoKind = SujetoOther
	}
	if row.ArtifactKind == KindSanctionsList {
		row.SanctionsListSource = SanctionsSourceFromName(filepath.Base(path))
	}
	if prefix, suffix := CuitFingerprint(filepath.Base(path)); prefix != "" {
		// Filename-level CUITs default to cliente classification.
		row.ClienteCuitPrefix = prefix
		row.ClienteCuitSuffix4 = suffix
	}

	ext := strings.ToLower(filepath.Ext(path))
	skipBody := ext == ".msi" || ext == ".exe" || ext == ".pdf" ||
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

	AnnotateSecurity(&row)
	*out = append(*out, row)
}

func (c *fileCollector) mergeFields(row *Row, body []byte) {
	var fields UIFFields
	switch row.ArtifactKind {
	case KindROSExport, KindROIExport, KindRFTExport,
		KindKYCDossier, KindMonitoringAlert, KindSumario,
		KindComplianceReport, KindDDJJPEP:
		fields = ParseUIFReport(body)
	case KindPEPList:
		fields = ParsePEPList(body)
	case KindSanctionsList:
		fields = ParseSanctionsList(body)
	case KindInstaller, KindOther, KindUnknown:
		return
	}

	if fields.HasPEPMarker {
		// PEP marker from body — distinct from filename
		// SanctionsListSource. Hashed (no raw name).
		if fields.PEPName != "" {
			row.PEPNameHash = HashSecret(fields.PEPName)
		} else {
			row.PEPNameHash = HashSecret("anonymous-pep-detection")
		}
	}
	if fields.HasSanctionsMarker && row.SanctionsListSource == SanctionsNone {
		row.SanctionsListSource = SanctionsOther
	}
	if fields.HasHighRiskJurisdiction {
		row.HighRiskJurisdiction = fields.HighRiskJurisdiction
	}
	if fields.HasStructuringMarker {
		row.HasStructuringPattern = true
	}
	if fields.HasKYCBody {
		row.HasKYCBody = true
	}
	if row.ClienteCuitPrefix == "" && fields.ClienteCuitRaw != "" {
		if p, s := CuitFingerprint(fields.ClienteCuitRaw); p != "" {
			row.ClienteCuitPrefix = p
			row.ClienteCuitSuffix4 = s
		}
	}
	if row.CumplientoOfficerCuitPfx == "" && fields.OfficerCuitRaw != "" {
		if p, s := CuitFingerprint(fields.OfficerCuitRaw); p != "" {
			if IsHumanCuitPrefix(p) {
				row.CumplientoOfficerCuitPfx = p
				row.CumplientoOfficerCuitSf4 = s
			}
		}
	}
	if row.PeriodYYYYMM == "" && fields.Period != "" {
		if p := PeriodFromFilename("x_" + fields.Period); p != "" {
			row.PeriodYYYYMM = p
		}
	}
	if fields.Status != "" {
		row.ReportStatus = normalizeStatus(fields.Status)
	} else if row.ReportStatus == StatusNone {
		row.ReportStatus = StatusUnknown
	}
	row.AlertCount = fields.AlertCount
	row.TransactionCount = fields.TransactionCount
	if fields.MaxAmountCents > 0 {
		row.MaxAmountARSCents = fields.MaxAmountCents
	}
	if fields.TotalAmountCents > 0 {
		row.TotalAmountARSCents = fields.TotalAmountCents
	}
}

func normalizeStatus(s string) ReportStatus {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "draft", "borrador":
		return StatusDraft
	case "filed", "presentado", "enviado":
		return StatusFiled
	case "rejected", "rechazado":
		return StatusRejected
	case "accepted", "aceptado", "aprobado":
		return StatusAccepted
	}
	return StatusUnknown
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
