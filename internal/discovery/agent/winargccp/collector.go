package winargccp

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

// fileCollector walks CCP install roots + per-user dirs.
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

func (c *fileCollector) Name() string { return "winargccp" }

func (c *fileCollector) Collect(_ context.Context) ([]Row, error) {
	out := make([]Row, 0, 16)

	roots := append([]string{}, c.installRoots...)
	if p := strings.TrimSpace(c.getenv("CCP_DIR")); p != "" {
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
			for _, rel := range UserCCPDirs() {
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
		FilePath:       path,
		FileSize:       fi.Size(),
		FileMode:       int(fi.Mode().Perm()),
		FileOwnerUID:   ownerUID(fi),
		UserProfile:    user,
		ArtifactKind:   ArtifactKindFromName(filepath.Base(path)),
		CCPEntity:      CCPEntityFromPath(path),
		AssetClass:     AssetUnknown,
		PeriodYYYYMM:   PeriodFromFilename(filepath.Base(path)),
		SettlementDate: SettlementDateFromFilename(filepath.Base(path)),
	}
	if row.CCPEntity == CCPUnknown {
		row.CCPEntity = CCPOther
	}
	if mat := MatriculaFromText(filepath.Base(path)); mat != "" {
		row.ClearingMemberMatricula = mat
	}
	if prefix, suffix := CuitFingerprint(filepath.Base(path)); prefix != "" {
		row.ClienteCuitPrefix = prefix
		row.ClienteCuitSuffix4 = suffix
	}

	ext := strings.ToLower(filepath.Ext(path))
	skipBody := ext == ".msi" || ext == ".exe" || ext == ".xlsx" ||
		ext == ".xls"
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
	if row.AssetClass == AssetUnknown {
		row.AssetClass = AssetClassFromBody(body)
	}
	if row.AssetClass == AssetUnknown {
		row.AssetClass = AssetOther
	}

	if row.ArtifactKind == KindInstaller || row.ArtifactKind == KindOther ||
		row.ArtifactKind == KindUnknown {
		return
	}

	fields := ParseCCPArtifact(body)
	if row.ClearingMemberMatricula == "" && fields.ClearingMemberMatricula != "" {
		row.ClearingMemberMatricula = fields.ClearingMemberMatricula
	}
	if row.ClienteCuitPrefix == "" && fields.ClienteCuitRaw != "" {
		if p, s := CuitFingerprint(fields.ClienteCuitRaw); p != "" {
			row.ClienteCuitPrefix = p
			row.ClienteCuitSuffix4 = s
		}
	}
	if row.SettlementDate == "" && fields.SettlementDate != "" {
		row.SettlementDate = fields.SettlementDate
	}
	if row.PeriodYYYYMM == "" && fields.Period != "" {
		if p := PeriodFromFilename("x_" + fields.Period); p != "" {
			row.PeriodYYYYMM = p
		}
	}
	if fields.MarginRequiredCents > 0 {
		row.MarginRequiredARSCents = fields.MarginRequiredCents
	}
	if fields.MarginPostedCents > 0 {
		row.MarginPostedARSCents = fields.MarginPostedCents
	}
	if fields.MarginCallCents > 0 {
		row.MarginCallARSCents = fields.MarginCallCents
	}
	if fields.MaxHaircutPct > 0 {
		row.MaxHaircutPct = fields.MaxHaircutPct
	}
	if fields.CompensadorBalanceCents != 0 {
		row.CompensadorBalanceCents = fields.CompensadorBalanceCents
	}
	if fields.DefaultFundContributionCents > 0 {
		row.DefaultFundContributionCents = fields.DefaultFundContributionCents
	}
	if fields.StressTestVarCents > 0 {
		row.StressTestVarCents = fields.StressTestVarCents
	}
	if fields.HasStressBreach {
		row.HasStressTestBreach = true
	}
	if fields.HasDefaultFundCall {
		row.HasDefaultFundCall = true
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
