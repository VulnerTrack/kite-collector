package winargmav

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

// fileCollector walks MAV install roots + per-user dirs.
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

func (c *fileCollector) Name() string { return "winargmav" }

func (c *fileCollector) Collect(_ context.Context) ([]Row, error) {
	out := make([]Row, 0, 16)

	roots := append([]string{}, c.installRoots...)
	if p := strings.TrimSpace(c.getenv("MAV_DIR")); p != "" {
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
			for _, rel := range UserMAVDirs() {
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
		FilePath:        path,
		FileSize:        fi.Size(),
		FileMode:        int(fi.Mode().Perm()),
		FileOwnerUID:    ownerUID(fi),
		UserProfile:     user,
		ArtifactKind:    ArtifactKindFromName(filepath.Base(path)),
		MemberKind:      MemberKindFromPath(path),
		InstrumentClass: InstrumentClassFromName(filepath.Base(path)),
		PeriodYYYYMM:    PeriodFromFilename(filepath.Base(path)),
	}
	if row.MemberKind == MemberUnknown {
		row.MemberKind = MemberOther
	}
	if row.InstrumentClass == InstUnknown {
		row.InstrumentClass = InstOther
	}
	if mat := MatriculaFromText(filepath.Base(path)); mat != "" {
		row.MemberMatricula = mat
	}
	if prefix, suffix := CuitFingerprint(filepath.Base(path)); prefix != "" {
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

	if row.FechaVencimiento != "" && IsOverdueDate(row.FechaVencimiento, c.now()) {
		row.HasDefaultRisk = true
	}
	if row.InstrumentClass == InstChPD &&
		row.FechaLibramiento != "" &&
		IsOverdueDate(row.FechaLibramiento, c.now()) {
		row.HasOverdueLibramiento = true
	}

	AnnotateSecurity(&row)
	*out = append(*out, row)
}

func (c *fileCollector) mergeFields(row *Row, body []byte) {
	// Skip body parsing only for installers / fully-unknown.
	// KindOther still receives parsing because instrument-class
	// files (chpd / pagare / letra / fce / on-sustentable) lack
	// a dedicated ArtifactKind but carry meaningful body data.
	if row.ArtifactKind == KindInstaller ||
		row.ArtifactKind == KindUnknown {
		return
	}
	fields := ParseMAVArtifact(body)
	if row.MemberMatricula == "" && fields.MemberMatricula != "" {
		row.MemberMatricula = fields.MemberMatricula
	}
	if row.ClienteCuitPrefix == "" && fields.ClienteCuitRaw != "" {
		if p, s := CuitFingerprint(fields.ClienteCuitRaw); p != "" {
			row.ClienteCuitPrefix = p
			row.ClienteCuitSuffix4 = s
		}
	}
	if row.LibradorCuitPrefix == "" && fields.LibradorCuitRaw != "" {
		if p, s := CuitFingerprint(fields.LibradorCuitRaw); p != "" {
			row.LibradorCuitPrefix = p
			row.LibradorCuitSuffix4 = s
		}
	}
	if row.ReceptorCuitPrefix == "" && fields.ReceptorCuitRaw != "" {
		if p, s := CuitFingerprint(fields.ReceptorCuitRaw); p != "" {
			row.ReceptorCuitPrefix = p
			row.ReceptorCuitSuffix4 = s
		}
	}
	if row.SGRName == "" && fields.SGRName != "" {
		row.SGRName = fields.SGRName
	}
	if row.Provincia == "" && fields.Provincia != "" {
		row.Provincia = fields.Provincia
	}
	if row.Moneda == MonedaNone && fields.Moneda != MonedaNone {
		row.Moneda = fields.Moneda
	}
	if row.FechaVencimiento == "" && fields.FechaVencimiento != "" {
		row.FechaVencimiento = fields.FechaVencimiento
	}
	if row.FechaLibramiento == "" && fields.FechaLibramiento != "" {
		row.FechaLibramiento = fields.FechaLibramiento
	}
	if fields.MontoCents > 0 {
		row.MontoARSCents = fields.MontoCents
	}
	if fields.TotalPortfolioCents > 0 {
		row.TotalPortfolioARSCents = fields.TotalPortfolioCents
	}
	if fields.MaxConcentrationPct > 0 {
		row.MaxConcentrationPct = fields.MaxConcentrationPct
	}
	if fields.HasDefaultMarker {
		row.HasDefaultRisk = true
	}
	if fields.HasProvDefaultMarker {
		row.HasProvincialDefaultRisk = true
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
