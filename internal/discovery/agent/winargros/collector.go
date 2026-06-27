package winargros

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// MaxWalkDepth bounds per-root tree depth.
const MaxWalkDepth = 6

// fileCollector walks UIF install roots + per-user dirs.
type fileCollector struct {
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
	}
}

func (c *fileCollector) Name() string { return "winargros" }

func (c *fileCollector) Collect(_ context.Context) ([]Row, error) {
	out := make([]Row, 0, 16)

	roots := append([]string{}, c.installRoots...)
	if p := strings.TrimSpace(c.getenv("UIF_ROS_DIR")); p != "" {
		roots = append([]string{p}, roots...)
	}
	if p := strings.TrimSpace(c.getenv("UIF_HOME")); p != "" {
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
			for _, rel := range UserROSDirs() {
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
		if !isCandidateExt(e.Name()) {
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
	// Dedupe: overlapping user-dir catalogue (e.g.
	// `Documents/UIF` + `Documents/UIF/ROS`) can have the
	// walker visit the same file twice.
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
		FilePath:     path,
		FileSize:     fi.Size(),
		FileMode:     int(fi.Mode().Perm()),
		FileOwnerUID: ownerUID(fi),
		UserProfile:  user,
		TipoReporte:  TipoReporteFromName(filepath.Base(path)),
	}
	if prefix, suffix := CuitFingerprint(filepath.Base(path)); prefix != "" {
		row.TargetCuitPrefix = prefix
		row.TargetCuitSuffix4 = suffix
	}

	ext := strings.ToLower(filepath.Ext(path))
	if ext != ".pdf" && fi.Size() <= MaxFileBytes {
		body, err := c.readFile(path)
		if err == nil {
			row.FileHash = HashContents(body)
			if fields, ok := ParseROSReport(body); ok {
				if row.TargetCuitPrefix == "" && fields.TargetCuitRaw != "" {
					row.TargetCuitPrefix, row.TargetCuitSuffix4 = CuitFingerprint(fields.TargetCuitRaw)
				}
				if fields.SujetoObligadoCuitRaw != "" {
					row.SujetoObligadoCuitPrefix, row.SujetoObligadoCuitSuffix4 = CuitFingerprint(fields.SujetoObligadoCuitRaw)
				}
				row.MontoARSCents = fields.MontoARSCents
				if row.Estado == "" {
					row.Estado = EstadoFromText(fields.EstadoText)
				}
				if fields.FechaText != "" {
					row.FechaReporte = fields.FechaText
				}
				row.DescripcionLength = fields.DescripcionLength
				row.IsPEPRelated = fields.HasPEPSignal
				if fields.HasTerrorismSignal && row.TipoReporte == TipoROS {
					// Narrative references terrorism financing; promote
					// classification (without overriding explicit RFT).
					row.TipoReporte = TipoRFT
				}
			}
		}
	}
	if row.Estado == "" {
		row.Estado = EstadoUnknown
	}

	AnnotateSecurity(&row)
	*out = append(*out, row)
}

func isCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".xml", ".json", ".txt", ".pdf":
		return true
	}
	return false
}

func isSystemPseudoProfile(name string) bool {
	for _, p := range []string{"Public", "Default", "Default User", "All Users"} {
		if strings.EqualFold(name, p) {
			return true
		}
	}
	return false
}
