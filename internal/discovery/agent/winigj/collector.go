package winigj

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

// fileCollector walks IGJ install roots + per-user dirs.
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

func (c *fileCollector) Name() string { return "winigj" }

func (c *fileCollector) Collect(_ context.Context) ([]Row, error) {
	out := make([]Row, 0, 16)

	roots := append([]string{}, c.installRoots...)
	if p := strings.TrimSpace(c.getenv("IGJ_DIR")); p != "" {
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
			for _, rel := range UserIGJDirs() {
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
	// Dedupe.
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
		ActoKind:     ActoKindFromName(filepath.Base(path)),
	}
	if prefix, suffix := CuitFingerprint(filepath.Base(path)); prefix != "" {
		row.SociedadCuitPrefix = prefix
		row.SociedadCuitSuffix4 = suffix
	}
	if correlativo := CorrelativoFromText(filepath.Base(path)); correlativo != "" {
		row.IgjCorrelativo = correlativo
	}

	ext := strings.ToLower(filepath.Ext(path))
	if ext != ".pdf" && fi.Size() <= MaxFileBytes {
		body, err := c.readFile(path)
		if err == nil {
			row.FileHash = HashContents(body)
			if fields, ok := ParseIGJActo(body); ok {
				if row.SociedadCuitPrefix == "" && fields.SociedadCuitRaw != "" {
					row.SociedadCuitPrefix, row.SociedadCuitSuffix4 = CuitFingerprint(fields.SociedadCuitRaw)
				}
				if row.SociedadDenominacion == "" && fields.SociedadDenominacion != "" {
					row.SociedadDenominacion = TruncateString(fields.SociedadDenominacion, MaxDenominacionChars)
				}
				if row.Estado == "" {
					row.Estado = EstadoFromText(fields.EstadoText)
				}
				if row.FechaActo == "" && fields.FechaActo != "" {
					row.FechaActo = fields.FechaActo
				}
				if row.FechaInscripcion == "" && fields.FechaInscripcion != "" {
					row.FechaInscripcion = fields.FechaInscripcion
				}
				if row.IgjCorrelativo == "" && fields.IgjCorrelativo != "" {
					row.IgjCorrelativo = fields.IgjCorrelativo
				}
				if row.IgjLegajo == "" && fields.IgjLegajo != "" {
					row.IgjLegajo = fields.IgjLegajo
				}
				if row.TipoSocietario == "" {
					row.TipoSocietario = TipoSocietarioFromText(fields.TipoSocietarioText)
				}
				if row.TipoSocietario == "" || row.TipoSocietario == TipoUnknown {
					row.TipoSocietario = TipoSocietarioFromText(row.SociedadDenominacion)
				}
			}
		}
	}
	// Fallback: classify tipo from filename basename.
	if row.TipoSocietario == "" || row.TipoSocietario == TipoUnknown {
		row.TipoSocietario = TipoSocietarioFromText(filepath.Base(path))
	}
	if row.TipoSocietario == "" {
		row.TipoSocietario = TipoUnknown
	}
	if row.Estado == "" {
		row.Estado = EstadoUnknown
	}

	if c.now().Sub(fi.ModTime()) <= RecentlyWindow {
		row.IsRecent = true
	}

	AnnotateSecurity(&row)
	*out = append(*out, row)
}

func isCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".pdf", ".xml", ".html", ".htm", ".txt", ".json":
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
