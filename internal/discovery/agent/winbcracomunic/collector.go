package winbcracomunic

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

// fileCollector walks BCRA install roots + per-user dirs.
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

func (c *fileCollector) Name() string { return "winbcracomunic" }

func (c *fileCollector) Collect(_ context.Context) ([]Row, error) {
	out := make([]Row, 0, 16)

	roots := append([]string{}, c.installRoots...)
	if p := strings.TrimSpace(c.getenv("BCRA_COM_DIR")); p != "" {
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
			for _, rel := range UserComDirs() {
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
	}
	// Filename-level parse first.
	kind, serie := ParseNumero(filepath.Base(path))
	row.ComunicacionKind = kind
	row.NumeroSerie = serie
	if kind != KindUnknown && serie > 0 {
		row.Numero = FormatNumero(kind, serie)
	}

	ext := strings.ToLower(filepath.Ext(path))
	if ext != ".pdf" && fi.Size() <= MaxFileBytes {
		body, err := c.readFile(path)
		if err == nil {
			row.FileHash = HashContents(body)
			if fields, ok := ParseComunicacion(body); ok {
				if row.Numero == "" && fields.Numero != "" {
					row.Numero = fields.Numero
					if k, s := ParseNumero(fields.Numero); k != KindUnknown {
						row.ComunicacionKind = k
						row.NumeroSerie = s
					}
				}
				if row.Asunto == "" && fields.AsuntoText != "" {
					row.Asunto = MaxStringLen(fields.AsuntoText, MaxAsuntoChars)
				}
				if row.FechaEmision == "" && fields.FechaEmision != "" {
					row.FechaEmision = fields.FechaEmision
				}
				if row.FechaVigencia == "" && fields.FechaVigencia != "" {
					row.FechaVigencia = fields.FechaVigencia
				}
				if row.SustituyeA == "" && fields.SustituyeA != "" {
					row.SustituyeA = fields.SustituyeA
				}
				if row.ModificaA == "" && fields.ModificaA != "" {
					row.ModificaA = fields.ModificaA
				}
				// Materia: prefer explicit body field; fall back to
				// asunto text.
				if fields.MateriaText != "" {
					row.Materia = MateriaFromText(fields.MateriaText)
				}
				if row.Materia == "" || row.Materia == MateriaUnknown {
					row.Materia = MateriaFromText(row.Asunto)
				}
			}
		}
	}
	// Final filename-asunto fallback for materia.
	if row.Materia == "" || row.Materia == MateriaUnknown {
		row.Materia = MateriaFromText(filepath.Base(path))
	}
	if row.Materia == "" {
		row.Materia = MateriaUnknown
	}

	if c.now().Sub(fi.ModTime()) <= RecentlyWindow {
		row.IsRecent = true
	}
	if row.FechaEmision == "" {
		row.FechaEmision = fi.ModTime().UTC().Format(time.RFC3339)
	}

	AnnotateSecurity(&row)
	*out = append(*out, row)
}

func isCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".pdf", ".xml", ".html", ".htm", ".txt":
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
