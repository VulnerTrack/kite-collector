package winpjn

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

// fileCollector walks PJN install roots + per-user dirs. Test
// seam swaps readFile / readDir / statFile / getenv / now.
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

func (c *fileCollector) Name() string { return "winpjn" }

func (c *fileCollector) Collect(_ context.Context) ([]Row, error) {
	out := make([]Row, 0, 16)

	roots := append([]string{}, c.installRoots...)
	if p := strings.TrimSpace(c.getenv("PJN_HOME")); p != "" {
		roots = append([]string{p}, roots...)
	}
	if p := strings.TrimSpace(c.getenv("LEXDOCTOR_HOME")); p != "" {
		roots = append([]string{p}, roots...)
	}

	for _, root := range roots {
		c.walk(root, "", &out, 0)
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
			for _, rel := range UserNotificationDirs() {
				dir := filepath.Join(append([]string{base, name}, rel...)...)
				c.walk(dir, name, &out, 0)
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
	fi, err := c.statFile(path)
	if err != nil {
		return
	}
	row := Row{
		FilePath:         path,
		FileSize:         fi.Size(),
		FileMode:         int(fi.Mode().Perm()),
		FileOwnerUID:     ownerUID(fi),
		UserProfile:      user,
		NotificationKind: NotificationKindFromName(filepath.Base(path)),
		NotificationDate: fi.ModTime().UTC().Format(time.RFC3339),
	}

	// Filename heuristics first.
	row.TipoProceso = TipoProcesoFromText(filepath.Base(path))
	if prefix, suffix := CuitFingerprint(filepath.Base(path)); prefix != "" {
		row.TargetCuitPrefix = prefix
		row.TargetCuitSuffix4 = suffix
	}
	if year, sfx := CuijFingerprint(filepath.Base(path)); year != "" {
		row.CuijYear = year
		row.CuijSuffix4 = sfx
	}

	// Skip body inspection for PDF / large files — PDFs are
	// opaque, and oversize files cost too much to hash.
	ext := strings.ToLower(filepath.Ext(path))
	if ext != ".pdf" && fi.Size() <= MaxFileBytes {
		body, err := c.readFile(path)
		if err == nil {
			row.FileHash = HashContents(body)
			if fields, ok := ParseSiblingMetadata(body); ok {
				if row.TipoProceso == ProcesoUnknown {
					row.TipoProceso = TipoProcesoFromText(fields.TipoProcesoText + " " + fields.Caratula)
				}
				if row.Juzgado == "" {
					row.Juzgado = TruncateString(fields.JuzgadoText, MaxJuzgadoChars)
				}
				if row.Secretaria == "" {
					row.Secretaria = TruncateString(fields.SecretariaText, MaxSecretariaChars)
				}
				if row.TargetCuitPrefix == "" && fields.CuitRaw != "" {
					row.TargetCuitPrefix, row.TargetCuitSuffix4 = CuitFingerprint(fields.CuitRaw)
				}
				if row.CuijYear == "" && fields.CuijRaw != "" {
					row.CuijYear, row.CuijSuffix4 = CuijFingerprint(fields.CuijRaw)
				}
				if fields.FechaText != "" {
					row.NotificationDate = fields.FechaText
				}
			}
		}
	}

	// Recency from mtime.
	if c.now().Sub(fi.ModTime()) <= RecentlyWindow {
		row.IsRecent = true
	}

	AnnotateSecurity(&row)
	*out = append(*out, row)
}

func isCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".pdf", ".xml", ".html", ".htm", ".json", ".txt":
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
