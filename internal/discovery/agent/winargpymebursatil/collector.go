package winargpymebursatil

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

// fileCollector walks PyME-bursátil install roots + per-user
// dirs.
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

func (c *fileCollector) Name() string { return "winargpymebursatil" }

func (c *fileCollector) Collect(_ context.Context) ([]Row, error) {
	out := make([]Row, 0, 16)

	roots := append([]string{}, c.installRoots...)
	if p := strings.TrimSpace(c.getenv("PYME_BURSATIL_DIR")); p != "" {
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
			for _, rel := range UserPyMEDirs() {
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
		FilePath:       path,
		FileSize:       fi.Size(),
		FileMode:       int(fi.Mode().Perm()),
		FileOwnerUID:   ownerUID(fi),
		UserProfile:    user,
		InstrumentKind: InstrumentKindFromName(filepath.Base(path)),
	}
	if sgr := SgrMatriculaFromText(filepath.Base(path)); sgr != "" {
		row.SgrMatricula = sgr
	}
	if prefix, suffix := CuitFingerprint(filepath.Base(path)); prefix != "" {
		row.EmisorCuitPrefix = prefix
		row.EmisorCuitSuffix4 = suffix
	}

	ext := strings.ToLower(filepath.Ext(path))
	if ext != ".pdf" && fi.Size() <= MaxFileBytes {
		body, err := c.readFile(path)
		if err == nil {
			row.FileHash = HashContents(body)
			if fields, ok := ParsePyMEInstrument(body); ok {
				if row.EmisorCuitPrefix == "" && fields.EmisorCuitRaw != "" {
					row.EmisorCuitPrefix, row.EmisorCuitSuffix4 = CuitFingerprint(fields.EmisorCuitRaw)
				}
				if fields.ReceptorCuitRaw != "" {
					row.ReceptorCuitPrefix, row.ReceptorCuitSuffix4 = CuitFingerprint(fields.ReceptorCuitRaw)
				}
				if row.SgrMatricula == "" && fields.SgrMatricula != "" {
					row.SgrMatricula = fields.SgrMatricula
				}
				if row.MontoARSCents == 0 {
					row.MontoARSCents = fields.MontoARSCents
				}
				if row.Moneda == "" {
					row.Moneda = MonedaFromText(fields.MonedaText)
				}
				if fields.FechaEmision != "" {
					row.FechaEmision = fields.FechaEmision
				}
				if fields.FechaVencimiento != "" {
					row.FechaVencimiento = fields.FechaVencimiento
				}
				if fields.HasSgrAval {
					row.HasSgrAval = true
				}
			}
		}
	}

	if c.now().Sub(fi.ModTime()) <= RecentlyWindow {
		row.IsRecent = true
	}

	AnnotateSecurityWithClock(&row, c.now)
	*out = append(*out, row)
}

func isSystemPseudoProfile(name string) bool {
	for _, p := range []string{"Public", "Default", "Default User", "All Users"} {
		if strings.EqualFold(name, p) {
			return true
		}
	}
	return false
}
