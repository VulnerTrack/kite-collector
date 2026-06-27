package winargbeneficiarios

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// MaxWalkDepth bounds per-root tree depth.
const MaxWalkDepth = 6

// fileCollector walks UBO install roots + per-user dirs.
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

func (c *fileCollector) Name() string { return "winargbeneficiarios" }

func (c *fileCollector) Collect(_ context.Context) ([]Row, error) {
	out := make([]Row, 0, 16)

	roots := append([]string{}, c.installRoots...)
	if p := strings.TrimSpace(c.getenv("AFIP_BF_DIR")); p != "" {
		roots = append([]string{p}, roots...)
	}
	if p := strings.TrimSpace(c.getenv("UIF_BF_DIR")); p != "" {
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
			for _, rel := range UserUBODirs() {
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
		FilingKind:   FilingKindFromName(filepath.Base(path)),
		PeriodYYYY:   PeriodFromName(filepath.Base(path)),
	}

	// Filename CUIT (obligado).
	if prefix, suffix := CuitFingerprint(filepath.Base(path)); prefix != "" {
		row.ObligadoCuitPrefix = prefix
		row.ObligadoCuitSuffix4 = suffix
	}

	// Skip body parse for PDF / oversized.
	ext := strings.ToLower(filepath.Ext(path))
	if ext != ".pdf" && fi.Size() <= MaxFileBytes {
		body, err := c.readFile(path)
		if err == nil {
			row.FileHash = HashContents(body)
			if fields, ok := ParseUBODeclaration(body); ok {
				if row.ObligadoCuitPrefix == "" && fields.ObligadoCuitRaw != "" {
					row.ObligadoCuitPrefix, row.ObligadoCuitSuffix4 = CuitFingerprint(fields.ObligadoCuitRaw)
				}
				if row.ObligadoDenominacion == "" && fields.ObligadoDenominacion != "" {
					row.ObligadoDenominacion = TruncateString(fields.ObligadoDenominacion, MaxDenominacionChars)
				}
				if row.PeriodYYYY == "" && fields.PeriodYYYY != "" {
					row.PeriodYYYY = fields.PeriodYYYY
				}
				if row.Estado == "" {
					row.Estado = EstadoFromText(fields.EstadoText)
				}
				row.BeneficiariosCount = fields.BeneficiariosCount
				row.MaxParticipacionPct = fields.MaxParticipacionPct
				row.HasIndirectControlChain = fields.HasIndirectControlChain
				row.HasExtranjeroBeneficiario = fields.HasExtranjeroUBO
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
