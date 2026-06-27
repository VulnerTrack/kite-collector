package winafipsiradig

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

// fileCollector walks SIRADIG install roots + per-user dirs.
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

func (c *fileCollector) Name() string { return "winafipsiradig" }

func (c *fileCollector) Collect(_ context.Context) ([]Row, error) {
	out := make([]Row, 0, 16)

	roots := append([]string{}, c.installRoots...)
	if p := strings.TrimSpace(c.getenv("SIRADIG_DIR")); p != "" {
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
			for _, rel := range UserSiradigDirs() {
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
		FilePath:     path,
		FileSize:     fi.Size(),
		FileMode:     int(fi.Mode().Perm()),
		FileOwnerUID: ownerUID(fi),
		UserProfile:  user,
		ArtifactKind: ArtifactKindFromName(filepath.Base(path)),
		PeriodYYYYMM: PeriodFromFilename(filepath.Base(path)),
	}
	if prefix, suffix := CuitFingerprintEmpleado(filepath.Base(path)); prefix != "" {
		row.EmpleadoCuitPrefix = prefix
		row.EmpleadoCuitSuffix4 = suffix
	}

	ext := strings.ToLower(filepath.Ext(path))
	if ext != ".pdf" && fi.Size() <= MaxFileBytes {
		body, err := c.readFile(path)
		if err == nil {
			row.FileHash = HashContents(body)
			if fields, ok := ParseSiradig(body); ok {
				if row.EmpleadoCuitPrefix == "" && fields.EmpleadoCuitRaw != "" {
					row.EmpleadoCuitPrefix, row.EmpleadoCuitSuffix4 = CuitFingerprintEmpleado(fields.EmpleadoCuitRaw)
				}
				if row.EmpleadorCuitPrefix == "" && fields.EmpleadorCuitRaw != "" {
					p, s := CuitFingerprintAny(fields.EmpleadorCuitRaw)
					if IsValidEmpleadorCuitPrefix(p) {
						row.EmpleadorCuitPrefix = p
						row.EmpleadorCuitSuffix4 = s
					}
				}
				if row.ConyugeCuitPrefix == "" && fields.ConyugeCuitRaw != "" {
					row.ConyugeCuitPrefix, row.ConyugeCuitSuffix4 = CuitFingerprintEmpleado(fields.ConyugeCuitRaw)
				}
				if row.LandlordCuitPrefix == "" && fields.LandlordCuitRaw != "" {
					p, s := CuitFingerprintAny(fields.LandlordCuitRaw)
					if p != "" {
						row.LandlordCuitPrefix = p
						row.LandlordCuitSuffix4 = s
					}
				}
				if row.PeriodYYYYMM == "" && fields.Period != "" {
					if p := PeriodFromFilename("x_" + fields.Period); p != "" {
						row.PeriodYYYYMM = p
					}
				}
				if fields.DependientesCount > row.DependientesCount {
					row.DependientesCount = fields.DependientesCount
				}
				if row.AlquilerARSCents == 0 {
					row.AlquilerARSCents = DecimalToCents(fields.AlquilerARSText)
				}
				if row.DeduccionesTotalARSCents == 0 {
					row.DeduccionesTotalARSCents = DecimalToCents(fields.DeduccionesTotalARSText)
				}
			}
		}
	} else if ext == ".pdf" {
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

func isSystemPseudoProfile(name string) bool {
	for _, p := range []string{"Public", "Default", "Default User", "All Users"} {
		if strings.EqualFold(name, p) {
			return true
		}
	}
	return false
}
