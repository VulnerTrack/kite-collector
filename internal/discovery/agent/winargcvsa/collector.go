package winargcvsa

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

// fileCollector walks CVSA install roots + per-user dirs.
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

func (c *fileCollector) Name() string { return "winargcvsa" }

func (c *fileCollector) Collect(_ context.Context) ([]Row, error) {
	out := make([]Row, 0, 16)

	roots := append([]string{}, c.installRoots...)
	if p := strings.TrimSpace(c.getenv("CVSA_CUSTODY_DIR")); p != "" {
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
			for _, rel := range UserCVSADirs() {
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
		FilePath:               path,
		FileSize:               fi.Size(),
		FileMode:               int(fi.Mode().Perm()),
		FileOwnerUID:           ownerUID(fi),
		UserProfile:            user,
		ArtifactKind:           ArtifactKindFromName(filepath.Base(path)),
		PeriodYYYYMM:           PeriodFromFilename(filepath.Base(path)),
		CuentaComitenteSuffix4: CuentaSuffix4(filepath.Base(path)),
	}
	if mat := MatriculaFromText(filepath.Base(path)); mat != "" {
		row.BrokerMatricula = mat
	}
	if prefix, suffix := CuitFingerprint(filepath.Base(path)); prefix != "" {
		if IsBrokerCuitPrefix(prefix) {
			row.BrokerCuitPrefix = prefix
			row.BrokerCuitSuffix4 = suffix
		} else {
			row.ClienteCuitPrefix = prefix
			row.ClienteCuitSuffix4 = suffix
		}
	}

	ext := strings.ToLower(filepath.Ext(path))
	if ext != ".cda" && fi.Size() <= MaxFileBytes {
		body, err := c.readFile(path)
		if err == nil {
			row.FileHash = HashContents(body)
			if fields, ok := ParseCVSAArtifact(body); ok {
				if row.BrokerMatricula == "" && fields.BrokerMatricula != "" {
					row.BrokerMatricula = fields.BrokerMatricula
				}
				if row.BrokerCuitPrefix == "" && fields.BrokerCuitRaw != "" {
					if p, s := CuitFingerprint(fields.BrokerCuitRaw); p != "" {
						row.BrokerCuitPrefix = p
						row.BrokerCuitSuffix4 = s
					}
				}
				if row.ClienteCuitPrefix == "" && fields.ClienteCuitRaw != "" {
					if p, s := CuitFingerprint(fields.ClienteCuitRaw); p != "" {
						row.ClienteCuitPrefix = p
						row.ClienteCuitSuffix4 = s
					}
				}
				if row.CuentaComitenteSuffix4 == "" && fields.CuentaComitenteID != "" {
					id := fields.CuentaComitenteID
					if len(id) > 4 {
						id = id[len(id)-4:]
					}
					row.CuentaComitenteSuffix4 = id
				}
				if row.PeriodYYYYMM == "" && fields.Period != "" {
					if p := PeriodFromFilename("x_" + fields.Period); p != "" {
						row.PeriodYYYYMM = p
					}
				}
				if fields.HasForeignOwner {
					row.HasForeignOwner = true
				}
				row.InstrumentCount = fields.InstrumentCount
				row.CotitularesCount = fields.CotitularesCount
				row.MaxPositionARSCents = fields.MaxPositionCents
				row.TotalPositionARSCents = fields.TotalCents
				if fields.TotalCents > 0 && fields.MaxPositionCents > 0 {
					row.MaxPositionPct = int(fields.MaxPositionCents * 100 / fields.TotalCents)
					if row.MaxPositionPct > 100 {
						row.MaxPositionPct = 100
					}
				}
			}
		}
	} else if ext == ".cda" {
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
