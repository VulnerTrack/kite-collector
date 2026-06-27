package winafippadron

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// DefaultUsersBases is the curated set of per-OS user-profile
// bases.
func DefaultUsersBases() []string {
	return []string{
		`C:\Users`,
		"/home",
		"/Users",
	}
}

// MaxWalkDepth bounds per-user tree depth.
const MaxWalkDepth = 6

// fileCollector walks per-user trees for padrón cache files.
type fileCollector struct {
	getenv     func(string) string
	readFile   func(string) ([]byte, error)
	readDir    func(string) ([]os.DirEntry, error)
	statFile   func(string) (os.FileInfo, error)
	usersBases []string
}

// NewCollector returns a Collector wired to canonical paths.
func NewCollector() Collector {
	return &fileCollector{
		usersBases: DefaultUsersBases(),
		getenv:     os.Getenv,
		readFile:   os.ReadFile,
		readDir:    os.ReadDir,
		statFile:   os.Stat,
	}
}

func (c *fileCollector) Name() string { return "winafippadron" }

func (c *fileCollector) Collect(_ context.Context) ([]Row, error) {
	out := make([]Row, 0, 16)

	for _, k := range []string{"PYAFIPWS_HOME", "AFIPSDK_CACHE_DIR", "AFIP_PADRON_DIR"} {
		if p := strings.TrimSpace(c.getenv(k)); p != "" {
			c.walk(p, "", &out, 0)
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
			c.walk(filepath.Join(base, name), name, &out, 0)
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
		kind := QueryKindFromName(e.Name())
		if kind == QueryUnknown {
			continue
		}
		c.consider(full, user, kind, out)
		if len(*out) >= MaxRows {
			return
		}
	}
}

func (c *fileCollector) consider(path, user string, kind QueryKind, out *[]Row) {
	fi, err := c.statFile(path)
	if err != nil {
		return
	}
	if fi.Size() > MaxFileBytes {
		return
	}
	body, err := c.readFile(path)
	if err != nil {
		return
	}
	row, ok := ParsePadronCache(body)
	if !ok {
		return
	}
	row.FilePath = path
	row.FileHash = HashContents(body)
	row.FileSize = fi.Size()
	row.FileMode = int(fi.Mode().Perm())
	row.FileOwnerUID = ownerUID(fi)
	row.UserProfile = user
	row.QueryKind = kind

	// If parser didn't get a CUIT, try filename.
	if row.TargetCuitPrefix == "" {
		// Look for embedded CUIT in basename.
		base := filepath.Base(path)
		row.TargetCuitPrefix, row.TargetCuitSuffix4 = CuitFingerprint(base)
	}
	AnnotateSecurity(&row)
	*out = append(*out, row)
}

func isCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".xml", ".json":
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
