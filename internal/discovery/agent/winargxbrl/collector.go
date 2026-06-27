package winargxbrl

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

// fileCollector walks per-user trees looking for Argentine
// XBRL filings. Test seam swaps readFile / readDir / statFile
// / getenv.
type fileCollector struct {
	getenv     func(string) string
	readFile   func(string) ([]byte, error)
	readDir    func(string) ([]os.DirEntry, error)
	statFile   func(string) (os.FileInfo, error)
	usersBases []string
}

// NewCollector returns a Collector wired to the canonical
// per-OS paths.
func NewCollector() Collector {
	return &fileCollector{
		usersBases: DefaultUsersBases(),
		getenv:     os.Getenv,
		readFile:   os.ReadFile,
		readDir:    os.ReadDir,
		statFile:   os.Stat,
	}
}

func (c *fileCollector) Name() string { return "winargxbrl" }

func (c *fileCollector) Collect(_ context.Context) ([]Filing, error) {
	out := make([]Filing, 0, 16)

	for _, k := range []string{"CNV_AIF_DIR", "XBRL_FILINGS_DIR"} {
		if p := strings.TrimSpace(c.getenv(k)); p != "" {
			c.walk(p, "", &out, 0)
		}
	}

	for _, base := range c.usersBases {
		entries, err := c.readDir(base)
		if err != nil {
			continue
		}
		sort.Slice(entries, func(i, j int) bool {
			return entries[i].Name() < entries[j].Name()
		})
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			name := e.Name()
			if isSystemPseudoProfile(name) || strings.HasPrefix(name, ".") {
				continue
			}
			c.walk(filepath.Join(base, name), name, &out, 0)
			if len(out) >= MaxFilings {
				break
			}
		}
		if len(out) >= MaxFilings {
			break
		}
	}

	if len(out) > MaxFilings {
		out = out[:MaxFilings]
	}
	SortFilings(out)
	return out, nil
}

func (c *fileCollector) walk(dir, user string, out *[]Filing, depth int) {
	if depth > MaxWalkDepth {
		return
	}
	entries, err := c.readDir(dir)
	if err != nil {
		return
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name() < entries[j].Name()
	})
	for _, e := range entries {
		full := filepath.Join(dir, e.Name())
		if e.IsDir() {
			c.walk(full, user, out, depth+1)
			if len(*out) >= MaxFilings {
				return
			}
			continue
		}
		if !isXBRLCandidateExt(e.Name()) {
			continue
		}
		if !IsXBRLCandidatePath(full) {
			continue
		}
		c.consider(full, user, out)
		if len(*out) >= MaxFilings {
			return
		}
	}
}

func (c *fileCollector) consider(path, user string, out *[]Filing) {
	fi, err := c.statFile(path)
	if err != nil {
		return
	}
	if fi.Size() > MaxFileBytes {
		// Inventory metadata only.
		f := Filing{
			FilePath:     path,
			FileSize:     fi.Size(),
			FileMode:     int(fi.Mode().Perm()),
			FileOwnerUID: ownerUID(fi),
			UserProfile:  user,
			FilingKind:   ClassifyByExtension(path),
		}
		AnnotateSecurity(&f)
		*out = append(*out, f)
		return
	}
	body, err := c.readFile(path)
	if err != nil {
		return
	}
	hash := HashContents(body)
	f, ok := ParseXBRLInstance(body)
	if !ok {
		// Non-XBRL XML — skip silently. We don't want to flood
		// the table with arbitrary XML the user happens to keep
		// in a `xbrl/` directory.
		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".xsd" || ext == ".zip" {
			f = Filing{FilingKind: ClassifyByExtension(path)}
		} else {
			return
		}
	}
	f.FilePath = path
	f.FileHash = hash
	f.FileSize = fi.Size()
	f.FileMode = int(fi.Mode().Perm())
	f.FileOwnerUID = ownerUID(fi)
	f.UserProfile = user
	AnnotateSecurity(&f)
	*out = append(*out, f)
}

func isXBRLCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".xbrl", ".xml", ".zip", ".xsd":
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
