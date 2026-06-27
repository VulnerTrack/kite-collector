package winfilezilla

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

// SitemanagerRelComponentsPosix is the POSIX per-user path tail:
// `.config/filezilla/sitemanager.xml`.
func SitemanagerRelComponentsPosix() []string {
	return []string{".config", "filezilla", "sitemanager.xml"}
}

// SitemanagerRelComponentsWindows is the Windows per-user path
// tail: `AppData\Roaming\FileZilla\sitemanager.xml`.
func SitemanagerRelComponentsWindows() []string {
	return []string{"AppData", "Roaming", "FileZilla", "sitemanager.xml"}
}

// fileCollector walks sitemanager.xml from per-user trees +
// `FZ_DATADIR` env override. Test seam swaps readFile /
// readDir / statFile / getenv.
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

func (c *fileCollector) Name() string { return "winfilezilla" }

func (c *fileCollector) Collect(_ context.Context) ([]Site, error) {
	out := make([]Site, 0, 4)

	// Env-var override (FileZilla honours FZ_DATADIR for the
	// directory containing sitemanager.xml).
	if p := strings.TrimSpace(c.getenv("FZ_DATADIR")); p != "" {
		c.harvest(filepath.Join(p, "sitemanager.xml"), "", &out)
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
			c.harvest(
				filepath.Join(append([]string{base, name}, SitemanagerRelComponentsPosix()...)...),
				name, &out)
			c.harvest(
				filepath.Join(append([]string{base, name}, SitemanagerRelComponentsWindows()...)...),
				name, &out)
			if len(out) >= MaxSites {
				break
			}
		}
		if len(out) >= MaxSites {
			break
		}
	}

	if len(out) > MaxSites {
		out = out[:MaxSites]
	}
	SortSites(out)
	return out, nil
}

func (c *fileCollector) harvest(path, user string, out *[]Site) {
	body, err := c.readFile(path)
	if err != nil {
		return
	}
	parsed := ParseSitemanager(body)
	if len(parsed) == 0 {
		return
	}
	hash := HashContents(body)
	mode := 0
	uid := 0
	if fi, err := c.statFile(path); err == nil {
		mode = int(fi.Mode().Perm())
		uid = ownerUID(fi)
	}
	for _, p := range parsed {
		p.FilePath = path
		p.FileHash = hash
		p.FileMode = mode
		p.FileOwnerUID = uid
		p.UserProfile = user
		AnnotateSecurity(&p)
		*out = append(*out, p)
		if len(*out) >= MaxSites {
			return
		}
	}
}

func isSystemPseudoProfile(name string) bool {
	for _, p := range []string{"Public", "Default", "Default User", "All Users"} {
		if strings.EqualFold(name, p) {
			return true
		}
	}
	return false
}
