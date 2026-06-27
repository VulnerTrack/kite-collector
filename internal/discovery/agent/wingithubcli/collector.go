package wingithubcli

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

// HostsRelComponentsPosix is the per-user POSIX path tail to
// the gh hosts file: `.config/gh/hosts.yml`.
func HostsRelComponentsPosix() []string {
	return []string{".config", "gh", "hosts.yml"}
}

// HostsRelComponentsWindows is the per-user Windows path tail
// to the gh hosts file: `AppData\Roaming\GitHub CLI\hosts.yml`.
func HostsRelComponentsWindows() []string {
	return []string{"AppData", "Roaming", "GitHub CLI", "hosts.yml"}
}

// fileCollector walks gh hosts.yml from per-user trees +
// `GH_CONFIG_DIR` env override. Test seam swaps readFile /
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

func (c *fileCollector) Name() string { return "wingithubcli" }

func (c *fileCollector) Collect(_ context.Context) ([]Row, error) {
	out := make([]Row, 0, 4)

	// Env-var override wins.
	if p := strings.TrimSpace(c.getenv("GH_CONFIG_DIR")); p != "" {
		c.harvest(filepath.Join(p, "hosts.yml"), "", &out)
	}

	// Per-user discovery — try both POSIX + Windows tails so
	// the walker stays portable on Linux CI scanning Windows
	// home dirs in a mounted volume.
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
				filepath.Join(append([]string{base, name}, HostsRelComponentsPosix()...)...),
				name, &out)
			c.harvest(
				filepath.Join(append([]string{base, name}, HostsRelComponentsWindows()...)...),
				name, &out)
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

func (c *fileCollector) harvest(path, user string, out *[]Row) {
	body, err := c.readFile(path)
	if err != nil {
		return
	}
	parsed := ParseHostsYAML(body)
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
		if len(*out) >= MaxRows {
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
