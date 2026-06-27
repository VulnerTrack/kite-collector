package wingit

import (
	"context"
	"errors"
	"io/fs"
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

// DefaultSystemConfigPaths is the curated set of system-wide git
// config locations.
func DefaultSystemConfigPaths() []string {
	return []string{
		"/etc/gitconfig",
		`C:\Program Files\Git\etc\gitconfig`,
		`C:\Program Files (x86)\Git\etc\gitconfig`,
		"/usr/local/etc/gitconfig",
	}
}

// fileCollector walks gitconfig + git-credentials files from
// per-user trees + system paths + XDG variants. Test seam swaps
// readFile / readDir / statFile / getenv.
type fileCollector struct {
	getenv        func(string) string
	readFile      func(string) ([]byte, error)
	readDir       func(string) ([]os.DirEntry, error)
	statFile      func(string) (os.FileInfo, error)
	usersBases    []string
	systemConfigs []string
}

// NewCollector returns a Collector wired to the canonical per-OS
// paths.
func NewCollector() Collector {
	return &fileCollector{
		usersBases:    DefaultUsersBases(),
		systemConfigs: DefaultSystemConfigPaths(),
		getenv:        os.Getenv,
		readFile:      os.ReadFile,
		readDir:       os.ReadDir,
		statFile:      os.Stat,
	}
}

func (c *fileCollector) Name() string { return "wingit" }

func (c *fileCollector) Collect(_ context.Context) ([]Entry, error) {
	out := make([]Entry, 0, 16)

	// System-wide config first.
	for _, p := range c.systemConfigs {
		c.harvestConfig(p, "", ScopeSystem, &out)
	}

	// Per-user discovery.
	for _, base := range c.usersBases {
		entries, err := c.readDir(base)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
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
			home := filepath.Join(base, name)
			c.harvestConfig(filepath.Join(home, ".gitconfig"), name, ScopeGlobal, &out)
			c.harvestConfig(filepath.Join(home, ".config", "git", "config"), name, ScopeXDG, &out)
			c.harvestCredentials(filepath.Join(home, ".git-credentials"), name, &out)
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
	SortEntries(out)
	return out, nil
}

// harvestConfig parses one git config file and stamps file
// metadata onto every emitted Entry. Missing files / parse
// errors silently skip.
func (c *fileCollector) harvestConfig(path, user string, scope FileScope, out *[]Entry) {
	body, err := c.readFile(path)
	if err != nil {
		return
	}
	parsed := ParseGitConfig(body)
	if len(parsed) == 0 {
		return
	}
	hash := HashContents(body)
	mode, uid := c.statMeta(path)
	for _, p := range parsed {
		p.FilePath = path
		p.FileHash = hash
		p.FileMode = mode
		p.FileOwnerUID = uid
		p.UserProfile = user
		p.FileScope = scope
		AnnotateSecurity(&p)
		*out = append(*out, p)
		if len(*out) >= MaxRows {
			return
		}
	}
}

// harvestCredentials parses one ~/.git-credentials body and
// stamps file metadata onto every emitted Entry.
func (c *fileCollector) harvestCredentials(path, user string, out *[]Entry) {
	body, err := c.readFile(path)
	if err != nil {
		return
	}
	parsed := ParseGitCredentialsStore(body)
	if len(parsed) == 0 {
		return
	}
	hash := HashContents(body)
	mode, uid := c.statMeta(path)
	for _, p := range parsed {
		p.FilePath = path
		p.FileHash = hash
		p.FileMode = mode
		p.FileOwnerUID = uid
		p.UserProfile = user
		p.FileScope = ScopeCredentials
		AnnotateSecurity(&p)
		*out = append(*out, p)
		if len(*out) >= MaxRows {
			return
		}
	}
}

// statMeta returns (mode, uid) for `path`. Errors collapse to
// (0, 0) — the row still emits.
func (c *fileCollector) statMeta(path string) (int, int) {
	fi, err := c.statFile(path)
	if err != nil {
		return 0, 0
	}
	return int(fi.Mode().Perm()), ownerUID(fi)
}

func isSystemPseudoProfile(name string) bool {
	for _, p := range []string{"Public", "Default", "Default User", "All Users"} {
		if strings.EqualFold(name, p) {
			return true
		}
	}
	return false
}
