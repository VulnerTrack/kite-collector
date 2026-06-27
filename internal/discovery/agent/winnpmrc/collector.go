package winnpmrc

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

// DefaultGlobalNpmrcs is the curated set of global / built-in
// npmrc locations. The audit pipeline sees them with file_scope
// labels mapped per-OS by the collector.
func DefaultGlobalNpmrcs() []struct {
	Path  string
	Scope FileScope
} {
	return []struct {
		Path  string
		Scope FileScope
	}{
		{"/etc/npmrc", ScopeGlobal},
		{"/usr/local/etc/npmrc", ScopeGlobal},
		{`C:\Program Files\nodejs\etc\npmrc`, ScopeGlobal},
		{"/usr/lib/node_modules/npm/npmrc", ScopeBuiltin},
		{`C:\Program Files\nodejs\node_modules\npm\npmrc`, ScopeBuiltin},
	}
}

// fileCollector walks npmrc files from per-user trees + global
// paths + NPM_CONFIG_* env overrides. Test seam swaps readFile
// / readDir / statFile / getenv.
type fileCollector struct {
	getenv      func(string) string
	readFile    func(string) ([]byte, error)
	readDir     func(string) ([]os.DirEntry, error)
	statFile    func(string) (os.FileInfo, error)
	usersBases  []string
	globalPaths []struct {
		Path  string
		Scope FileScope
	}
}

// NewCollector returns a Collector wired to the canonical
// per-OS paths.
func NewCollector() Collector {
	return &fileCollector{
		usersBases:  DefaultUsersBases(),
		globalPaths: DefaultGlobalNpmrcs(),
		getenv:      os.Getenv,
		readFile:    os.ReadFile,
		readDir:     os.ReadDir,
		statFile:    os.Stat,
	}
}

func (c *fileCollector) Name() string { return "winnpmrc" }

func (c *fileCollector) Collect(_ context.Context) ([]Entry, error) {
	out := make([]Entry, 0, 16)

	// Env-var overrides.
	if p := strings.TrimSpace(c.getenv("NPM_CONFIG_USERCONFIG")); p != "" {
		c.harvest(p, "", ScopeUser, &out)
	}
	if p := strings.TrimSpace(c.getenv("NPM_CONFIG_GLOBALCONFIG")); p != "" {
		c.harvest(p, "", ScopeGlobal, &out)
	}

	// Global / built-in npmrcs.
	for _, g := range c.globalPaths {
		c.harvest(g.Path, "", g.Scope, &out)
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
			c.harvest(filepath.Join(base, name, ".npmrc"), name, ScopeUser, &out)
			if len(out) >= MaxEntries {
				break
			}
		}
		if len(out) >= MaxEntries {
			break
		}
	}

	if len(out) > MaxEntries {
		out = out[:MaxEntries]
	}
	SortEntries(out)
	return out, nil
}

// harvest reads + parses a single npmrc and appends each
// discovered entry (stamped with file metadata) to `out`.
// Missing files / parse errors silently skip.
func (c *fileCollector) harvest(path, user string, scope FileScope, out *[]Entry) {
	body, err := c.readFile(path)
	if err != nil {
		return
	}
	parsed := ParseNpmrc(body)
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
		p.FileScope = scope
		AnnotateSecurity(&p)
		*out = append(*out, p)
		if len(*out) >= MaxEntries {
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
