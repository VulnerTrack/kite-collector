package winauthkeys

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// DefaultWindowsAdminFile is the canonical Windows OpenSSH
// administrators authorized_keys location.
const DefaultWindowsAdminFile = `C:\ProgramData\ssh\administrators_authorized_keys`

// DefaultWindowsUsersBase is the parent of every Windows user
// profile.
const DefaultWindowsUsersBase = `C:\Users`

// DefaultLinuxRootFile is the canonical /root/.ssh authorized_keys.
const DefaultLinuxRootFile = "/root/.ssh/authorized_keys"

// DefaultLinuxUsersBase / DefaultMacUsersBase are the parents of
// per-user profiles on Linux + macOS.
const (
	DefaultLinuxUsersBase = "/home"
	DefaultMacUsersBase   = "/Users"
)

// UserKeyRelPath is the per-user relative path components. Kept
// as a slice so filepath.Join produces native separators on every
// OS.
var UserKeyRelPath = []string{".ssh", "authorized_keys"}

// seed pairs a discovery file with its scope tag. Per-user files
// are discovered by walking the user base; the seed list covers
// admin/root files only.
type seed struct {
	path  string
	scope KeyScope
}

// fileCollector walks authorized_keys files from a configurable
// seed list + user-base directories. Test seam swaps readFile /
// readDir.
type fileCollector struct {
	readFile   func(string) ([]byte, error)
	readDir    func(string) ([]os.DirEntry, error)
	usersBases []string
	rootFiles  []seed
}

// NewCollector returns a Collector wired to the canonical Windows
// + POSIX paths.
func NewCollector() Collector {
	return &fileCollector{
		usersBases: []string{
			DefaultWindowsUsersBase,
			DefaultLinuxUsersBase,
			DefaultMacUsersBase,
		},
		rootFiles: []seed{
			{path: DefaultWindowsAdminFile, scope: ScopeAdmin},
			{path: DefaultLinuxRootFile, scope: ScopeRoot},
		},
		readFile: os.ReadFile,
		readDir:  os.ReadDir,
	}
}

func (c *fileCollector) Name() string { return "winauthkeys" }

func (c *fileCollector) Collect(_ context.Context) ([]Key, error) {
	out := make([]Key, 0, 16)

	// Admin- and root-scope files first.
	for _, s := range c.rootFiles {
		if body, err := c.readFile(s.path); err == nil {
			out = append(out, ParseAuthorizedKeys(body, s.path, s.scope, "")...)
		}
	}

	// Per-user files discovered via each user-base directory.
	for _, base := range c.usersBases {
		entries, err := c.readDir(base)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			return nil, err
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
			path := filepath.Join(append([]string{base, name}, UserKeyRelPath...)...)
			body, err := c.readFile(path)
			if err != nil {
				continue
			}
			out = append(out, ParseAuthorizedKeys(body, path, ScopeUser, name)...)
			if len(out) >= MaxKeys {
				break
			}
		}
		if len(out) >= MaxKeys {
			break
		}
	}

	if len(out) > MaxKeys {
		out = out[:MaxKeys]
	}
	SortKeys(out)
	return out, nil
}

func isSystemPseudoProfile(name string) bool {
	for _, p := range []string{"Public", "Default", "Default User", "All Users"} {
		if strings.EqualFold(name, p) {
			return true
		}
	}
	return false
}
