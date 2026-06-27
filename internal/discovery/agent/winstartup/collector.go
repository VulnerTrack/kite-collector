package winstartup

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// DefaultAllUsersRoot is the canonical ProgramData Startup folder.
const DefaultAllUsersRoot = `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp`

// DefaultPerUserSuffix is the relative path under each user
// profile that contains their personal Startup folder.
const DefaultPerUserSuffix = `AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`

// DefaultUsersBase is the parent of every local user profile.
const DefaultUsersBase = `C:\Users`

// seed pairs a discovery directory with its scope tag and
// optional user-profile name (per-user only).
type seed struct {
	dir     string
	scope   Scope
	profile string
}

// fileCollector walks Startup folders from a configurable seed
// list. Test seam swaps readFile / readDir / statFile.
type fileCollector struct {
	readFile     func(string) ([]byte, error)
	readDir      func(string) ([]os.DirEntry, error)
	statFile     func(string) (os.FileInfo, error)
	usersBase    string
	allUsersRoot string
}

// NewCollector returns a Collector wired to the canonical Startup
// directories. Missing roots are silently skipped.
func NewCollector() Collector {
	return &fileCollector{
		usersBase:    DefaultUsersBase,
		allUsersRoot: DefaultAllUsersRoot,
		readFile:     os.ReadFile,
		readDir:      os.ReadDir,
		statFile:     os.Stat,
	}
}

func (c *fileCollector) Name() string { return "winstartup" }

func (c *fileCollector) Collect(_ context.Context) ([]Item, error) {
	seeds := []seed{{dir: c.allUsersRoot, scope: ScopeAllUsers}}

	// Discover per-user profiles by listing the Users base.
	if entries, err := c.readDir(c.usersBase); err == nil {
		sort.Slice(entries, func(i, j int) bool {
			return entries[i].Name() < entries[j].Name()
		})
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			name := e.Name()
			// Skip system pseudo-profiles.
			if strings.EqualFold(name, "Public") ||
				strings.EqualFold(name, "Default") ||
				strings.EqualFold(name, "Default User") ||
				strings.EqualFold(name, "All Users") ||
				strings.HasPrefix(name, ".") {
				continue
			}
			seeds = append(seeds, seed{
				dir:     filepath.Join(c.usersBase, name, DefaultPerUserSuffix),
				scope:   ScopePerUser,
				profile: name,
			})
		}
	}

	out := make([]Item, 0, 16)
	for _, s := range seeds {
		entries, err := c.readDir(s.dir)
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
			if e.IsDir() {
				continue
			}
			name := e.Name()
			if strings.HasPrefix(name, ".") {
				continue
			}
			full := filepath.Join(s.dir, name)
			body, err := c.readFile(full)
			if err != nil {
				continue
			}
			item := Item{
				FilePath:      full,
				FileHash:      HashContents(body),
				FileName:      name,
				FileExtension: strings.ToLower(filepath.Ext(name)),
				FileSizeBytes: int64(len(body)),
				UserProfile:   s.profile,
				Scope:         s.scope,
			}
			if fi, err := c.statFile(full); err == nil {
				item.FileMtime = fi.ModTime().Unix()
			}
			if strings.EqualFold(item.FileExtension, ".lnk") {
				if target, perr := ParseShellLinkTarget(body); perr == nil {
					item.TargetPath = target
				}
			}
			AnnotateSecurity(&item)
			out = append(out, item)
			if len(out) >= MaxItems {
				break
			}
		}
		if len(out) >= MaxItems {
			break
		}
	}

	SortItems(out)
	return out, nil
}
