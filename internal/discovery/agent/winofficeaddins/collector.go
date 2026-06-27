package winofficeaddins

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// DefaultUsersBase is the parent of every local user profile.
const DefaultUsersBase = `C:\Users`

// DefaultMachineWideOfficeRoots is the curated set of machine-
// wide Office installation roots. Each holds a STARTUP / XLSTART
// directory the host walks at launch.
func DefaultMachineWideOfficeRoots() []string {
	return []string{
		`C:\Program Files\Microsoft Office\root\Office16`,
		`C:\Program Files (x86)\Microsoft Office\root\Office16`,
		`C:\Program Files\Microsoft Office\Office16`,
		`C:\Program Files (x86)\Microsoft Office\Office16`,
		`C:\Program Files\Microsoft Office\Office15`,
		`C:\Program Files (x86)\Microsoft Office\Office15`,
		`C:\Program Files\Microsoft Office\Office14`,
		`C:\Program Files (x86)\Microsoft Office\Office14`,
	}
}

// PerUserSubdirs is the curated set of (relative-path, host) pairs
// the collector walks under each user profile's AppData\Roaming.
func PerUserSubdirs() []struct {
	Rel  string
	Host OfficeHost
} {
	return []struct {
		Rel  string
		Host OfficeHost
	}{
		{`AppData\Roaming\Microsoft\Word\STARTUP`, HostWord},
		{`AppData\Roaming\Microsoft\Excel\XLSTART`, HostExcel},
		{`AppData\Roaming\Microsoft\PowerPoint\STARTUP`, HostPowerPoint},
		{`AppData\Roaming\Microsoft\Outlook`, HostOutlook}, // VbaProject.OTM here
		{`AppData\Roaming\Microsoft\AddIns`, HostOfficeShared},
		{`AppData\Roaming\Microsoft\Templates`, HostOfficeShared},
	}
}

// MachineWideSubdirs is the curated set of (relative-path, host)
// pairs inside each Office install root the collector walks.
func MachineWideSubdirs() []struct {
	Rel  string
	Host OfficeHost
} {
	return []struct {
		Rel  string
		Host OfficeHost
	}{
		{`STARTUP`, HostWord},
		{`XLSTART`, HostExcel},
	}
}

// seed pairs a discovery directory with its scope, host tag, and
// optional per-user profile name.
type seed struct {
	dir     string
	host    OfficeHost
	scope   Scope
	profile string
}

// fileCollector walks the Office add-in / startup dirs from a
// configurable base. Test seam swaps readFile / readDir / statFile.
type fileCollector struct {
	readFile         func(string) ([]byte, error)
	readDir          func(string) ([]os.DirEntry, error)
	statFile         func(string) (os.FileInfo, error)
	usersBase        string
	machineWideRoots []string
}

// NewCollector returns a Collector wired to the canonical Office
// startup directories. Missing roots are silently skipped.
func NewCollector() Collector {
	return &fileCollector{
		usersBase:        DefaultUsersBase,
		machineWideRoots: DefaultMachineWideOfficeRoots(),
		readFile:         os.ReadFile,
		readDir:          os.ReadDir,
		statFile:         os.Stat,
	}
}

func (c *fileCollector) Name() string { return "winofficeaddins" }

func (c *fileCollector) Collect(_ context.Context) ([]Item, error) {
	seeds := c.buildSeeds()

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
				OfficeHost:    s.host,
				Scope:         s.scope,
			}
			if fi, err := c.statFile(full); err == nil {
				item.FileMtime = fi.ModTime().Unix()
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

// buildSeeds returns every (dir, host, scope, profile) tuple the
// collector should walk. Per-user seeds are discovered by listing
// the Users base; machine-wide seeds are the curated install
// roots intersected with the STARTUP/XLSTART subdirs.
func (c *fileCollector) buildSeeds() []seed {
	seeds := make([]seed, 0, 16)

	// Machine-wide seeds.
	for _, root := range c.machineWideRoots {
		for _, s := range MachineWideSubdirs() {
			seeds = append(seeds, seed{
				dir:   filepath.Join(root, s.Rel),
				host:  s.Host,
				scope: ScopeMachineWide,
			})
		}
	}

	// Per-user seeds discovered by listing the Users base.
	entries, err := c.readDir(c.usersBase)
	if err != nil {
		return seeds
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
		for _, s := range PerUserSubdirs() {
			seeds = append(seeds, seed{
				dir:     filepath.Join(c.usersBase, name, s.Rel),
				host:    s.Host,
				scope:   ScopePerUser,
				profile: name,
			})
		}
	}
	return seeds
}

func isSystemPseudoProfile(name string) bool {
	for _, p := range []string{"Public", "Default", "Default User", "All Users"} {
		if strings.EqualFold(name, p) {
			return true
		}
	}
	return false
}
