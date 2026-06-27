package linuxsnap

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// MaxWalkDepth bounds per-root tree depth.
const MaxWalkDepth = 10

// fileCollector walks snap install roots + per-user dirs.
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

func (c *fileCollector) Name() string { return "linuxsnap" }

func (c *fileCollector) Collect(_ context.Context) ([]Row, error) {
	out := make([]Row, 0, 32)

	roots := append([]string{}, c.installRoots...)
	if p := strings.TrimSpace(c.getenv("SNAP_INVENTORY_DIR")); p != "" {
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
			for _, rel := range UserSnapDirs() {
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
	kind := ArtifactKindFromPath(path)
	if kind == KindOther {
		// Skip unrelated yaml/json/desktop files that aren't
		// part of a recognised snap path shape.
		return
	}
	row := Row{
		FilePath:            path,
		FileSize:            fi.Size(),
		FileMode:            int(fi.Mode().Perm()),
		FileOwnerUID:        ownerUID(fi),
		UserProfile:         user,
		ArtifactKind:        kind,
		Confinement:         ConfinementEmpty,
		SnapType:            SnapTypeEmpty,
		DPDSClass:           DPDSUnknown,
		SnapName:            SnapNameFromPath(path),
		InstallDateYYYYMMDD: fi.ModTime().UTC().Format("20060102"),
	}

	parseable := kind == KindSnapYAML || kind == KindSnapManifestYAML
	if parseable && fi.Size() <= MaxFileBytes {
		body, err := c.readFile(path)
		if err == nil {
			row.FileHash = HashContents(body)
			if fields, ok := ParseSnapYAML(body); ok {
				if row.SnapName == "" {
					row.SnapName = fields.Name
				} else if fields.Name != "" {
					// snap.yaml `name:` is authoritative if path
					// inference yielded a different value.
					row.SnapName = fields.Name
				}
				row.SnapVersion = fields.Version
				row.Publisher = fields.Publisher
				row.Summary = truncate(fields.Summary, 512)
				row.Website = fields.Website
				row.License = fields.License
				row.BaseSnap = fields.Base
				if fields.Confinement != ConfinementEmpty {
					row.Confinement = fields.Confinement
				}
				if fields.Type != SnapTypeEmpty {
					row.SnapType = fields.Type
				}
				row.PlugsCount = int64(len(fields.Plugs))
				for _, p := range fields.Plugs {
					PlugToField(&row, p)
				}
			}
		}
	} else if fi.Size() <= MaxFileBytes {
		body, err := c.readFile(path)
		if err == nil {
			row.FileHash = HashContents(body)
		}
	}

	if c.now().Sub(fi.ModTime()) <= RecentlyWindow {
		row.IsRecent = true
	}

	AnnotateSecurityWithClock(&row, c.now)
	*out = append(*out, row)
}

// truncate caps a string at n bytes to bound row width.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func isSystemPseudoProfile(name string) bool {
	for _, p := range []string{"Public", "Default", "Default User", "All Users", "Shared"} {
		if strings.EqualFold(name, p) {
			return true
		}
	}
	return false
}
