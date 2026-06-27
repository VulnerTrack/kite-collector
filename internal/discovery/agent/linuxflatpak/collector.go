package linuxflatpak

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// MaxWalkDepth bounds per-root tree depth. Flatpak app trees
// nest `app/<id>/<branch>/<arch>/active/files/share/metainfo/...`
// — 10 levels covers realistic depth.
const MaxWalkDepth = 12

// fileCollector walks flatpak install roots + per-user dirs.
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

func (c *fileCollector) Name() string { return "linuxflatpak" }

func (c *fileCollector) Collect(_ context.Context) ([]Row, error) {
	out := make([]Row, 0, 32)

	roots := append([]string{}, c.installRoots...)
	if p := strings.TrimSpace(c.getenv("FLATPAK_INVENTORY_DIR")); p != "" {
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
			for _, rel := range UserFlatpakDirs() {
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
		// Skip unrelated .desktop / .xml / metadata files that
		// aren't in a recognised flatpak path.
		return
	}
	row := Row{
		FilePath:            path,
		FileSize:            fi.Size(),
		FileMode:            int(fi.Mode().Perm()),
		FileOwnerUID:        ownerUID(fi),
		UserProfile:         user,
		ArtifactKind:        kind,
		DPDSClass:           DPDSUnknown,
		AppID:               AppIDFromPath(path),
		InstallDateYYYYMMDD: fi.ModTime().UTC().Format("20060102"),
	}
	row.Publisher = PublisherFromAppID(row.AppID)

	if fi.Size() <= MaxFileBytes {
		body, err := c.readFile(path)
		if err == nil {
			row.FileHash = HashContents(body)
			switch kind {
			case KindFlatpakMetadata:
				if md, ok := ParseFlatpakMetadata(body); ok {
					if row.AppID == "" && md.AppID != "" {
						row.AppID = md.AppID
						row.Publisher = PublisherFromAppID(md.AppID)
					}
					row.Runtime = md.Runtime
					ContextValueToFields(&row, "sockets", md.Sockets)
					ContextValueToFields(&row, "devices", md.Devices)
					ContextValueToFields(&row, "filesystems", md.Filesystems)
					ContextValueToFields(&row, "shared", md.Shared)
				}
			case KindFlatpakMetainfoXML, KindFlatpakAppdataXML:
				if mi, ok := ParseMetainfoXML(body); ok {
					if row.AppID == "" && mi.AppID != "" {
						row.AppID = mi.AppID
						row.Publisher = PublisherFromAppID(mi.AppID)
					}
					row.DisplayName = mi.Name
					row.Summary = truncate(mi.Summary, 512)
					row.License = mi.License
					row.Homepage = mi.Homepage
					row.Version = mi.Version
					// Override install_date with the AppStream
					// release date when available.
					if mi.ReleaseDate != "" {
						if d := normaliseReleaseDate(mi.ReleaseDate); d != "" {
							row.InstallDateYYYYMMDD = d
						}
					}
				}
			case KindFlatpakDesktop, KindFlatpakRepoRef,
				KindOther, KindUnknown:
				// metadata-only — leave structured fields empty.
			}
		}
	}

	if c.now().Sub(fi.ModTime()) <= RecentlyWindow {
		row.IsRecent = true
	}

	AnnotateSecurityWithClock(&row, c.now)
	*out = append(*out, row)
}

// normaliseReleaseDate accepts ISO-8601 dates or YYYYMMDD
// and returns YYYYMMDD; empty on parse failure.
func normaliseReleaseDate(s string) string {
	s = strings.TrimSpace(s)
	if len(s) == 8 {
		return s
	}
	if len(s) == 10 {
		// YYYY-MM-DD
		return s[0:4] + s[5:7] + s[8:10]
	}
	if len(s) >= 10 {
		return s[0:4] + s[5:7] + s[8:10]
	}
	return ""
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
