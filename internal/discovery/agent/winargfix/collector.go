package winargfix

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// MaxWalkDepth bounds per-root tree depth.
const MaxWalkDepth = 6

// fileCollector walks FIX-session install roots + per-user dirs.
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

func (c *fileCollector) Name() string { return "winargfix" }

func (c *fileCollector) Collect(_ context.Context) ([]Row, error) {
	out := make([]Row, 0, 16)

	roots := append([]string{}, c.installRoots...)
	if p := strings.TrimSpace(c.getenv("FIX_LOG_DIR")); p != "" {
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
			for _, rel := range UserFIXDirs() {
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
	kind := SessionKindFromName(filepath.Base(path))
	row := Row{
		FilePath:     path,
		FileSize:     fi.Size(),
		FileMode:     int(fi.Mode().Perm()),
		FileOwnerUID: ownerUID(fi),
		UserProfile:  user,
		SessionKind:  kind,
		Venue:        VenueFromSessionKind(kind),
		PeriodYYYYMM: PeriodFromFilename(filepath.Base(path)),
	}
	if mat := MatriculaFromText(filepath.Base(path)); mat != "" {
		row.BrokerMatricula = mat
	}
	// Sender/Target from canonical QuickFIX filename, if present.
	if s, t := SenderTargetFromFilename(filepath.Base(path)); s != "" || t != "" {
		row.SenderCompSuffix4 = s
		row.TargetCompSuffix4 = t
	}

	if fi.Size() <= MaxFileBytes {
		body, err := c.readFile(path)
		if err == nil {
			row.FileHash = HashContents(body)
			if sum, ok := ParseFIXLog(body); ok {
				if row.SenderCompSuffix4 == "" && sum.SenderCompID != "" {
					row.SenderCompSuffix4 = CompSuffix4(sum.SenderCompID)
				}
				if row.TargetCompSuffix4 == "" && sum.TargetCompID != "" {
					row.TargetCompSuffix4 = CompSuffix4(sum.TargetCompID)
				}
				// Venue from target/sender if unknown.
				if row.Venue == VenueUnknown {
					if v := VenueFromText(sum.TargetCompID); v != VenueUnknown && v != VenueOther {
						row.Venue = v
					} else if v := VenueFromText(sum.SenderCompID); v != VenueUnknown && v != VenueOther {
						row.Venue = v
					}
				}
				if sum.AccountRaw != "" {
					prefix, suffix := CuitFingerprint(sum.AccountRaw)
					if prefix != "" {
						row.AccountCuitPrefix = prefix
						row.AccountCuitSuffix4 = suffix
					}
				}
				row.MessageCount = sum.MessageCount
				row.OrderCount = sum.OrderCount
				row.CancelCount = sum.CancelCount
				row.ExecCount = sum.ExecCount
				row.SessionFirstSeen = sum.FirstSeen
				row.SessionLastSeen = sum.LastSeen
				if sum.HasPasswordTag {
					row.HasPasswordTag = true
				}
				if sum.IsAfterHours {
					row.IsAfterHours = true
				}
			}
		}
	}

	if c.now().Sub(fi.ModTime()) <= RecentlyWindow {
		row.IsRecent = true
	}

	AnnotateSecurity(&row)
	*out = append(*out, row)
}

func isSystemPseudoProfile(name string) bool {
	for _, p := range []string{"Public", "Default", "Default User", "All Users"} {
		if strings.EqualFold(name, p) {
			return true
		}
	}
	return false
}
