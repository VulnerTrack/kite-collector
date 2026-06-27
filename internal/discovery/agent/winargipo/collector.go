package winargipo

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const MaxWalkDepth = 6

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

func (c *fileCollector) Name() string { return "winargipo" }

func (c *fileCollector) Collect(_ context.Context) ([]Row, error) {
	out := make([]Row, 0, 16)

	roots := append([]string{}, c.installRoots...)
	if p := strings.TrimSpace(c.getenv("IPO_DIR")); p != "" {
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
			for _, rel := range UserIPODirs() {
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
	base := filepath.Base(path)
	row := Row{
		FilePath:        path,
		FileSize:        fi.Size(),
		FileMode:        int(fi.Mode().Perm()),
		FileOwnerUID:    ownerUID(fi),
		UserProfile:     user,
		ArtifactKind:    ArtifactKindFromName(base),
		BookrunnerALYC:  BookrunnerALYCFromName(base),
		IPORole:         IPORoleUnknown,
		ReportingPeriod: PeriodFromFilename(base),
	}

	ext := strings.ToLower(filepath.Ext(path))
	skipBody := ext == ".msi" || ext == ".exe" || ext == ".pkg" || ext == ".dmg"
	if !skipBody && fi.Size() <= MaxFileBytes {
		body, err := c.readFile(path)
		if err == nil {
			row.FileHash = HashContents(body)
			c.mergeFields(&row, body)
		}
	} else if skipBody && fi.Size() <= MaxFileBytes {
		body, err := c.readFile(path)
		if err == nil {
			row.FileHash = HashContents(body)
		}
	}

	if c.now().Sub(fi.ModTime()) <= RecentlyWindow {
		row.IsRecent = true
	}

	AnnotateSecurity(&row)
	*out = append(*out, row)
}

func (c *fileCollector) mergeFields(row *Row, body []byte) {
	fields := ParseIPO(body)
	if fields.HasPassword {
		row.HasPasswordInConfig = true
	}
	if fields.BookrunnerALYC != "" && fields.BookrunnerALYC != ALYCUnknown {
		row.BookrunnerALYC = fields.BookrunnerALYC
	}
	if fields.BookrunnerRole != "" && fields.BookrunnerRole != RoleUnknown {
		row.BookrunnerRole = fields.BookrunnerRole
	}
	if fields.OfferingType != "" && fields.OfferingType != OfferingUnknown {
		row.OfferingType = fields.OfferingType
	}
	if fields.ListingVenue != "" && fields.ListingVenue != VenueUnknown {
		row.ListingVenue = fields.ListingVenue
	}
	if fields.IssuerCuitRaw != "" {
		if p, s := CuitEntityOnlyFingerprint(fields.IssuerCuitRaw); p != "" {
			row.IssuerCuitPrefix = p
			row.IssuerCuitSuffix4 = s
		}
	}
	if fields.BookrunnerCuitRaw != "" {
		if p, s := CuitEntityOnlyFingerprint(fields.BookrunnerCuitRaw); p != "" {
			row.BookrunnerCuitPrefix = p
			row.BookrunnerCuitSuffix4 = s
		}
	}
	if fields.DealCodename != "" {
		row.DealCodename = fields.DealCodename
	}
	if fields.InvestorCount > 0 {
		row.InvestorCount = fields.InvestorCount
	}
	if fields.AllocationCount > 0 {
		row.AllocationCount = fields.AllocationCount
	}
	if fields.InsiderCount > 0 {
		row.InsiderCount = fields.InsiderCount
	}
	if fields.OfferingSizeARS > 0 {
		row.OfferingSizeARS = fields.OfferingSizeARS
	}
	if fields.GreenshoeSizeARS > 0 {
		row.GreenshoeSizeARS = fields.GreenshoeSizeARS
	}
	if fields.BookrunnerFeeBps > 0 {
		row.BookrunnerFeeBps = fields.BookrunnerFeeBps
	}
}

func isSystemPseudoProfile(name string) bool {
	for _, p := range []string{
		"Public", "Default", "Default User", "All Users", "Shared",
	} {
		if strings.EqualFold(name, p) {
			return true
		}
	}
	return false
}
